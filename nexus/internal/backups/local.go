package backups

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
)

func removeNexusPackage(path string) {
	if strings.HasPrefix(filepath.Base(path), "nexus-recovery-") {
		_ = os.RemoveAll(path)
	}
}
func (r *Runtime) nexusPackage(run models.SupervisedRun, data sealedDefinition) (string, error) {
	if r.DBPath == "" || len(r.Key) != 32 {
		return "", ErrInput
	}
	source, err := os.Stat(r.DBPath)
	if err != nil || source.Size() > int64(data.ExportLimitGiB)<<30 {
		return "", ErrInput
	}
	directory, err := os.MkdirTemp("", "nexus-recovery-"+run.ID+"-")
	if err != nil {
		return "", err
	}
	complete := false
	defer func() {
		if !complete {
			removeNexusPackage(directory)
		}
	}()
	if err := db.RecoverySnapshot(r.DBPath, filepath.Join(directory, "nexus.db"), r.Key); err != nil {
		return "", err
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(r.Key) + "\n")
	defer clear(encoded)
	if err := os.WriteFile(filepath.Join(directory, "encryption-key.base64"), encoded, 0600); err != nil {
		return "", err
	}
	var schema int
	if err := r.DB.Raw("SELECT max(version) FROM schema_migrations").Scan(&schema).Error; err != nil {
		return "", err
	}
	manifest, _ := json.Marshal(map[string]any{"schema": schema, "createdAt": time.Now().UTC(), "instructions": "Stop the old Nexus before promotion. Restore nexus.db with its matching encryption key. Sessions, invitations and future schedules are disabled in this recovery copy. Inspect existing remote run identities before enabling automation. Remote app data, Vault storage, host files and provider state require separate sources."})
	if err := os.WriteFile(filepath.Join(directory, "recovery.json"), manifest, 0600); err != nil {
		return "", err
	}
	if r.RecoveryAuth != nil {
		hash, totpSecret, totpEnabled := r.RecoveryAuth()
		config := []byte("NEXUS_PASSWORD_HASH='" + strings.ReplaceAll(hash, "'", "") + "'\nNEXUS_ENCRYPTION_KEY='" + base64.StdEncoding.EncodeToString(r.Key) + "'\nNEXUS_TOTP_ENABLED='" + strconv.FormatBool(totpEnabled) + "'\nNEXUS_TOTP_SECRET='" + strings.ReplaceAll(totpSecret, "'", "") + "'\nNEXUS_ENABLE_BACKUPS='false'\nNEXUS_ENABLE_AUTOMATION='false'\nNEXUS_ENABLE_JOB_SUPERVISION='false'\nNEXUS_ENABLE_OPERATION_SUPERVISION='false'\n")
		defer clear(config)
		if err := os.WriteFile(filepath.Join(directory, "recovery.env"), config, 0600); err != nil {
			return "", err
		}
	}
	complete = true
	return directory, nil
}

type limitedOutput struct {
	bytes.Buffer
	limit int
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > w.limit {
		return 0, errors.New("backup output limit")
	}
	return w.Buffer.Write(p)
}
func (r *Runtime) runLocal(run models.SupervisedRun, input []byte, seconds int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	localExecutions.Store(localKey{r.DB, run.ID}, context.CancelFunc(cancel))
	defer localExecutions.Delete(localKey{r.DB, run.ID})
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				current, err := r.Get("", run.ID)
				if err != nil || !r.Allowed(current) {
					cancel()
					return
				}
			}
		}
	}()
	service := r.controller(func() bool { return r.Allowed(run) })
	if !r.Allowed(run) {
		r.notStarted(run, "authority_changed")
		return
	}
	receipt := localReceipt{RunID: run.ID, Hash: run.CommandHash, OwnerPID: os.Getpid(), OwnerStart: processStart(os.Getpid()), Namespace: processNamespace()}
	if err := r.writeReceipt(run, receipt); err != nil {
		r.notStarted(run, "local_receipt_unavailable")
		return
	}
	now := time.Now().UTC()
	claim := r.DB.Model(&models.SupervisedRun{}).Where("id=? AND state='prepared' AND dispatch_started_at IS NULL AND cancel_requested_at IS NULL AND finished_at IS NULL", run.ID).Updates(map[string]any{"state": "running", "dispatch_started_at": now})
	if claim.Error != nil || claim.RowsAffected != 1 {
		return
	}
	command := exec.CommandContext(ctx, "python3", "-I", "-c", engineSource())
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	output := &limitedOutput{limit: 65536}
	command.Stdout = output
	command.Stderr = io.Discard
	stdin, err := command.StdinPipe()
	if err == nil {
		err = command.Start()
	}
	if err == nil {
		receipt.PID = command.Process.Pid
		if receiptErr := r.writeReceipt(run, receipt); receiptErr != nil {
			_ = command.Cancel()
			_ = stdin.Close()
			_ = command.Wait()
			err = receiptErr
		} else {
			_, writeErr := stdin.Write(input)
			_ = stdin.Close()
			waitErr := command.Wait()
			err = waitErr
			if writeErr != nil {
				err = writeErr
			}
		}
	}
	code := 0
	state := "exited"
	if err != nil {
		state = "failed"
		code = 1
	}
	if command.ProcessState != nil {
		code = command.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		state = "cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			state = "timed_out"
		}
	}
	_ = service.Save(run, jobsupervisor.Snapshot{State: state, Verified: true, Empty: true, Released: true, ExitCode: &code, Output: output.String()})
}
