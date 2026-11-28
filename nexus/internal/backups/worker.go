package backups

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
)

func (r *Runtime) cleanStaging(ctx context.Context, run models.SupervisedRun, server string) error {
	if run.FinishedAt == nil {
		return ErrBusy
	}
	var complete bool
	r.DB.Raw("SELECT cleaned FROM backup_run_cleanup WHERE run_id=?", run.ID).Scan(&complete)
	if complete {
		return nil
	}
	input, _ := json.Marshal(map[string]string{"action": "cleanup", "policyId": run.TaskID, "runId": run.ID, "workRoot": r.workRoot(server)})
	if server == "" {
		command := exec.CommandContext(ctx, "python3", "-I", "-c", engineSource())
		command.Stdin = strings.NewReader(string(input))
		command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
		if err := command.Run(); err != nil {
			return err
		}
		_ = os.Remove(r.receiptPath(run.ID))
	} else {
		row, err := r.policy(server, run.TaskID)
		if err != nil {
			return err
		}
		data, err := r.config(row)
		if err != nil {
			return err
		}
		current, err := r.hostBinding(server)
		if err != nil || current != data.HostBinding {
			return ErrConflict
		}
		var host models.Server
		if err := r.DB.First(&host, "id=?", server).Error; err != nil {
			return err
		}
		key, err := nexuscrypto.Decrypt(r.Key, host.PrivateKeyEnc)
		if err != nil {
			return err
		}
		defer clear(key)
		if r.Pool == nil {
			return ErrDisabled
		}
		client, err := r.Pool.GetContext(ctx, nexusssh.ServerConfig{ID: host.ID, Host: host.Host, Port: host.Port, User: host.Username, PrivKey: key})
		if err != nil {
			return err
		}
		output, err := nexusssh.Run(ctx, client, Command(), strings.NewReader(string(input)), 15*time.Second)
		if err != nil {
			return err
		}
		var result Result
		if json.Unmarshal([]byte(output), &result) != nil || result.State != "cleaned" || !result.Verified {
			return ErrConflict
		}
	}
	return r.DB.Exec("UPDATE backup_run_cleanup SET cleaned=1 WHERE run_id=?", run.ID).Error
}
func (r *Runtime) Tick(ctx context.Context) {
	if !r.Enabled {
		return
	}
	var policies []Policy
	if r.DB.Where("enabled=1 AND archived=0 AND next_at IS NOT NULL AND julianday(next_at)<=julianday(?)", time.Now().UTC()).Order("julianday(next_at),id").Limit(32).Find(&policies).Error != nil {
		return
	}
	for _, policy := range policies {
		if ctx.Err() != nil {
			return
		}
		id, err := audit.NewID()
		if err != nil {
			return
		}
		if _, err = r.reserve(nil, policy.ServerID, policy.ID, id, "backup", "", true); err == ErrDenied || err == ErrConflict {
			_ = r.DB.Model(&Policy{}).Where("id=?", policy.ID).Updates(map[string]any{"enabled": false, "last_state": "authority_changed"}).Error
		}
	}
}
func (r *Runtime) Reconcile(ctx context.Context) {
	var rows []models.SupervisedRun
	if r.DB.Where("kind='scheduled' AND action LIKE 'backup:%' AND finished_at IS NULL").Order("COALESCE(last_checked_at,created_at),id").Limit(128).Find(&rows).Error != nil {
		return
	}
	for _, run := range rows {
		if ctx.Err() != nil {
			return
		}
		key := localKey{r.DB, run.ID}
		if _, active := activeRuns.Load(key); active {
			continue
		}
		if _, loaded := r.active.LoadOrStore(run.ID, true); loaded {
			continue
		}
		select {
		case r.slots <- struct{}{}:
			go func(run models.SupervisedRun) {
				defer func() { <-r.slots; r.active.Delete(run.ID) }()
				bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
				defer cancel()
				job := r.controller(func() bool { current, err := r.Get(scopeOf(run), run.ID); return err == nil && r.Allowed(current) })
				if run.DispatchStartedAt == nil {
					if time.Since(run.CreatedAt) < 2*time.Minute {
						return
					}
					r.notStarted(run, "dispatcher_interrupted_before_submission")
					return
				}
				if run.ServerID == LocalHost {
					if _, running := localExecutions.Load(localKey{r.DB, run.ID}); running {
						return
					}
					owner, empty, noDispatch := r.localOrphan(run)
					if owner {
						return
					}
					snapshot := jobsupervisor.Snapshot{State: "unknown", Detail: "local_process_unverified"}
					if empty {
						snapshot = jobsupervisor.Snapshot{State: "interrupted", Verified: true, Empty: true, Detail: "local_owner_terminated"}
						if noDispatch {
							snapshot = jobsupervisor.Snapshot{State: "not_started", NoDispatch: true, Detail: "local_owner_terminated_before_submission"}
						}
					}
					_ = job.Save(run, snapshot)
				} else {
					row, err := r.policy(run.ServerID, run.TaskID)
					if err != nil {
						return
					}
					data, err := r.config(row)
					if err != nil {
						return
					}
					binding, err := r.hostBinding(run.ServerID)
					if err != nil || binding != data.HostBinding {
						_ = job.Save(run, jobsupervisor.Snapshot{State: "unknown", Detail: "backup_host_changed"})
						_ = r.finish(run.ID)
						return
					}
					action := "inspect"
					if run.CancelRequestedAt != nil || !r.Allowed(run) {
						action = "cancel"
					}
					_ = r.DB.Model(&run).Update("last_checked_at", time.Now().UTC()).Error
					_, _ = job.Inspect(bounded, run, action)
				}
				_ = r.finish(run.ID)
				current, err := r.Get(scopeOf(run), run.ID)
				if err == nil && current.FinishedAt != nil {
					_ = r.cleanStaging(bounded, current, scopeOf(run))
				}
			}(run)
		default:
			r.active.Delete(run.ID)
			return
		}
	}
}
func scopeOf(run models.SupervisedRun) string {
	if run.ServerID == LocalHost {
		return ""
	}
	return run.ServerID
}
func (r *Runtime) Run(ctx context.Context) {
	go func() {
		r.Reconcile(ctx)
		r.Tick(ctx)
		r.SweepHealth(time.Now().UTC())
		ticker := time.NewTicker(5 * time.Second)
		healthTicker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		defer healthTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.Reconcile(ctx)
				r.Tick(ctx)
			case <-healthTicker.C:
				r.SweepHealth(time.Now().UTC())
			}
		}
	}()
}
