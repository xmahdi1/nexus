package backups

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

type localKey struct {
	DB  *gorm.DB
	Run string
}

var localExecutions sync.Map

type localReceipt struct {
	RunID      string `json:"runId"`
	Hash       string `json:"hash"`
	OwnerPID   int    `json:"ownerPid"`
	OwnerStart string `json:"ownerStart"`
	PID        int    `json:"pid"`
	Namespace  string `json:"namespace"`
}

func processStart(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	index := strings.LastIndex(string(data), ")")
	if index < 0 {
		return ""
	}
	fields := strings.Fields(string(data[index+1:]))
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}
func processNamespace() string { value, _ := os.Readlink("/proc/self/ns/pid"); return value }
func privateDirectory(root string) error {
	if !filepath.IsAbs(root) {
		return ErrInput
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return ErrInput
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return ErrDenied
	}
	return nil
}
func (r *Runtime) receiptPath(id string) string {
	return filepath.Join(r.WorkRoot, "local-runs", id+".json")
}
func (r *Runtime) writeReceipt(run models.SupervisedRun, receipt localReceipt) error {
	root := filepath.Dir(r.receiptPath(run.ID))
	if err := privateDirectory(r.WorkRoot); err != nil {
		return err
	}
	if err := privateDirectory(root); err != nil {
		return err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(root, "receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), r.receiptPath(run.ID))
}
func (r *Runtime) localOrphan(run models.SupervisedRun) (ownerAlive, empty, noDispatch bool) {
	path := r.receiptPath(run.ID)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return false, false, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false, false, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false, false
	}
	var receipt localReceipt
	if json.Unmarshal(data, &receipt) != nil || receipt.RunID != run.ID || receipt.Hash != run.CommandHash || receipt.Namespace == "" || receipt.Namespace != processNamespace() || receipt.OwnerPID < 1 || receipt.OwnerStart == "" {
		return false, false, false
	}
	if receipt.OwnerStart != "" && processStart(receipt.OwnerPID) == receipt.OwnerStart {
		return true, false, false
	}
	if receipt.PID == 0 {
		return false, true, true
	}
	if receipt.PID < 2 {
		return false, false, false
	}
	if errors.Is(syscall.Kill(-receipt.PID, 0), syscall.ESRCH) {
		return false, true, false
	}
	return false, false, false
}
