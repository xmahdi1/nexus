package backups

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type jobController interface {
	DispatchBackup(context.Context, models.SupervisedRun, string, []byte, int) (jobsupervisor.Snapshot, error)
	Inspect(context.Context, models.SupervisedRun, string) (jobsupervisor.Snapshot, error)
	Cached(models.SupervisedRun) (jobsupervisor.Snapshot, error)
	Save(models.SupervisedRun, jobsupervisor.Snapshot) error
}

var activeRuns sync.Map

type Runtime struct {
	*Service
	Pool          *nexusssh.Pool
	Supervised    bool
	RecoveryAuth  func() (string, string, bool)
	controller    func(func() bool) jobController
	active        sync.Map
	slots         chan struct{}
	healthAfter   string
	coverageAfter string
}

func NewRuntime(service *Service, pool *nexusssh.Pool, supervised bool) *Runtime {
	r := &Runtime{Service: service, Pool: pool, Supervised: supervised, slots: make(chan struct{}, 4)}
	r.controller = func(guard func() bool) jobController {
		job := jobsupervisor.NewService(r.DB, r.Key, pool)
		job.Guard = guard
		return job
	}
	return r
}
func permissions(action string) []string {
	required := []string{"backups.read", "secrets.use", "jobs.execute"}
	switch action {
	case "install", "init":
		return append(required, "backups.manage")
	case "backup":
		return append(required, "backups.execute")
	case "restore", "verify":
		return append(required, "backups.restore")
	case "check", "snapshots":
		return required
	case "retention-preview":
		return append(required, "backups.manage")
	case "retention-apply":
		return append(required, "backups.manage", "backups.prune")
	}
	return nil
}
func hostScope(server string) string {
	if server == "" {
		return LocalHost
	}
	return server
}
func (r *Runtime) Allowed(run models.SupervisedRun) bool {
	if !r.Enabled || run.Kind != "scheduled" || !strings.HasPrefix(run.Action, "backup:") || run.CancelRequestedAt != nil {
		return false
	}
	var row Policy
	if r.DB.First(&row, "id=?", run.TaskID).Error != nil || row.Archived || hostScope(row.ServerID) != run.ServerID || row.Digest != run.OperationContext {
		return false
	}
	data, err := r.config(row)
	if err != nil || !r.ownerAllowed(row, data) {
		return false
	}
	required := permissions(strings.TrimPrefix(run.Action, "backup:"))
	if len(required) == 0 {
		return false
	}
	if row.ServerID != "" {
		required = append(required, "servers.connect")
	} else {
		required = append(required, "backups.nexus.manage", "secrets.reveal")
	}
	if !authorization.New(r.DB).All(run.ActorID, row.ServerID, required...) {
		return false
	}
	if strings.HasPrefix(run.Action, "backup:retention-") {
		if run.SourceSessionID == "" {
			return false
		}
		if _, err := r.retentionJob(run); err != nil {
			return false
		}
	}
	if run.SourceSessionID != "" {
		if r.Sessions == nil {
			return false
		}
		a, err := r.Sessions.AccessForSession(run.SourceSessionID, run.ActorID)
		if err != nil {
			return false
		}
		if row.ServerID != "" {
			protected, err := authorization.New(r.DB).Protected(row.ServerID)
			if err != nil || (protected && !a.RecentMFA()) {
				return false
			}
		}
	} else {
		lease := row.LastRunID == run.ID && ((row.Mode == "once" && row.LastState == "prepared") || row.LastState == "remote_unknown")
		if (!row.Enabled && !lease) || row.ActorID != run.ActorID || !authorization.New(r.DB).All(run.ActorID, row.ServerID, "backups.schedule") {
			return false
		}
		if row.ServerID != "" {
			protected, err := authorization.New(r.DB).Protected(row.ServerID)
			if err != nil || protected {
				return false
			}
		}
	}
	return true
}
func (r *Runtime) Start(a *auth.Access, server, policyID, id, action, snapshot string) (models.SupervisedRun, error) {
	if strings.HasPrefix(action, "retention-") {
		return models.SupervisedRun{}, ErrInput
	}
	required := permissions(action)
	if len(required) == 0 || !idPattern.MatchString(id) || (snapshot != "" && !snapshotPattern.MatchString(snapshot)) || ((action == "restore" || action == "verify") && snapshot == "") {
		return models.SupervisedRun{}, ErrInput
	}
	if server != "" {
		required = append(required, "servers.connect")
	} else {
		required = append(required, "secrets.reveal")
	}
	if err := r.require(a, server, true, required...); err != nil {
		return models.SupervisedRun{}, err
	}
	return r.reserve(a, server, policyID, id, action, snapshot, false)
}
func (r *Runtime) reserve(a *auth.Access, server, policyID, id, action, snapshot string, scheduled bool, retention ...RetentionRequest) (models.SupervisedRun, error) {
	var run models.SupervisedRun
	if !r.Enabled || (server != "" && !r.Supervised) {
		return run, ErrDisabled
	}

	target := sha256.Sum256([]byte(action + "\x00" + snapshot))
	targetHash := hex.EncodeToString(target[:])
	if len(retention) > 1 || (strings.HasPrefix(action, "retention-") != (len(retention) == 1)) || (len(retention) == 1 && (scheduled || a == nil)) {
		return run, ErrInput
	}
	if len(retention) == 1 {
		targetHash = retentionHash(action, retention[0])
	}
	created := false
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		inside := *r.Service
		inside.DB = tx
		row, err := inside.policy(server, policyID)
		if err != nil {
			return err
		}
		data, err := inside.config(row)
		if err != nil {
			return err
		}
		actor, session := row.ActorID, ""
		if a != nil {
			actor = a.User.ID
			session = a.Session.ID
		}
		if row.Archived || !inside.ownerAllowed(row, data) {
			return ErrDenied
		}
		run = models.SupervisedRun{ID: id, TaskID: row.ID, ServerID: hostScope(server), ActorID: actor, SourceSessionID: session, Kind: "scheduled", Action: "backup:" + action, OperationContext: row.Digest, TargetHash: targetHash, CommandHash: jobsupervisor.Digest("reserved-private-backup"), State: "prepared", CreatedAt: time.Now().UTC()}
		var old models.SupervisedRun
		if err := tx.First(&old, "id=?", id).Error; err == nil {
			if old.TaskID != row.ID || old.ServerID != run.ServerID || old.ActorID != actor || old.SourceSessionID != session || old.Action != run.Action || old.TargetHash != run.TargetHash {
				return ErrConflict
			}
			run = old
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		check := &Runtime{Service: &inside}
		check.controller = func(guard func() bool) jobController {
			job := jobsupervisor.NewService(tx, r.Key, r.Pool)
			job.Guard = guard
			return job
		}
		if len(retention) == 1 {
			encoded, _ := json.Marshal(retention[0])
			binding := retentionBinding(run)
			sealed, err := nexuscrypto.EncryptBackupRetention(r.Key, run.ID, binding, encoded)
			clear(encoded)
			if err != nil {
				return err
			}
			if err := tx.Exec("INSERT INTO backup_retention_jobs(run_id,binding,request_enc)VALUES(?,?,?)", run.ID, binding, sealed).Error; err != nil {
				return err
			}
			if action == "retention-apply" {
				if err := tx.Exec("INSERT INTO backup_retention_claims(preview_run_id,run_id)VALUES(?,?)", retention[0].PreviewRunID, run.ID).Error; err != nil {
					return ErrConflict
				}
			}
		}
		if !check.Allowed(run) {
			return ErrDenied
		}
		if scheduled && (!row.Enabled || row.NextAt == nil || row.NextAt.After(time.Now().UTC())) {
			return ErrConflict
		}
		var count int64
		for _, query := range []*gorm.DB{tx.Model(&models.SupervisedRun{}).Where("server_id=? AND finished_at IS NULL", run.ServerID), tx.Model(&models.ExecutionHostLock{}).Where("server_id=?", run.ServerID), tx.Model(&models.ScheduledTask{}).Where("server_id=? AND last_status='running'", run.ServerID)} {
			if err := query.Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return ErrBusy
			}
		}
		if err := tx.Create(&run).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO backup_run_cleanup(run_id,cleaned)VALUES(?,0)", run.ID).Error; err != nil {
			return err
		}
		updates := map[string]any{"last_run_id": id, "last_state": "prepared"}
		if scheduled {
			if row.Mode == "once" {
				updates["enabled"] = false
				updates["next_at"] = nil
			} else {
				updates["next_at"] = time.Now().UTC().Add(time.Duration(row.IntervalMinutes) * time.Minute)
			}
		}
		if err := tx.Model(&row).Updates(updates).Error; err != nil {
			return err
		}
		if err := authorization.New(tx).Record(actor, "backup.run.reserve", id, "prepared", row.ID, session); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return models.SupervisedRun{}, err
	}
	if created {
		activeRuns.Store(localKey{r.DB, id}, true)
		go func(run models.SupervisedRun) {
			defer activeRuns.Delete(localKey{r.DB, id})
			select {
			case r.slots <- struct{}{}:
				defer func() { <-r.slots }()
			case <-time.After(5 * time.Second):
				r.notStarted(run, "dispatcher_capacity")
				return
			}
			r.dispatch(run, snapshot)
		}(run)
	}
	return run, nil
}
func (r *Runtime) notStarted(run models.SupervisedRun, detail string) {
	_ = r.controller(func() bool { return false }).Save(run, jobsupervisor.Snapshot{State: "not_started", NoDispatch: true, Released: true, Detail: detail})
	_ = r.finish(run.ID)
}
func (r *Runtime) Get(server, id string) (models.SupervisedRun, error) {
	var row models.SupervisedRun
	if !idPattern.MatchString(id) {
		return row, ErrInput
	}
	err := r.DB.First(&row, "id=? AND server_id=? AND kind='scheduled' AND action LIKE 'backup:%'", id, hostScope(server)).Error
	return row, err
}
func (r *Runtime) Runs(a *auth.Access, server string) ([]models.SupervisedRun, error) {
	if err := r.require(a, server, false, "backups.read", "jobs.read"); err != nil {
		return nil, err
	}
	rows := []models.SupervisedRun{}
	err := r.DB.Where("server_id=? AND kind='scheduled' AND action LIKE 'backup:%'", hostScope(server)).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	if err == nil {
		err = r.require(a, server, false, "backups.read", "jobs.read")
	}
	return rows, err
}
func (r *Runtime) dispatch(run models.SupervisedRun, snapshot string) {
	var row Policy
	if r.DB.First(&row, "id=?", run.TaskID).Error != nil {
		r.notStarted(run, "policy_unavailable")
		return
	}
	data, err := r.config(row)
	if err != nil || !r.Allowed(run) {
		r.notStarted(run, "authority_changed")
		return
	}
	action := strings.TrimPrefix(run.Action, "backup:")
	nexusDirectory := ""
	if row.ServerID == "" && action == "backup" {
		nexusDirectory, err = r.nexusPackage(run, data)
		if err != nil {
			r.notStarted(run, "recovery_snapshot_failed")
			return
		}
		defer removeNexusPackage(nexusDirectory)
	}
	input, err := privateRequest(action, row, data, run.ID, r.workRoot(row.ServerID), snapshot, nexusDirectory)
	if err == nil && strings.HasPrefix(action, "retention-") {
		var request *RetentionRequest
		request, err = r.retentionJob(run)
		if err == nil {
			var payload map[string]json.RawMessage
			err = json.Unmarshal(input, &payload)
			if err == nil {
				payload["retention"], err = json.Marshal(request)
			}
			clear(input)
			if err == nil {
				input, err = json.Marshal(payload)
			}
		}
	}
	if err != nil || len(input) > jobsupervisor.MaxPrivateInput {
		clear(input)
		r.notStarted(run, "private_input_limit")
		return
	}
	defer clear(input)
	if !r.Allowed(run) {
		r.notStarted(run, "authority_changed")
		return
	}
	command := Command()
	if len(command) > 16384 {
		r.notStarted(run, "adapter_limit")
		return
	}
	run.CommandHash = jobsupervisor.DigestWithInput(command, input)
	changed := r.DB.Model(&models.SupervisedRun{}).Where("id=? AND state='prepared' AND dispatch_started_at IS NULL AND cancel_requested_at IS NULL AND finished_at IS NULL", run.ID).Update("command_hash", run.CommandHash)
	if changed.Error != nil || changed.RowsAffected != 1 {
		return
	}
	if row.ServerID == "" {
		r.runLocal(run, input, data.RuntimeSeconds)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = r.controller(func() bool { current, err := r.Get(row.ServerID, run.ID); return err == nil && r.Allowed(current) }).DispatchBackup(ctx, run, command, input, data.RuntimeSeconds)
		cancel()
	}
	if nexusDirectory != "" {
		removeNexusPackage(nexusDirectory)
	}
	_ = r.finish(run.ID)
	current, loadErr := r.Get(row.ServerID, run.ID)
	if loadErr == nil && current.FinishedAt != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_ = r.cleanStaging(ctx, current, row.ServerID)
		cancel()
	}
}
func (r *Runtime) Observe(ctx context.Context, a *auth.Access, server, id, action string) (jobsupervisor.Snapshot, *Result, error) {
	required := []string{"backups.read", "jobs.read", "logs.read", "secrets.use"}
	if action == "cancel" {
		required = []string{"backups.read", "jobs.cancel"}
	} else if action == "release" {
		required = append(required, "jobs.manage")
	} else if action != "inspect" {
		return jobsupervisor.Snapshot{}, nil, ErrInput
	}
	if err := r.require(a, server, true, required...); err != nil {
		return jobsupervisor.Snapshot{}, nil, err
	}
	run, err := r.Get(server, id)
	if err != nil {
		return jobsupervisor.Snapshot{}, nil, err
	}
	if server != "" {
		row, loadErr := r.policy(server, run.TaskID)
		if loadErr != nil {
			return jobsupervisor.Snapshot{}, nil, loadErr
		}
		data, loadErr := r.config(row)
		if loadErr != nil {
			return jobsupervisor.Snapshot{}, nil, loadErr
		}
		binding, loadErr := r.hostBinding(server)
		if loadErr != nil || binding != data.HostBinding {
			return jobsupervisor.Snapshot{}, nil, ErrConflict
		}
	}
	if action == "cancel" {
		now := time.Now().UTC()
		if err := r.DB.Model(&run).Where("finished_at IS NULL").Update("cancel_requested_at", now).Error; err != nil {
			return jobsupervisor.Snapshot{}, nil, err
		}
		if stop, ok := localExecutions.Load(localKey{r.DB, id}); ok {
			stop.(context.CancelFunc)()
		}
	}
	var observed jobsupervisor.Snapshot
	if server == "" {
		observed, err = r.controller(func() bool { return false }).Cached(run)
	} else {
		observed, err = r.controller(func() bool { return r.Allowed(run) }).Inspect(ctx, run, action)
	}
	if err == nil {
		err = r.finish(id)
	}
	if err == nil && action == "release" {
		current, loadErr := r.Get(server, id)
		if loadErr != nil {
			err = loadErr
		} else if current.FinishedAt == nil {
			err = ErrBusy
		} else {
			err = r.cleanStaging(ctx, current, server)
		}
	}
	var result *Result
	if action == "inspect" {
		result = parseResult(observed.Output, r.workRoot(server), run.TaskID, run.ID)
	}
	observed.Output = ""
	if err == nil {
		err = r.require(a, server, true, required...)
	}
	return observed, result, err
}
