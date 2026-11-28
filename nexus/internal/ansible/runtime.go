package ansible

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

var ErrBusy = errors.New("a frozen host already has an unresolved execution")
var runPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidExecutionID(value string) bool { return runPattern.MatchString(value) }

type jobController interface {
	DispatchAnsible(context.Context, models.SupervisedRun, string, []byte, int) (jobsupervisor.Snapshot, error)
	Inspect(context.Context, models.SupervisedRun, string) (jobsupervisor.Snapshot, error)
	Cached(models.SupervisedRun) (jobsupervisor.Snapshot, error)
	Save(models.SupervisedRun, jobsupervisor.Snapshot) error
}

type Runtime struct {
	*Service
	Pool        *nexusssh.Pool
	Supervised  bool
	controller  func(func() bool) jobController
	input       func(context.Context, Plan, string, map[string]string) ([]byte, error)
	active      sync.Map
	slots       chan struct{}
	queueActive sync.Map
	queueSlots  chan struct{}
}

func NewRuntime(service *Service, pool *nexusssh.Pool, supervised bool) *Runtime {
	r := &Runtime{Service: service, Pool: pool, Supervised: supervised, slots: make(chan struct{}, 4), queueSlots: make(chan struct{}, 2)}
	r.controller = func(guard func() bool) jobController {
		job := jobsupervisor.NewService(r.DB, r.Key, pool)
		job.Guard = guard
		return job
	}
	r.input = r.privateInput
	return r
}

func (r *Runtime) Allowed(run models.SupervisedRun) bool {
	if !r.Supervised || !r.Enabled || run.Kind != "ansible" || run.TaskID != "" {
		return false
	}
	plan, err := r.AuthorizedPlan(run.OperationContext)
	return err == nil && plan.ActorID == run.ActorID && plan.SourceSessionID == run.SourceSessionID && plan.ServerID == run.ServerID && authorization.New(r.DB).All(run.ActorID, run.ServerID, "jobs.execute")
}

// Start reserves every frozen host and a single-use plan before any SSH/Vault
// activity. Neither an HTTP retry nor process recovery submits another command.
func (r *Runtime) Start(ctx context.Context, a *auth.Access, server, planID, identity string, tokens map[string]string) (models.SupervisedRun, error) {
	return r.start(ctx, a, server, planID, identity, tokens, "")
}
func (r *Runtime) start(ctx context.Context, a *auth.Access, server, planID, identity string, tokens map[string]string, queueID string) (models.SupervisedRun, error) {
	var run models.SupervisedRun
	if !r.Supervised || !r.Enabled {
		return run, ErrDisabled
	}
	if !ValidExecutionID(identity) || !idPattern.MatchString(planID) || len(tokens) > 10 {
		return run, ErrInput
	}
	for _, token := range tokens {
		if token == "" || len(token) > 8192 || stringsUnsafeToken(token) {
			return run, ErrInput
		}
	}
	if err := r.require(a, server, true, "ansible.projects.read", "ansible.playbooks.execute", "jobs.execute"); err != nil {
		return run, err
	}
	created := false
	err := r.DB.Transaction(func(tx *gorm.DB) error {
		if err := queueAdmission(tx, server, planID, identity, queueID, a); err != nil {
			return err
		}
		var existing models.SupervisedRun
		err := tx.First(&existing, "id=?", identity).Error
		if err == nil {
			if existing.Kind != "ansible" || existing.ServerID != server || existing.ActorID != a.User.ID || existing.SourceSessionID != a.Session.ID || existing.OperationContext != planID {
				return ErrConflict
			}
			run = existing
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		inside := *r.Service
		inside.DB = tx
		plan, err := inside.AuthorizedPlan(planID)
		if err != nil {
			return err
		}
		if plan.ServerID != server || plan.ActorID != a.User.ID || plan.SourceSessionID != a.Session.ID {
			return ErrDenied
		}
		cfg, err := inside.config(plan)
		if err != nil {
			return err
		}
		for id := range tokens {
			if cfg.VaultBindings[id] == "" {
				return ErrInput
			}
		}
		for id := range cfg.VaultBindings {
			if tokens[id] == "" {
				return ErrInput
			}
		}
		var count int64
		if err := tx.Table("ansible_run_plans").Where("plan_id=?", planID).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return ErrConflict
		}
		hosts := []string{server}
		for _, target := range cfg.Targets {
			hosts = append(hosts, target.ServerID)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			if err := tx.Model(&models.SupervisedRun{}).Where("server_id=? AND finished_at IS NULL", host).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return ErrBusy
			}
			if err := tx.Model(&models.ScheduledTask{}).Where("server_id=? AND last_status='running'", host).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return ErrBusy
			}
			if err := tx.Model(&models.ExecutionHostLock{}).Where("server_id=?", host).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return ErrBusy
			}
			if err := tx.Create(&models.ExecutionHostLock{ServerID: host, RunID: identity}).Error; err != nil {
				return err
			}
		}
		run = models.SupervisedRun{ID: identity, Kind: "ansible", Action: "ansible-playbook", ServerID: server, ActorID: a.User.ID, SourceSessionID: a.Session.ID, OperationContext: planID, CommandHash: jobsupervisor.Digest("reserved-private-input"), State: "prepared", CreatedAt: time.Now().UTC()}
		if err := tx.Create(&run).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO ansible_run_plans(run_id,plan_id) VALUES(?,?)", identity, planID).Error; err != nil {
			return err
		}
		if err := authorization.New(tx).Record(a.User.ID, "ansible.run.reserve", identity, "prepared", "", a.Session.ID); err != nil {
			return err
		}
		if queueID != "" {
			now := time.Now().UTC()
			changed := tx.Model(&QueueEntry{}).Where("id=? AND state='waiting'", queueID).Updates(map[string]any{"state": "admitted", "detail": "", "admitted_at": now})
			if changed.Error != nil {
				return changed.Error
			}
			if changed.RowsAffected != 1 {
				return ErrConflict
			}
		}
		created = true
		return nil
	})
	if err != nil {
		return models.SupervisedRun{}, err
	}
	if !created {
		return run, err
	}
	job := r.controller(func() bool { return r.Allowed(run) })
	preparation, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var plan Plan
	if err := r.DB.First(&plan, "id=?", planID).Error; err != nil {
		return run, err
	}
	input, err := r.input(preparation, plan, identity, tokens)
	defer clear(input)
	if err != nil || !r.Allowed(run) || preparation.Err() != nil {
		outcome := jobsupervisor.Snapshot{State: "not_started", NoDispatch: true, Detail: "approved_input_preparation_failed"}
		if saveErr := job.Save(run, outcome); saveErr != nil {
			return run, saveErr
		}
		if err == nil {
			err = ErrDenied
		}
		if loadErr := r.DB.First(&run, "id=?", identity).Error; loadErr != nil {
			return run, loadErr
		}
		if releaseErr := r.releaseLocks(run); releaseErr != nil {
			return run, releaseErr
		}
		return run, err
	}
	command := jobCommand()
	if len(command) > 16384 || len(input) > jobsupervisor.MaxPrivateInput {
		if err := job.Save(run, jobsupervisor.Snapshot{State: "not_started", NoDispatch: true, Detail: "private_input_limit"}); err != nil {
			return run, err
		}
		if err := r.DB.First(&run, "id=?", identity).Error; err != nil {
			return run, err
		}
		if err := r.releaseLocks(run); err != nil {
			return run, err
		}
		return run, ErrInput
	}
	run.CommandHash = jobsupervisor.DigestWithInput(command, input)
	result := r.DB.Model(&models.SupervisedRun{}).Where("id=? AND state='prepared' AND dispatch_started_at IS NULL AND cancel_requested_at IS NULL AND finished_at IS NULL", run.ID).Update("command_hash", run.CommandHash)
	if result.Error != nil || result.RowsAffected != 1 {
		if r.DB.First(&run, "id=?", identity).Error == nil {
			_ = r.releaseLocks(run)
		}
		return run, ErrConflict
	}
	bounded, stop := context.WithTimeout(preparation, 30*time.Second)
	defer stop()
	cfg, err := r.config(plan)
	if err == nil {
		_, err = job.DispatchAnsible(bounded, run, command, input, cfg.Options.TimeoutSeconds)
	}
	if loadErr := r.DB.First(&run, "id=?", identity).Error; loadErr != nil {
		return run, loadErr
	}
	if releaseErr := r.releaseLocks(run); releaseErr != nil && err == nil {
		err = releaseErr
	}
	return run, err
}

func stringsUnsafeToken(value string) bool {
	for _, c := range value {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func (r *Runtime) releaseLocks(run models.SupervisedRun) error {
	if run.FinishedAt == nil {
		return nil
	}
	return r.DB.Transaction(func(tx *gorm.DB) error {
		if run.DispatchStartedAt == nil && run.State == "not_started" {
			if err := tx.Model(&run).Update("artifacts_removed", true).Error; err != nil {
				return err
			}
		}
		return tx.Where("run_id=?", run.ID).Delete(&models.ExecutionHostLock{}).Error
	})
}

func (r *Runtime) Get(server, identity string) (models.SupervisedRun, error) {
	var run models.SupervisedRun
	err := r.DB.First(&run, "id=? AND server_id=? AND kind='ansible'", identity, server).Error
	return run, err
}

func (r *Runtime) List(server string) ([]models.SupervisedRun, error) {
	rows := []models.SupervisedRun{}
	err := r.DB.Where("server_id=? AND kind='ansible'", server).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}

func (r *Runtime) Observe(ctx context.Context, run models.SupervisedRun, action string) (jobsupervisor.Snapshot, error) {
	if run.Kind != "ansible" || (action != "inspect" && action != "cancel" && action != "release") {
		return jobsupervisor.Snapshot{}, ErrInput
	}
	job := r.controller(func() bool { return r.Allowed(run) })
	if action == "inspect" && run.DispatchStartedAt == nil && run.FinishedAt == nil {
		if time.Since(run.CreatedAt) < 2*time.Minute {
			return job.Cached(run)
		}
		now := time.Now().UTC()
		if err := r.DB.Model(&run).Where("dispatch_started_at IS NULL AND finished_at IS NULL").Updates(map[string]any{"state": "not_started", "detail": "dispatcher_interrupted_before_submission", "finished_at": now}).Error; err != nil {
			return jobsupervisor.Snapshot{}, err
		}
		if err := r.DB.First(&run, "id=?", run.ID).Error; err != nil {
			return jobsupervisor.Snapshot{}, err
		}
	}
	result, err := job.Inspect(ctx, run, action)
	var current models.SupervisedRun
	if loadErr := r.DB.First(&current, "id=?", run.ID).Error; loadErr == nil {
		if releaseErr := r.releaseLocks(current); releaseErr != nil && err == nil {
			err = releaseErr
		}
	} else if err == nil {
		err = loadErr
	}
	return result, err
}

// Reconciliation only observes/cancels. Unknown transport results retain locks.
func (r *Runtime) Reconcile(ctx context.Context) {
	var rows []models.SupervisedRun
	if r.DB.Where("kind='ansible' AND finished_at IS NULL").Order("COALESCE(last_checked_at,created_at),id").Limit(128).Find(&rows).Error != nil {
		return
	}
	// A crash between terminal persistence and local release must not strand locks.
	r.DB.Exec("DELETE FROM execution_host_locks WHERE run_id IN (SELECT id FROM supervised_runs WHERE kind='ansible' AND finished_at IS NOT NULL)")
	r.DB.Exec("UPDATE supervised_runs SET artifacts_removed=1 WHERE kind='ansible' AND state='not_started' AND finished_at IS NOT NULL AND dispatch_started_at IS NULL")
	for _, run := range rows {
		if ctx.Err() != nil {
			return
		}
		if _, loaded := r.active.LoadOrStore(run.ID, true); loaded {
			continue
		}
		select {
		case r.slots <- struct{}{}:
			go func(run models.SupervisedRun) {
				defer func() { <-r.slots; r.active.Delete(run.ID) }()
				bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				action := "inspect"
				if run.CancelRequestedAt != nil || !r.Allowed(run) {
					action = "cancel"
				}
				if r.DB.Model(&run).Update("last_checked_at", time.Now().UTC()).Error == nil {
					_, _ = r.Observe(bounded, run, action)
				}
			}(run)
		default:
			r.active.Delete(run.ID)
		}
	}
}

func (r *Runtime) Run(ctx context.Context) {
	go func() {
		r.Reconcile(ctx)
		r.TickSchedules(ctx)
		r.DrainQueue(ctx)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.Reconcile(ctx)
				r.TickSchedules(ctx)
				r.DrainQueue(ctx)
			}
		}
	}()
}
