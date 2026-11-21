// Package operations supervises a fixed set of interactive server actions.
package operations

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/jobsupervisor"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/remoteaction"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

var ErrDisabled = errors.New("interactive operation supervision is disabled")
var ErrBusy = errors.New("this host has an unresolved execution; inspect or cancel it first")
var ErrConflict = errors.New("the request ID already identifies another operation")

type controller interface {
	Dispatch(context.Context, models.SupervisedRun, string) (jobsupervisor.Snapshot, error)
	Inspect(context.Context, models.SupervisedRun, string) (jobsupervisor.Snapshot, error)
	Cached(models.SupervisedRun) (jobsupervisor.Snapshot, error)
	Save(models.SupervisedRun, jobsupervisor.Snapshot) error
}
type Service struct {
	DB                *gorm.DB
	Sessions          *auth.Service
	Enabled           bool
	AutomationEnabled bool
	newController     func(func() bool) controller
	active            sync.Map
	slots             chan struct{}
}

func New(database *gorm.DB, key []byte, pool *nexusssh.Pool, sessions *auth.Service, enabled bool, automation ...bool) *Service {
	s := &Service{DB: database, Sessions: sessions, Enabled: enabled, slots: make(chan struct{}, 4)}
	s.AutomationEnabled = len(automation) == 1 && automation[0]
	s.newController = func(guard func() bool) controller {
		job := jobsupervisor.NewService(database, key, pool)
		job.Guard = guard
		return job
	}
	return s
}

// Allowed checks the issuing session's expiry, admission, credential epoch,
// current grants and protected-group MFA without extending that session's life.
func (s *Service) Allowed(run models.SupervisedRun) bool {
	if !s.Enabled || s.Sessions == nil || run.Kind != "operation" || run.TaskID != "" {
		return false
	}
	spec, ok := remoteaction.Find(run.Action)
	if !ok {
		return false
	}
	if strings.HasPrefix(spec.ID, "ansible-environment-") && !s.AutomationEnabled {
		return false
	}
	access, err := s.Sessions.AccessForSession(run.SourceSessionID, run.ActorID)
	if err != nil {
		return false
	}
	policy := authorization.New(s.DB)
	protected, err := policy.Protected(run.ServerID)
	return err == nil && (!protected || access.RecentMFA()) && policy.All(run.ActorID, run.ServerID, spec.Permissions...)
}

// Start reserves durable identity before opening SSH. Reusing an identical ID
// returns its existing metadata and never submits the command a second time.
func (s *Service) Start(ctx context.Context, actor, session, server, id, action, path, cid string) (models.SupervisedRun, error) {
	var run models.SupervisedRun
	if !s.Enabled {
		return run, ErrDisabled
	}
	if !remoteaction.ValidID(id) {
		return run, remoteaction.ErrInput
	}
	command, target, err := remoteaction.Build(action, path, cid)
	if err != nil {
		return run, err
	}
	run = models.SupervisedRun{ID: id, Kind: "operation", Action: action, SourceSessionID: session, ServerID: server, ActorID: actor, TargetHash: target, CommandHash: jobsupervisor.Digest(command), State: "prepared", CreatedAt: time.Now().UTC()}
	if !s.Allowed(run) {
		return models.SupervisedRun{}, authorization.ErrDenied
	}
	created := false
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var existing models.SupervisedRun
		err := tx.First(&existing, "id=?", id).Error
		if err == nil {
			if existing.ServerID != server || existing.ActorID != actor || existing.Kind != "operation" {
				return gorm.ErrRecordNotFound
			}
			if existing.Action != action || existing.TargetHash != target || existing.CommandHash != run.CommandHash {
				return ErrConflict
			}
			run = existing
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var count int64
		if err := tx.Model(&models.Server{}).Where("id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return gorm.ErrRecordNotFound
		}
		if err := tx.Model(&models.SupervisedRun{}).Where("server_id=? AND finished_at IS NULL", server).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrBusy
		}
		if err := tx.Model(&models.ScheduledTask{}).Where("server_id=? AND last_status='running'", server).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrBusy
		}
		if err := tx.Create(&run).Error; err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return models.SupervisedRun{}, err
	}
	if !created {
		return run, nil
	}
	authority := run
	job := s.newController(func() bool { return s.Allowed(authority) })
	dispatch, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, dispatchErr := job.Dispatch(dispatch, run, command)
	if err := s.DB.First(&run, "id=? AND kind='operation' AND server_id=?", id, server).Error; err != nil {
		return run, err
	}
	return run, dispatchErr
}

func (s *Service) Get(server, id string) (models.SupervisedRun, error) {
	var run models.SupervisedRun
	if !remoteaction.ValidID(id) {
		return run, gorm.ErrRecordNotFound
	}
	err := s.DB.First(&run, "id=? AND server_id=? AND kind='operation' AND task_id=''", id, server).Error
	return run, err
}
func (s *Service) List(server string) ([]models.SupervisedRun, error) {
	runs := []models.SupervisedRun{}
	err := s.DB.Where("server_id=? AND kind='operation' AND task_id=''", server).Order("created_at desc,id desc").Limit(50).Find(&runs).Error
	return runs, err
}
func (s *Service) Observe(ctx context.Context, run models.SupervisedRun, action string) (jobsupervisor.Snapshot, error) {
	if run.Kind != "operation" || run.TaskID != "" {
		return jobsupervisor.Snapshot{}, gorm.ErrRecordNotFound
	}
	job := s.newController(nil)
	if action == "cached" {
		return job.Cached(run)
	}
	if action != "inspect" && action != "cancel" && action != "release" {
		return jobsupervisor.Snapshot{}, remoteaction.ErrInput
	}
	if action == "inspect" && run.DispatchStartedAt == nil && run.FinishedAt == nil {
		// A fresh reservation may still be owned by a live HTTP dispatcher.
		if time.Since(run.CreatedAt) < time.Minute {
			return job.Cached(run)
		}
		now := time.Now().UTC()
		result := s.DB.Model(&models.SupervisedRun{}).Where("id=? AND kind='operation' AND dispatch_started_at IS NULL AND finished_at IS NULL", run.ID).Updates(map[string]any{"state": "not_started", "detail": "dispatcher_interrupted_before_submission", "finished_at": now})
		if result.Error != nil {
			return jobsupervisor.Snapshot{}, result.Error
		}
		var err error
		run, err = s.Get(run.ServerID, run.ID)
		if err != nil {
			return jobsupervisor.Snapshot{}, err
		}
		if run.FinishedAt != nil {
			return job.Cached(run)
		}
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return job.Inspect(bounded, run, action)
}

// Reconcile never starts work. Revocation, expiry or disabling the feature
// requests cancellation of the existing invocation, even after a restart.
func (s *Service) Reconcile(ctx context.Context) {
	var runs []models.SupervisedRun
	if s.DB.Where("kind='operation' AND task_id='' AND finished_at IS NULL").Order("COALESCE(last_checked_at,created_at),id").Limit(128).Find(&runs).Error != nil {
		return
	}
	for _, run := range runs {
		if ctx.Err() != nil {
			return
		}
		if _, loaded := s.active.LoadOrStore(run.ID, true); loaded {
			continue
		}
		select {
		case s.slots <- struct{}{}:
			go func(run models.SupervisedRun) {
				defer func() { <-s.slots; s.active.Delete(run.ID) }()
				bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				action := "inspect"
				if run.CancelRequestedAt != nil || !s.Allowed(run) {
					action = "cancel"
				}
				if s.DB.Model(&run).Update("last_checked_at", time.Now().UTC()).Error != nil {
					return
				}
				_, _ = s.Observe(bounded, run, action)
			}(run)
		default:
			s.active.Delete(run.ID)
		}
	}
}
func (s *Service) Run(ctx context.Context) {
	go func() {
		s.Reconcile(ctx)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Reconcile(ctx)
			}
		}
	}()
}
