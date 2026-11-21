package jobsupervisor

import (
	"context"
	"errors"
	"time"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type Service struct {
	DB    *gorm.DB
	Key   []byte
	Pool  *nexusssh.Pool
	Guard func() bool
}

func NewService(database *gorm.DB, key []byte, pool *nexusssh.Pool) *Service {
	return &Service{DB: database, Key: key, Pool: pool}
}

// Dispatch requires a durable row created in the task's claim transaction. Its
// CAS precedes all remote activity, so recovery never silently replays a start.
func (service *Service) Dispatch(ctx context.Context, run models.SupervisedRun, command string) (Snapshot, error) {
	return service.DispatchWithInput(ctx, run, command, nil)
}

// DispatchWithInput keeps credentials and structured execution context off argv,
// environment variables and ordinary logs. Only internal typed adapters use it;
// existing management handlers never accept arbitrary private stdin.
func (service *Service) DispatchWithInput(ctx context.Context, run models.SupervisedRun, command string, input []byte) (Snapshot, error) {
	now := time.Now().UTC()
	claimed := service.DB.Model(&models.SupervisedRun{}).Where("id=? AND task_id=? AND server_id=? AND actor_id=? AND command_hash=? AND dispatch_started_at IS NULL AND cancel_requested_at IS NULL AND state='prepared'", run.ID, run.TaskID, run.ServerID, run.ActorID, run.CommandHash).Updates(map[string]any{"dispatch_started_at": now, "state": "dispatching"})
	if claimed.Error != nil {
		return Snapshot{State: "unknown"}, claimed.Error
	}
	if claimed.RowsAffected != 1 {
		if err := service.DB.First(&run, "id=? AND task_id=? AND server_id=?", run.ID, run.TaskID, run.ServerID).Error; err != nil {
			return Snapshot{State: "unknown"}, err
		}
		if run.CancelRequestedAt != nil && run.DispatchStartedAt == nil {
			return service.Inspect(ctx, run, "cancel")
		}
		return service.Inspect(ctx, run, "inspect")
	}
	if DigestWithInput(command, input) != run.CommandHash || len(input) > MaxPrivateInput {
		result := Snapshot{State: "not_started", NoDispatch: true, Detail: "command_identity_changed"}
		return result, service.Save(run, result)
	}
	return service.call(ctx, run, Request{Action: "start", ID: run.ID, Hash: run.CommandHash, Command: command, Input: input, RuntimeSeconds: 600})
}

func (service *Service) Inspect(ctx context.Context, run models.SupervisedRun, action string) (Snapshot, error) {
	if run.FinishedAt != nil && (action == "inspect" || action == "cancel" || (action == "release" && run.ArtifactsRemoved)) {
		return service.Cached(run)
	}
	if action != "inspect" && action != "cancel" && action != "release" {
		return Snapshot{State: "unknown"}, errors.New("invalid run action")
	}
	if action == "cancel" {
		err := service.DB.Transaction(func(tx *gorm.DB) error {
			if err := tx.First(&run, "id=? AND task_id=? AND server_id=?", run.ID, run.TaskID, run.ServerID).Error; err != nil {
				return err
			}
			if run.FinishedAt != nil {
				return nil
			}
			now := time.Now().UTC()
			updates := map[string]any{}
			if run.CancelRequestedAt == nil {
				updates["cancel_requested_at"] = now
				run.CancelRequestedAt = &now
			}
			if run.DispatchStartedAt == nil && run.State == "prepared" {
				updates["state"] = "not_started"
				updates["detail"] = "cancelled_before_dispatch"
				updates["finished_at"] = now
			}
			if len(updates) > 0 {
				if err := tx.Model(&run).Updates(updates).Error; err != nil {
					return err
				}
			}
			return tx.First(&run, "id=?", run.ID).Error
		})
		if err != nil {
			return Snapshot{State: "unknown"}, err
		}
		if run.FinishedAt != nil {
			return service.Cached(run)
		}
	}
	return service.call(ctx, run, Request{Action: action, ID: run.ID, Hash: run.CommandHash, InvocationID: run.InvocationID})
}
func (service *Service) Cached(run models.SupervisedRun) (Snapshot, error) {
	result := Snapshot{State: run.State, Verified: run.VerifiedAt != nil, Empty: run.FinishedAt != nil, ExitCode: run.ExitCode, InvocationID: run.InvocationID, Truncated: run.Truncated, Released: run.ArtifactsRemoved, Detail: run.Detail}
	result.NoDispatch = run.FinishedAt != nil && (run.State == "not_started" || run.State == "unsupported" || run.State == "capacity_exceeded")
	if run.OutputEnc != "" {
		data, err := nexuscrypto.DecryptJobOutput(service.Key, run.ID, run.ServerID, run.OutputEnc)
		if err != nil {
			return Snapshot{State: "unknown"}, errors.New("could not read protected job output")
		}
		result.Output = string(data)
		clear(data)
	}
	return result, nil
}
func (service *Service) call(ctx context.Context, run models.SupervisedRun, request Request) (Snapshot, error) {
	var server models.Server
	if err := service.DB.First(&server, "id=?", run.ServerID).Error; err != nil {
		return Snapshot{State: "unknown"}, err
	}
	key, err := nexuscrypto.Decrypt(service.Key, server.PrivateKeyEnc)
	if err != nil {
		return Snapshot{State: "unknown"}, errors.New("could not load job transport")
	}
	defer clear(key)
	if service.Pool == nil {
		return Snapshot{State: "unknown"}, errors.New("job transport unavailable")
	}
	client, err := service.Pool.GetContext(ctx, nexusssh.ServerConfig{ID: server.ID, Host: server.Host, Port: server.Port, User: server.Username, PrivKey: key})
	result := Snapshot{State: "unknown", Detail: "transport_unavailable"}
	if request.Action == "start" && service.Guard != nil && !service.Guard() {
		result = Snapshot{State: "not_started", NoDispatch: true, Detail: "execution_authority_changed"}
		if err := service.Save(run, result); err != nil {
			return Snapshot{State: "unknown"}, err
		}
		return result, nil
	}
	if err == nil {
		if request.Action == "start" {
			var current models.SupervisedRun
			if err := service.DB.First(&current, "id=?", run.ID).Error; err != nil {
				return Snapshot{State: "unknown"}, err
			}
			if current.CancelRequestedAt != nil {
				result = Snapshot{State: "not_started", NoDispatch: true, Detail: "cancelled_before_dispatch"}
				return result, service.Save(run, result)
			}
		}
		if request.Action == "start" {
			request.BeforeDispatch = service.Guard
		}
		result, err = Execute(ctx, client, request)
	}
	if request.Action != "start" && (result.State == "unsupported" || result.NoDispatch) {
		result = Snapshot{State: "unknown", Detail: "supervisor_unavailable"}
	}
	if saveErr := service.Save(run, result); saveErr != nil {
		return Snapshot{State: "unknown"}, saveErr
	}
	if request.Action != "release" && !result.Terminal() {
		var current models.SupervisedRun
		if service.DB.First(&current, "id=? AND task_id=? AND server_id=?", run.ID, run.TaskID, run.ServerID).Error == nil && current.FinishedAt != nil {
			return service.Cached(current)
		}
	}
	return result, err
}
func (service *Service) Save(run models.SupervisedRun, result Snapshot) error {
	return service.DB.Transaction(func(tx *gorm.DB) error {
		var current models.SupervisedRun
		if err := tx.First(&current, "id=? AND server_id=? AND task_id=?", run.ID, run.ServerID, run.TaskID).Error; err != nil {
			return err
		}
		if current.FinishedAt != nil {
			if result.Released && result.Terminal() {
				return tx.Model(&current).Update("artifacts_removed", true).Error
			}
			return nil
		}
		if result.NoDispatch && current.InvocationID != "" {
			return errors.New("cannot erase an observed job invocation")
		}
		if current.InvocationID != "" && result.InvocationID != "" && current.InvocationID != result.InvocationID {
			return errors.New("job invocation identity changed")
		}
		now := time.Now().UTC()
		updates := map[string]any{"state": result.State, "detail": result.Detail, "verified_at": nil, "last_checked_at": now}
		if result.InvocationID != "" {
			updates["invocation_id"] = result.InvocationID
		}
		if result.Verified {
			updates["verified_at"] = now
		}
		if result.Verified {
			encrypted, err := nexuscrypto.EncryptJobOutput(service.Key, current.ID, current.ServerID, []byte(result.Output))
			if err != nil {
				return err
			}
			updates["output_enc"] = encrypted
			updates["truncated"] = result.Truncated
			updates["exit_code"] = result.ExitCode
		}
		if result.Terminal() {
			updates["finished_at"] = now
			updates["artifacts_removed"] = result.Released
		}
		if result.NoDispatch {
			updates["finished_at"] = now
		}
		return tx.Model(&current).Updates(updates).Error
	})
}
