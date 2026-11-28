package githubactions

import (
	"context"
	"errors"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
)

func (s *Service) operationToken(ctx context.Context, a *auth.Access, server, id, permission string, write, high bool) (Connection, *Token, error) {
	if err := s.require(a, server, high, permission, "secrets.use"); err != nil {
		return Connection{}, nil, err
	}
	row, data, err := s.connection(server, id)
	if err != nil {
		return row, nil, err
	}
	key := []byte(data.PEM)
	defer clear(key)
	token, err := s.Client.InstallationToken(ctx, App{ClientID: data.ClientID, InstallationID: data.InstallationID, PrivateKey: key}, data.Repository, write)
	if err != nil {
		return row, nil, err
	}
	if err := s.currentConnection(a, row, high, permission); err != nil {
		token.Clear()
		return row, nil, err
	}
	return row, token, nil
}
func (s *Service) currentConnection(a *auth.Access, row Connection, high bool, permission string) error {
	if err := s.require(a, row.ServerID, high, permission, "secrets.use"); err != nil {
		return err
	}
	current, _, err := s.connection(row.ServerID, row.ID)
	if err != nil || current.ConfigEnc != row.ConfigEnc {
		return ErrDenied
	}
	return nil
}
func (s *Service) Run(ctx context.Context, a *auth.Access, server, id string, run int64) (Run, error) {
	row, token, err := s.operationToken(ctx, a, server, id, "github.actions.read", false, false)
	if err != nil {
		return Run{}, err
	}
	defer token.Clear()
	out, err := s.Client.Run(ctx, row.repository(), token, run)
	if check := s.currentConnection(a, row, false, "github.actions.read"); check != nil {
		return Run{}, check
	}
	return out, err
}
func (s *Service) Artifacts(ctx context.Context, a *auth.Access, server, id string, run int64, page int) (ArtifactPage, error) {
	row, token, err := s.operationToken(ctx, a, server, id, "github.actions.read", false, false)
	if err != nil {
		return ArtifactPage{}, err
	}
	defer token.Clear()
	out, err := s.Client.Artifacts(ctx, row.repository(), token, run, page)
	if check := s.currentConnection(a, row, false, "github.actions.read"); check != nil {
		return ArtifactPage{}, check
	}
	return out, err
}
func (s *Service) Content(ctx context.Context, a *auth.Access, server, id string, run, item int64, artifact bool) ([]byte, error) {
	permission := "github.actions.logs.read"
	if artifact {
		permission = "github.actions.artifacts.read"
	}
	row, token, err := s.operationToken(ctx, a, server, id, permission, false, true)
	if err != nil {
		return nil, err
	}
	defer token.Clear()
	var data []byte
	if artifact {
		data, err = s.Client.ArtifactZIP(ctx, row.repository(), token, run, item)
	} else {
		data, err = s.Client.JobLog(ctx, row.repository(), token, run, item)
	}
	if check := s.currentConnection(a, row, true, permission); check != nil {
		clear(data)
		return nil, check
	}
	if ctx.Err() != nil {
		clear(data)
		return nil, ErrDenied
	}
	return data, err
}

type Cancellation struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	ServerID        string     `json:"serverId"`
	ConnectionID    string     `json:"connectionId"`
	ActorID         string     `json:"actorId"`
	SourceSessionID string     `json:"-"`
	RunID           int64      `json:"runId"`
	RunAttempt      int64      `json:"runAttempt"`
	State           string     `json:"state"`
	CreatedAt       time.Time  `json:"createdAt"`
	SubmittedAt     *time.Time `json:"submittedAt"`
}

func (Cancellation) TableName() string { return "github_cancellations" }
func (s *Service) Cancellations(a *auth.Access, server string) ([]Cancellation, error) {
	if err := s.require(a, server, false, "github.actions.read"); err != nil {
		return nil, err
	}
	if err := s.DB.Model(&Cancellation{}).Where("server_id=? AND state='prepared' AND created_at<?", server, time.Now().UTC().Add(-2*time.Minute)).Update("state", "not_submitted").Error; err != nil {
		return nil, err
	}
	rows := []Cancellation{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}
func (s *Service) Cancel(ctx context.Context, a *auth.Access, server, connectionID, id string, run, attempt int64) (Cancellation, error) {
	var row Cancellation
	if !ValidRequestID(id) || !validID(run) || !validID(attempt) {
		return row, ErrInput
	}
	const permission = "github.actions.cancel"
	if err := s.require(a, server, true, permission, "secrets.use"); err != nil {
		return row, err
	}
	created := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, permission, "secrets.use"); err != nil {
			return err
		}
		if err := tx.First(&row, "id=?", id).Error; err == nil {
			if row.ServerID != server || row.ConnectionID != connectionID || row.ActorID != a.User.ID || row.SourceSessionID != a.Session.ID || row.RunID != run || row.RunAttempt != attempt {
				return ErrConflict
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if _, _, err := inside.connection(server, connectionID); err != nil {
			return err
		}
		row = Cancellation{ID: id, ServerID: server, ConnectionID: connectionID, ActorID: a.User.ID, SourceSessionID: a.Session.ID, RunID: run, RunAttempt: attempt, State: "prepared", CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		created = true
		return authorization.New(tx).Record(a.User.ID, "github.cancel.reserve", id, "prepared", "", a.Session.ID)
	})
	if err != nil {
		return Cancellation{}, err
	}
	if !created {
		return row, nil
	}
	finish := func(state string, cause error) (Cancellation, error) {
		result := s.DB.Model(&Cancellation{}).Where("id=? AND state IN ('prepared','submitting')", id).Update("state", state)
		if result.Error != nil || result.RowsAffected != 1 {
			return row, ErrUnknown
		}
		row.State = state
		return row, cause
	}
	connection, token, err := s.operationToken(ctx, a, server, connectionID, permission, true, true)
	if err != nil {
		return finish("not_submitted", err)
	}
	defer token.Clear()
	remote, err := s.Client.Run(ctx, connection.repository(), token, run)
	if err != nil {
		return finish("not_submitted", err)
	}
	if remote.RunAttempt != attempt || remote.Status == "completed" {
		return finish("not_submitted", ErrConflict)
	}
	allowed := func() bool { return ctx.Err() == nil && s.currentConnection(a, connection, true, permission) == nil }
	if !allowed() {
		return finish("not_submitted", ErrDenied)
	}
	now := time.Now().UTC()
	result := s.DB.Model(&Cancellation{}).Where("id=? AND state='prepared'", id).Updates(map[string]any{"state": "submitting", "submitted_at": now})
	if result.Error != nil || result.RowsAffected != 1 {
		return row, ErrConflict
	}
	row.State = "submitting"
	row.SubmittedAt = &now
	err = s.Client.CancelOnce(ctx, connection.repository(), token, run, allowed)
	state := "requested"
	if err != nil {
		state = "unknown"
		if errors.Is(err, ErrInput) || errors.Is(err, ErrDenied) || errors.Is(err, ErrConflict) {
			state = "not_submitted"
		}
	}
	return finish(state, err)
}
