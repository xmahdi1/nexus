package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
)

type Change struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	ServerID        string     `json:"serverId"`
	ConnectionID    string     `json:"connectionId"`
	ActorID         string     `json:"actorId"`
	SourceSessionID string     `json:"-"`
	Kind            string     `json:"kind"`
	InputEnc        string     `json:"-"`
	State           string     `json:"state"`
	Phase           string     `json:"phase"`
	ResourceID      int64      `json:"resourceId"`
	Branch          string     `json:"branch"`
	CommitSHA       string     `json:"commitSha"`
	PullNumber      int64      `json:"pullNumber"`
	CreatedAt       time.Time  `json:"createdAt"`
	SubmittedAt     *time.Time `json:"submittedAt"`
}

func (Change) TableName() string { return "github_changes" }
func (s *Service) Changes(a *auth.Access, server string) ([]Change, error) {
	if err := s.require(a, server, false, "github.actions.read"); err != nil {
		return nil, err
	}
	// Prepared records have never claimed a provider write. No recovery path sends.
	if err := s.DB.Model(&Change{}).Where("server_id=? AND state='prepared' AND created_at<?", server, time.Now().UTC().Add(-2*time.Minute)).Update("state", "not_submitted").Error; err != nil {
		return nil, err
	}
	rows := []Change{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}
func (s *Service) reserveChange(a *auth.Access, server, connection, id, kind, permission string, input any) (Change, bool, error) {
	var row Change
	if !ValidRequestID(id) {
		return row, false, ErrInput
	}
	if err := s.require(a, server, true, permission, "secrets.use"); err != nil {
		return row, false, err
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return row, false, ErrInput
	}
	defer clear(payload)
	created := false
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, permission, "secrets.use"); err != nil {
			return err
		}
		if err := tx.First(&row, "id=?", id).Error; err == nil {
			if row.ServerID != server || row.ConnectionID != connection || row.ActorID != a.User.ID || row.SourceSessionID != a.Session.ID || row.Kind != kind {
				return ErrConflict
			}
			previous, err := nexuscrypto.DecryptGitHubPayload(s.Key, "change", id, server, row.InputEnc)
			defer clear(previous)
			if err != nil || string(previous) != string(payload) {
				return ErrConflict
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if _, _, err := inside.connection(server, connection); err != nil {
			return err
		}
		sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "change", id, server, payload)
		if err != nil {
			return err
		}
		row = Change{ID: id, ServerID: server, ConnectionID: connection, ActorID: a.User.ID, SourceSessionID: a.Session.ID, Kind: kind, InputEnc: sealed, State: "prepared", CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		created = true
		return authorization.New(tx).Record(a.User.ID, "github.change.reserve", id, "prepared", "", a.Session.ID)
	})
	if err != nil {
		return Change{}, false, err
	}
	return row, created, nil
}
func (s *Service) saveChange(row *Change, from, state, phase string) error {
	result := s.DB.Model(&Change{}).Where("id=? AND state=?", row.ID, from).Updates(map[string]any{"state": state, "phase": phase, "resource_id": row.ResourceID, "branch": row.Branch, "commit_sha": row.CommitSHA, "pull_number": row.PullNumber, "submitted_at": row.SubmittedAt})
	if result.Error != nil || result.RowsAffected != 1 {
		row.State = "unknown"
		row.Phase = phase
		return ErrUnknown
	}
	row.State = state
	row.Phase = phase
	return nil
}
func (s *Service) scopedToken(ctx context.Context, a *auth.Access, server, id, permission, scope string, write bool) (Connection, *Token, error) {
	if err := s.require(a, server, true, permission, "secrets.use"); err != nil {
		return Connection{}, nil, err
	}
	row, data, err := s.connection(server, id)
	if err != nil {
		return row, nil, err
	}
	key := []byte(data.PEM)
	defer clear(key)
	app := App{ClientID: data.ClientID, InstallationID: data.InstallationID, PrivateKey: key}
	var token *Token
	if scope == "runners" {
		token, err = s.Client.RunnerToken(ctx, app, data.Repository, write)
	} else if scope == "workflows" {
		token, err = s.Client.WorkflowToken(ctx, app, data.Repository, write)
	} else {
		return row, nil, ErrInput
	}
	if err != nil {
		return row, nil, err
	}
	if err := s.currentConnection(a, row, true, permission); err != nil {
		token.Clear()
		return row, nil, err
	}
	return row, token, nil
}
func (s *Service) ProviderRunners(ctx context.Context, a *auth.Access, server, id string, page int) (RunnerPage, error) {
	row, token, err := s.scopedToken(ctx, a, server, id, "github.runners.provider.read", "runners", false)
	if err != nil {
		return RunnerPage{}, err
	}
	defer token.Clear()
	out, err := s.Client.Runners(ctx, row.repository(), token, page)
	if check := s.currentConnection(a, row, true, "github.runners.provider.read"); check != nil {
		return RunnerPage{}, check
	}
	return out, err
}

type RemoveRunner struct {
	RunnerID int64  `json:"runnerId"`
	Name     string `json:"name"`
}

func (s *Service) RemoveProviderRunner(ctx context.Context, a *auth.Access, server, connection, id string, input RemoveRunner) (Change, error) {
	if !validID(input.RunnerID) || len(input.Name) < 1 || len(input.Name) > 128 {
		return Change{}, ErrInput
	}
	const permission = "github.runners.provider.manage"
	row, created, err := s.reserveChange(a, server, connection, id, "runner_remove", permission, input)
	if err != nil || !created {
		return row, err
	}
	row.ResourceID = input.RunnerID
	finish := func(state string, cause error) (Change, error) {
		from := row.State
		if err := s.saveChange(&row, from, state, row.Phase); err != nil {
			return row, err
		}
		return row, cause
	}
	c, token, err := s.scopedToken(ctx, a, server, connection, permission, "runners", true)
	if err != nil {
		return finish("not_submitted", err)
	}
	defer token.Clear()
	current, err := s.Client.Runner(ctx, c.repository(), token, input.RunnerID)
	if err != nil {
		return finish("not_submitted", err)
	}
	if current.Name != input.Name || current.Status != "offline" || current.Busy {
		return finish("not_submitted", ErrConflict)
	}
	allowed := func() bool { return ctx.Err() == nil && s.currentConnection(a, c, true, permission) == nil }
	if !allowed() {
		return finish("not_submitted", ErrDenied)
	}
	now := time.Now().UTC()
	row.SubmittedAt = &now
	if err := s.saveChange(&row, "prepared", "submitting", "runner_delete"); err != nil {
		return row, err
	}
	err = s.Client.RemoveRunnerOnce(ctx, c.repository(), token, input.RunnerID, allowed)
	state := "applied"
	if err != nil {
		state = "unknown"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrInput) {
			state = "not_submitted"
		}
	}
	return finish(state, err)
}
