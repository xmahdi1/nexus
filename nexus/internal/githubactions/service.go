package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

var ErrDisabled = errors.New("automation is disabled")
var identityPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidRequestID(value string) bool { return identityPattern.MatchString(value) }

type Connection struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	ServerID       string    `json:"serverId"`
	Owner          string    `json:"owner"`
	Name           string    `json:"name"`
	RepositoryID   int64     `json:"repositoryId"`
	ClientID       string    `json:"clientId"`
	InstallationID int64     `json:"installationId"`
	ConfigEnc      string    `json:"-"`
	CreatedBy      string    `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
	Disabled       bool      `json:"disabled"`
}

func (Connection) TableName() string { return "github_connections" }
func (c Connection) repository() Repository {
	return Repository{Owner: c.Owner, Name: c.Name, ID: c.RepositoryID}
}

type ConnectionInput struct {
	Repository
	ClientID       string `json:"clientId"`
	InstallationID int64  `json:"installationId"`
	PrivateKey     string `json:"privateKey"`
}
type privateConnection struct {
	Repository     Repository
	ClientID       string
	InstallationID int64
	PEM            string
}
type Submission struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	ServerID        string     `json:"serverId"`
	ConnectionID    string     `json:"connectionId"`
	ActorID         string     `json:"actorId"`
	SourceSessionID string     `json:"-"`
	InputEnc        string     `json:"-"`
	State           string     `json:"state"`
	WorkflowID      int64      `json:"workflowId"`
	Ref             string     `json:"ref"`
	RunID           int64      `json:"runId"`
	CreatedAt       time.Time  `json:"createdAt"`
	SubmittedAt     *time.Time `json:"submittedAt"`
}

func (Submission) TableName() string { return "github_dispatches" }

type Service struct {
	DB       *gorm.DB
	Key      []byte
	Sessions *auth.Service
	Enabled  bool
	Client   *Client
}

func (s *Service) require(a *auth.Access, server string, high bool, permissions ...string) error {
	if !s.Enabled {
		return ErrDisabled
	}
	if a == nil || !a.AuthorizedNow() || !authorization.New(s.DB).All(a.User.ID, server, append(permissions, "servers.read")...) {
		return ErrDenied
	}
	var count int64
	if s.DB.Model(&models.Server{}).Where("id=?", server).Count(&count).Error != nil || count != 1 {
		return ErrDenied
	}
	if high {
		protected, err := authorization.New(s.DB).Protected(server)
		if err != nil || (protected && !a.RecentMFA()) {
			return ErrDenied
		}
	}
	return nil
}
func (s *Service) List(a *auth.Access, server string) ([]Connection, error) {
	if err := s.require(a, server, false, "github.actions.read"); err != nil {
		return nil, err
	}
	rows := []Connection{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(30).Find(&rows).Error
	return rows, err
}
func (s *Service) Create(ctx context.Context, a *auth.Access, server string, input ConnectionInput) (Connection, error) {
	var row Connection
	if err := s.require(a, server, true, "github.connections.manage", "secrets.create", "secrets.use"); err != nil {
		return row, err
	}
	if input.Repository.Validate() != nil {
		return row, ErrInput
	}
	key := []byte(input.PrivateKey)
	defer clear(key)
	token, err := s.Client.InstallationToken(ctx, App{ClientID: input.ClientID, InstallationID: input.InstallationID, PrivateKey: key}, input.Repository, false)
	if err != nil {
		return row, err
	}
	defer token.Clear()
	if ctx.Err() != nil {
		return row, ErrDenied
	}
	if err := s.require(a, server, true, "github.connections.manage", "secrets.create", "secrets.use"); err != nil {
		return row, err
	}
	id, err := audit.NewID()
	if err != nil {
		return row, err
	}
	data, _ := json.Marshal(privateConnection{input.Repository, input.ClientID, input.InstallationID, input.PrivateKey})
	defer clear(data)
	sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "connection", id, server, data)
	if err != nil {
		return row, err
	}
	row = Connection{ID: id, ServerID: server, Owner: input.Owner, Name: input.Name, RepositoryID: input.Repository.ID, ClientID: input.ClientID, InstallationID: input.InstallationID, ConfigEnc: sealed, CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "github.connections.manage", "secrets.create", "secrets.use"); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&Connection{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 30 {
			return ErrInput
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "github.connection.create", id, "created", "", a.Session.ID)
	})
	return row, err
}
func (s *Service) Disable(a *auth.Access, server, id string) error {
	if err := s.require(a, server, true, "github.connections.manage"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "github.connections.manage"); err != nil {
			return err
		}
		result := tx.Model(&Connection{}).Where("id=? AND server_id=?", id, server).Update("disabled", true)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrDenied
		}
		return authorization.New(tx).Record(a.User.ID, "github.connection.disable", id, "disabled", "", a.Session.ID)
	})
}
func (s *Service) connection(server, id string) (Connection, privateConnection, error) {
	var row Connection
	var data privateConnection
	if !identityPattern.MatchString(id) {
		return row, data, ErrInput
	}
	if err := s.DB.First(&row, "id=? AND server_id=? AND disabled=0", id, server).Error; err != nil {
		return row, data, ErrDenied
	}
	plain, err := nexuscrypto.DecryptGitHubPayload(s.Key, "connection", id, server, row.ConfigEnc)
	if err != nil {
		return row, data, ErrDenied
	}
	defer clear(plain)
	if json.Unmarshal(plain, &data) != nil || data.Repository != row.repository() || data.ClientID != row.ClientID || data.InstallationID != row.InstallationID {
		return row, data, ErrConflict
	}
	return row, data, nil
}
func (s *Service) token(ctx context.Context, a *auth.Access, server, id string, write bool) (Connection, *Token, error) {
	permission := "github.actions.read"
	if write {
		permission = "github.actions.dispatch"
	}
	if err := s.require(a, server, write, permission, "secrets.use"); err != nil {
		return Connection{}, nil, err
	}
	row, data, err := s.connection(server, id)
	if err != nil {
		return row, nil, err
	}
	key := []byte(data.PEM)
	defer clear(key)
	token, err := s.Client.InstallationToken(ctx, App{ClientID: data.ClientID, InstallationID: data.InstallationID, PrivateKey: key}, data.Repository, write)
	return row, token, err
}
func (s *Service) Workflows(ctx context.Context, a *auth.Access, server, id string, page int) (WorkflowPage, error) {
	row, token, err := s.token(ctx, a, server, id, false)
	if err != nil {
		return WorkflowPage{}, err
	}
	defer token.Clear()
	result, err := s.Client.Workflows(ctx, row.repository(), token, page)
	if check := s.require(a, server, false, "github.actions.read", "secrets.use"); check != nil {
		return WorkflowPage{}, check
	}
	if _, _, check := s.connection(server, id); check != nil {
		return WorkflowPage{}, check
	}
	return result, err
}

// Submit permanently reserves request identity before minting credentials or
// contacting Actions. Process recovery may observe history but never dispatches.
func (s *Service) Submit(ctx context.Context, a *auth.Access, server, connectionID, id string, input Dispatch) (Submission, error) {
	var row Submission
	if !identityPattern.MatchString(id) || input.Validate() != nil {
		return row, ErrInput
	}
	if err := s.require(a, server, true, "github.actions.dispatch", "secrets.use"); err != nil {
		return row, err
	}
	payload, _ := json.Marshal(input)
	defer clear(payload)
	created := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "github.actions.dispatch", "secrets.use"); err != nil {
			return err
		}
		if err := tx.First(&row, "id=?", id).Error; err == nil {
			if row.ServerID != server || row.ConnectionID != connectionID || row.ActorID != a.User.ID || row.SourceSessionID != a.Session.ID {
				return ErrConflict
			}
			data, err := nexuscrypto.DecryptGitHubPayload(s.Key, "dispatch", id, server, row.InputEnc)
			defer clear(data)
			if err != nil || string(data) != string(payload) {
				return ErrConflict
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if _, _, err := inside.connection(server, connectionID); err != nil {
			return err
		}
		sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "dispatch", id, server, payload)
		if err != nil {
			return err
		}
		row = Submission{ID: id, ServerID: server, ConnectionID: connectionID, ActorID: a.User.ID, SourceSessionID: a.Session.ID, InputEnc: sealed, State: "prepared", WorkflowID: input.WorkflowID, Ref: input.Ref, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		created = true
		return authorization.New(tx).Record(a.User.ID, "github.dispatch.reserve", id, "prepared", "", a.Session.ID)
	})
	if err != nil {
		return Submission{}, err
	}
	if !created {
		return row, nil
	}
	connection, token, err := s.token(ctx, a, server, connectionID, true)
	if err != nil {
		return s.notSubmitted(row, err)
	}
	defer token.Clear()
	allowed := func() bool {
		if ctx.Err() != nil || s.require(a, server, true, "github.actions.dispatch", "secrets.use") != nil {
			return false
		}
		current, _, err := s.connection(server, connectionID)
		return err == nil && current.ConfigEnc == connection.ConfigEnc
	}
	if !allowed() {
		return s.notSubmitted(row, ErrDenied)
	}
	now := time.Now().UTC()
	claimed := s.DB.Model(&row).Where("state='prepared'").Updates(map[string]any{"state": "submitting", "submitted_at": now})
	if claimed.Error != nil || claimed.RowsAffected != 1 {
		return row, ErrConflict
	}
	row.State = "submitting"
	row.SubmittedAt = &now
	result, err := s.Client.DispatchOnce(ctx, connection.repository(), token, input, allowed)
	state := "submitted"
	if err != nil {
		state = "unknown"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrInput) {
			state = "not_submitted"
		}
	}
	saved := s.DB.Model(&row).Where("state='submitting'").Updates(map[string]any{"state": state, "run_id": result.RunID})
	if saved.Error != nil || saved.RowsAffected != 1 {
		return row, ErrUnknown
	}
	if load := s.DB.First(&row, "id=?", id).Error; load != nil {
		return row, ErrUnknown
	}
	return row, err
}

func (s *Service) notSubmitted(row Submission, cause error) (Submission, error) {
	result := s.DB.Model(&row).Where("state='prepared'").Update("state", "not_submitted")
	if result.Error != nil {
		return row, ErrUnknown
	}
	if err := s.DB.First(&row, "id=?", row.ID).Error; err != nil {
		return row, ErrUnknown
	}
	return row, cause
}
func (s *Service) Submissions(a *auth.Access, server string) ([]Submission, error) {
	if err := s.require(a, server, false, "github.actions.read"); err != nil {
		return nil, err
	}
	// Prepared rows have never entered the provider-write claim. Bounded HTTP
	// preparation has ended after this grace period; retire without replay.
	if err := s.DB.Model(&Submission{}).Where("server_id=? AND state='prepared' AND created_at<?", server, time.Now().UTC().Add(-2*time.Minute)).Update("state", "not_submitted").Error; err != nil {
		return nil, err
	}
	rows := []Submission{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}

func (s *Service) Runs(ctx context.Context, a *auth.Access, server, id string, page int) (RunPage, error) {
	row, token, err := s.token(ctx, a, server, id, false)
	if err != nil {
		return RunPage{}, err
	}
	defer token.Clear()
	result, err := s.Client.Runs(ctx, row.repository(), token, page)
	if check := s.require(a, server, false, "github.actions.read", "secrets.use"); check != nil {
		return RunPage{}, check
	}
	if _, _, check := s.connection(server, id); check != nil {
		return RunPage{}, check
	}
	return result, err
}
func (s *Service) Jobs(ctx context.Context, a *auth.Access, server, id string, run int64, page int) (JobPage, error) {
	row, token, err := s.token(ctx, a, server, id, false)
	if err != nil {
		return JobPage{}, err
	}
	defer token.Clear()
	result, err := s.Client.Jobs(ctx, row.repository(), token, run, page)
	if check := s.require(a, server, false, "github.actions.read", "secrets.use"); check != nil {
		return JobPage{}, check
	}
	if _, _, check := s.connection(server, id); check != nil {
		return JobPage{}, check
	}
	return result, err
}
