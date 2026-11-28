package githubactions

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
)

type OrganizationConnection struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	ServerID       string    `json:"serverId"`
	Login          string    `json:"login"`
	OrganizationID int64     `json:"organizationId"`
	ClientID       string    `json:"clientId"`
	InstallationID int64     `json:"installationId"`
	ConfigEnc      string    `json:"-"`
	Disabled       bool      `json:"disabled"`
	CreatedBy      string    `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (OrganizationConnection) TableName() string { return "github_organizations" }
func (row OrganizationConnection) organization() Organization {
	return Organization{Login: row.Login, ID: row.OrganizationID}
}

type OrganizationInput struct {
	Organization
	ClientID       string `json:"clientId"`
	InstallationID int64  `json:"installationId"`
	PrivateKey     string `json:"privateKey"`
}
type privateOrganization struct {
	Organization   Organization
	ClientID       string
	InstallationID int64
	PEM            string
}
type OrganizationChange struct {
	ID              string     `gorm:"primaryKey" json:"id"`
	ServerID        string     `json:"serverId"`
	ConnectionID    string     `json:"connectionId"`
	ActorID         string     `json:"actorId"`
	SourceSessionID string     `json:"-"`
	Kind            string     `json:"kind"`
	InputEnc        string     `json:"-"`
	State           string     `json:"state"`
	ResourceID      int64      `json:"resourceId"`
	CreatedAt       time.Time  `json:"createdAt"`
	SubmittedAt     *time.Time `json:"submittedAt"`
	ExpiresAt       *time.Time `json:"expiresAt"`
}

func (OrganizationChange) TableName() string { return "github_organization_changes" }
func (s *Service) Organizations(a *auth.Access, server string) ([]OrganizationConnection, error) {
	if err := s.require(a, server, true, "github.organizations.read"); err != nil {
		return nil, err
	}
	rows := []OrganizationConnection{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(30).Find(&rows).Error
	return rows, err
}
func (s *Service) CreateOrganization(ctx context.Context, a *auth.Access, server string, input OrganizationInput) (OrganizationConnection, error) {
	var row OrganizationConnection
	permissions := []string{"github.organizations.connections.manage", "secrets.create", "secrets.use"}
	if err := s.require(a, server, true, permissions...); err != nil {
		return row, err
	}
	if input.Organization.Validate() != nil {
		return row, ErrInput
	}
	key := []byte(input.PrivateKey)
	defer clear(key)
	token, err := s.Client.OrganizationToken(ctx, App{ClientID: input.ClientID, InstallationID: input.InstallationID, PrivateKey: key}, input.Organization, false)
	if err != nil {
		return row, err
	}
	defer token.Clear()
	if ctx.Err() != nil {
		return row, ErrDenied
	}
	id, err := audit.NewID()
	if err != nil {
		return row, err
	}
	data, _ := json.Marshal(privateOrganization{input.Organization, input.ClientID, input.InstallationID, input.PrivateKey})
	defer clear(data)
	sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "organization", id, server, data)
	if err != nil {
		return row, err
	}
	row = OrganizationConnection{ID: id, ServerID: server, Login: input.Login, OrganizationID: input.Organization.ID, ClientID: input.ClientID, InstallationID: input.InstallationID, ConfigEnc: sealed, CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, permissions...); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&OrganizationConnection{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 30 {
			return ErrInput
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "github.organization.create", row.ID, "created", "", a.Session.ID)
	})
	return row, err
}
func (s *Service) DisableOrganization(a *auth.Access, server, id string) error {
	if !ValidRequestID(id) {
		return ErrInput
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "github.organizations.connections.manage"); err != nil {
			return err
		}
		result := tx.Model(&OrganizationConnection{}).Where("id=? AND server_id=?", id, server).Update("disabled", true)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrDenied
		}
		return authorization.New(tx).Record(a.User.ID, "github.organization.disable", id, "disabled", "", a.Session.ID)
	})
}
func (s *Service) organizationConnection(server, id string) (OrganizationConnection, privateOrganization, error) {
	var row OrganizationConnection
	var data privateOrganization
	if !ValidRequestID(id) {
		return row, data, ErrInput
	}
	if err := s.DB.First(&row, "id=? AND server_id=? AND disabled=0", id, server).Error; err != nil {
		return row, data, ErrDenied
	}
	plain, err := nexuscrypto.DecryptGitHubPayload(s.Key, "organization", id, server, row.ConfigEnc)
	if err != nil {
		return row, data, ErrDenied
	}
	defer clear(plain)
	if json.Unmarshal(plain, &data) != nil || data.Organization != row.organization() || data.ClientID != row.ClientID || data.InstallationID != row.InstallationID {
		return row, data, ErrConflict
	}
	return row, data, nil
}
func (s *Service) currentOrganization(a *auth.Access, row OrganizationConnection, permissions ...string) error {
	if err := s.require(a, row.ServerID, true, permissions...); err != nil {
		return err
	}
	current, _, err := s.organizationConnection(row.ServerID, row.ID)
	if err != nil {
		return err
	}
	if current.ConfigEnc != row.ConfigEnc {
		return ErrConflict
	}
	return nil
}
func (s *Service) organizationToken(ctx context.Context, a *auth.Access, server, id, permission string, write bool) (OrganizationConnection, *OrganizationToken, error) {
	if err := s.require(a, server, true, permission, "secrets.use"); err != nil {
		return OrganizationConnection{}, nil, err
	}
	row, data, err := s.organizationConnection(server, id)
	if err != nil {
		return row, nil, err
	}
	key := []byte(data.PEM)
	defer clear(key)
	token, err := s.Client.OrganizationToken(ctx, App{ClientID: data.ClientID, InstallationID: data.InstallationID, PrivateKey: key}, data.Organization, write)
	if err != nil {
		return row, nil, err
	}
	if ctx.Err() != nil {
		token.Clear()
		return row, nil, ErrDenied
	}
	if err := s.currentOrganization(a, row, permission, "secrets.use"); err != nil {
		token.Clear()
		return row, nil, err
	}
	return row, token, nil
}
func (s *Service) OrganizationRunners(ctx context.Context, a *auth.Access, server, id string, page int) (RunnerPage, error) {
	row, token, err := s.organizationToken(ctx, a, server, id, "github.organizations.read", false)
	if err != nil {
		return RunnerPage{}, err
	}
	defer token.Clear()
	result, err := s.Client.OrganizationRunners(ctx, row.organization(), token, page)
	if check := s.currentOrganization(a, row, "github.organizations.read", "secrets.use"); check != nil {
		return RunnerPage{}, check
	}
	return result, err
}
func (s *Service) OrganizationChanges(a *auth.Access, server string) ([]OrganizationChange, error) {
	if err := s.require(a, server, true, "github.organizations.read"); err != nil {
		return nil, err
	}
	if err := s.DB.Model(&OrganizationChange{}).Where("server_id=? AND state='prepared' AND created_at<?", server, time.Now().UTC().Add(-2*time.Minute)).Update("state", "not_submitted").Error; err != nil {
		return nil, err
	}
	rows := []OrganizationChange{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}
func (s *Service) reserveOrganizationChange(a *auth.Access, server, connection, id, kind string, input RemoveRunner) (OrganizationChange, bool, error) {
	var row OrganizationChange
	permission := "github.organizations.runners.manage"
	extra := "secrets.use"
	if kind == "registration" {
		permission = "github.organizations.runners.register"
		extra = "secrets.reveal"
	} else if kind != "runner_remove" {
		return row, false, ErrInput
	}
	if !ValidRequestID(id) {
		return row, false, ErrInput
	}
	payload, _ := json.Marshal(input)
	defer clear(payload)
	created := false
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, permission, extra, "secrets.use"); err != nil {
			return err
		}
		if err := tx.First(&row, "id=?", id).Error; err == nil {
			if row.ServerID != server || row.ConnectionID != connection || row.Kind != kind || row.ActorID != a.User.ID || row.SourceSessionID != a.Session.ID {
				return ErrConflict
			}
			previous, err := nexuscrypto.DecryptGitHubPayload(s.Key, "organization-change", id, server, row.InputEnc)
			defer clear(previous)
			if err != nil || string(previous) != string(payload) {
				return ErrConflict
			}
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if _, _, err := inside.organizationConnection(server, connection); err != nil {
			return err
		}
		sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "organization-change", id, server, payload)
		if err != nil {
			return err
		}
		row = OrganizationChange{ID: id, ServerID: server, ConnectionID: connection, ActorID: a.User.ID, SourceSessionID: a.Session.ID, Kind: kind, InputEnc: sealed, State: "prepared", ResourceID: input.RunnerID, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		created = true
		return authorization.New(tx).Record(a.User.ID, "github.organization.reserve", id, "prepared", "", a.Session.ID)
	})
	if err != nil {
		return OrganizationChange{}, false, err
	}
	return row, created, nil
}
func (s *Service) saveOrganizationChange(row *OrganizationChange, state string) error {
	result := s.DB.Model(&OrganizationChange{}).Where("id=? AND state=?", row.ID, row.State).Updates(map[string]any{"state": state, "submitted_at": row.SubmittedAt, "expires_at": row.ExpiresAt})
	if result.Error != nil || result.RowsAffected != 1 {
		row.State = "unknown"
		return ErrUnknown
	}
	row.State = state
	return nil
}

// ChangeOrganizationRunner claims exactly one write. History never reissues a
// token, resumes a provider request or exposes token content from an old request.
func (s *Service) ChangeOrganizationRunner(ctx context.Context, a *auth.Access, server, connection, id, kind string, input RemoveRunner) (OrganizationChange, *RegistrationCredential, error) {
	if kind == "runner_remove" && (!validID(input.RunnerID) || len(input.Name) < 1 || len(input.Name) > 128 || strings.ContainsAny(input.Name, "\x00\r\n")) {
		return OrganizationChange{}, nil, ErrInput
	}
	if kind == "registration" && (input.RunnerID != 0 || input.Name != "") {
		return OrganizationChange{}, nil, ErrInput
	}
	row, created, err := s.reserveOrganizationChange(a, server, connection, id, kind, input)
	if err != nil || !created {
		return row, nil, err
	}
	finish := func(state string, cause error) (OrganizationChange, *RegistrationCredential, error) {
		if err := s.saveOrganizationChange(&row, state); err != nil {
			return row, nil, err
		}
		return row, nil, cause
	}
	permission := "github.organizations.runners.manage"
	permissions := []string{permission, "secrets.use"}
	if kind == "registration" {
		permission = "github.organizations.runners.register"
		permissions = []string{permission, "secrets.use", "secrets.reveal"}
	}
	current, token, err := s.organizationToken(ctx, a, server, connection, permission, true)
	if err != nil {
		return finish("not_submitted", err)
	}
	defer token.Clear()
	allowed := func() bool { return ctx.Err() == nil && s.currentOrganization(a, current, permissions...) == nil }
	if kind == "runner_remove" {
		runner, err := s.Client.OrganizationRunner(ctx, current.organization(), token, input.RunnerID)
		if err != nil {
			return finish("not_submitted", err)
		}
		if runner.Name != input.Name || runner.Busy || runner.Status != "offline" {
			return finish("not_submitted", ErrConflict)
		}
	}
	if !allowed() {
		return finish("not_submitted", ErrDenied)
	}
	now := time.Now().UTC()
	row.SubmittedAt = &now
	if err := s.saveOrganizationChange(&row, "submitting"); err != nil {
		return row, nil, err
	}
	var credential *RegistrationCredential
	if kind == "registration" {
		result, cause := s.Client.OrganizationRegistrationOnce(ctx, current.organization(), token, allowed)
		err = cause
		if err == nil {
			credential = &result
			row.ExpiresAt = &result.ExpiresAt
		}
	} else {
		err = s.Client.RemoveOrganizationRunnerOnce(ctx, current.organization(), token, input.RunnerID, allowed)
	}
	state := "applied"
	if err != nil {
		state = "unknown"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrInput) {
			state = "not_submitted"
		}
	}
	if err := s.saveOrganizationChange(&row, state); err != nil {
		if credential != nil {
			credential.Token = ""
		}
		return row, nil, err
	}
	if !allowed() {
		if credential != nil {
			credential.Token = ""
		}
		return row, nil, ErrDenied
	}
	return row, credential, err
}
