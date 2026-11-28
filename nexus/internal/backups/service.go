package backups

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

type Service struct {
	DB       *gorm.DB
	Key      []byte
	Sessions *auth.Service
	Enabled  bool
	DBPath   string
	WorkRoot string
}

type envelope struct {
	Salt    []byte          `json:"salt"`
	Payload json.RawMessage `json:"payload"`
}

func (s *Service) seal(id, server string, data sealedDefinition) (string, string, error) {
	payload, err := json.Marshal(data)
	if err != nil || len(payload) > 64<<10 {
		return "", "", ErrInput
	}
	defer clear(payload)
	salt := make([]byte, 32)
	defer clear(salt)
	if _, err = rand.Read(salt); err != nil {
		return "", "", err
	}
	hash := sha256.New()
	hash.Write(salt)
	hash.Write(payload)
	wrapped, err := json.Marshal(envelope{salt, payload})
	if err != nil {
		return "", "", err
	}
	defer clear(wrapped)
	value, err := nexuscrypto.EncryptBackupPolicy(s.Key, id, server, wrapped)
	return value, hex.EncodeToString(hash.Sum(nil)), err
}
func (s *Service) config(row Policy) (sealedDefinition, error) {
	var result sealedDefinition
	data, err := nexuscrypto.DecryptBackupPolicy(s.Key, row.ID, row.ServerID, row.ConfigEnc)
	if err != nil {
		return result, ErrConflict
	}
	defer clear(data)
	var wrapped envelope
	if json.Unmarshal(data, &wrapped) != nil || len(wrapped.Salt) != 32 {
		return result, ErrConflict
	}
	defer clear(wrapped.Salt)
	defer clear(wrapped.Payload)
	hash := sha256.New()
	hash.Write(wrapped.Salt)
	hash.Write(wrapped.Payload)
	if hex.EncodeToString(hash.Sum(nil)) != row.Digest || json.Unmarshal(wrapped.Payload, &result) != nil || result.ServerID != row.ServerID || result.OwnerID != row.ActorID || result.Name != row.Name || result.Timing.Mode != row.Mode || result.Timing.IntervalMinutes != row.IntervalMinutes || result.Definition.Validate(row.ServerID == "") != nil {
		return sealedDefinition{}, ErrConflict
	}
	return result, nil
}
func (s *Service) require(a *auth.Access, server string, high bool, permissions ...string) error {
	if !s.Enabled {
		return ErrDisabled
	}
	if server == "" {
		permissions = append(permissions, "backups.nexus.manage")
	}
	if a == nil || !a.AuthorizedNow() || !authorization.New(s.DB).All(a.User.ID, server, permissions...) {
		return ErrDenied
	}
	if high && server != "" {
		protected, err := authorization.New(s.DB).Protected(server)
		if err != nil || (protected && !a.RecentMFA()) {
			return ErrDenied
		}
	}
	return nil
}
func (s *Service) hostBinding(server string) (string, error) {
	if server == "" {
		return "nexus-local", nil
	}
	var host models.Server
	if err := s.DB.First(&host, "id=?", server).Error; err != nil {
		return "", err
	}
	if host.Username != "root" || !strings.HasPrefix(host.KnownHostKey, "SHA256:") || len(host.KnownHostKey) != 50 {
		return "", ErrInput
	}
	key, err := nexuscrypto.Decrypt(s.Key, host.PrivateKeyEnc)
	if err != nil {
		return "", ErrInput
	}
	defer clear(key)
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return "", ErrInput
	}
	data := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s\x00%s", host.ID, host.Host, host.Port, host.Username, host.KnownHostKey, ssh.FingerprintSHA256(signer.PublicKey()))
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:]), nil
}
func (s *Service) ownerAllowed(row Policy, config sealedDefinition) bool {
	permissions := []string{"backups.manage", "secrets.use"}
	if row.ServerID != "" {
		permissions = append(permissions, "servers.read", "servers.connect")
	} else {
		permissions = append(permissions, "backups.nexus.manage", "secrets.reveal")
	}
	if !s.Enabled || !authorization.New(s.DB).All(row.ActorID, row.ServerID, permissions...) {
		return false
	}
	current, err := s.hostBinding(row.ServerID)
	return err == nil && current == config.HostBinding
}
func (s *Service) policy(server, id string) (Policy, error) {
	var row Policy
	if !idPattern.MatchString(id) {
		return row, ErrInput
	}
	err := s.DB.First(&row, "id=? AND server_id=?", id, server).Error
	return row, err
}
func (s *Service) view(row Policy) (PolicyView, error) {
	data, err := s.config(row)
	if err != nil {
		return PolicyView{}, err
	}
	result := PolicyView{Policy: row, RepositoryKind: data.Repository.Kind, SourceKinds: []string{}, Repository: RepositoryView{Kind: data.Repository.Kind, Location: data.Repository.Location, Region: data.Repository.Region}, Sources: []SourceView{}}
	for _, source := range data.Sources {
		result.SourceKinds = append(result.SourceKinds, source.Kind)
		result.Sources = append(result.Sources, SourceView{Kind: source.Kind, Label: source.Label, Path: source.Path, ContainerID: source.ContainerID, Volume: source.Volume})
	}
	return result, nil
}
func (s *Service) Policies(a *auth.Access, server string) ([]PolicyView, error) {
	if err := s.require(a, server, false, "backups.read"); err != nil {
		return nil, err
	}
	rows := []Policy{}
	if err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error; err != nil {
		return nil, err
	}
	result := []PolicyView{}
	for _, row := range rows {
		view, err := s.view(row)
		if err != nil {
			return nil, err
		}
		result = append(result, view)
	}
	if err := s.require(a, server, false, "backups.read"); err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Service) Create(a *auth.Access, server, id string, definition Definition) (PolicyView, error) {
	if !idPattern.MatchString(id) || definition.Validate(server == "") != nil {
		return PolicyView{}, ErrInput
	}
	now := time.Now().UTC()
	if definition.Timing.At != nil {
		at := definition.Timing.At.UTC()
		definition.Timing.At = &at
		if at.Before(now.Add(-time.Minute)) || at.After(now.AddDate(1, 0, 0)) {
			return PolicyView{}, ErrInput
		}
	}
	workRoot := s.WorkRoot
	if server != "" {
		workRoot = "/var/lib/nexus-backups"
	}
	if definition.Repository.Kind == "local" && workRoot != "" && (definition.Repository.Location == workRoot || strings.HasPrefix(definition.Repository.Location, workRoot+"/")) {
		return PolicyView{}, ErrInput
	}
	for _, source := range definition.Sources {
		if source.Path != "" && workRoot != "" && (source.Path == workRoot || strings.HasPrefix(source.Path, workRoot+"/")) {
			return PolicyView{}, ErrInput
		}
		if source.Path != "" && definition.Repository.Kind == "local" && (source.Path == definition.Repository.Location || strings.HasPrefix(source.Path, definition.Repository.Location+"/")) {
			return PolicyView{}, ErrInput
		}
	}
	if definition.ExportLimitGiB == 0 {
		definition.ExportLimitGiB = 10
	}
	required := []string{"backups.manage", "backups.read", "secrets.create", "secrets.use"}
	if server != "" {
		required = append(required, "servers.connect")
	} else {
		required = append(required, "secrets.reveal")
	}
	if definition.Timing.Mode != "manual" {
		required = append(required, "backups.schedule")
	}
	if err := s.require(a, server, true, required...); err != nil {
		return PolicyView{}, err
	}
	binding, err := s.hostBinding(server)
	if err != nil {
		return PolicyView{}, err
	}
	data := sealedDefinition{Definition: definition, ServerID: server, OwnerID: a.User.ID, HostBinding: binding}
	var row Policy
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, required...); err != nil {
			return err
		}
		var old Policy
		if err := tx.First(&old, "id=?", id).Error; err == nil {
			if old.ServerID != server || old.ActorID != a.User.ID {
				return ErrConflict
			}
			previous, err := inside.config(old)
			if err != nil {
				return err
			}
			before, _ := json.Marshal(previous)
			after, _ := json.Marshal(data)
			defer clear(before)
			defer clear(after)
			if string(before) != string(after) {
				return ErrConflict
			}
			row = old
			return nil
		} else if err != gorm.ErrRecordNotFound {
			return err
		}
		var count int64
		if err := tx.Model(&Policy{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrInput
		}
		sealed, digest, err := inside.seal(id, server, data)
		if err != nil {
			return err
		}
		row = Policy{ID: id, ServerID: server, Name: definition.Name, ActorID: a.User.ID, ConfigEnc: sealed, Digest: digest, Mode: definition.Timing.Mode, IntervalMinutes: definition.Timing.IntervalMinutes, LastState: "setup_required", CreatedAt: now}
		if definition.Timing.Mode != "manual" {
			at := now.Add(time.Duration(definition.Timing.IntervalMinutes) * time.Minute)
			if definition.Timing.At != nil {
				at = *definition.Timing.At
			}
			row.NextAt = &at
		}
		// New schedules stay paused until the operator initializes/tests the repository.
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "backup.policy.create", id, "setup_required", "", a.Session.ID)
	})
	if err != nil {
		return PolicyView{}, err
	}
	return s.view(row)
}
func (s *Service) SetEnabled(a *auth.Access, server, id string, enabled bool) error {
	if err := s.require(a, server, true, "backups.manage", "backups.schedule"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		row, err := inside.policy(server, id)
		if err != nil {
			return err
		}
		if err := inside.require(a, server, true, "backups.manage", "backups.schedule"); err != nil {
			return err
		}
		if row.Archived || row.Mode == "manual" {
			return ErrInput
		}
		updates := map[string]any{"enabled": enabled, "last_state": "paused"}
		if enabled {
			data, err := inside.config(row)
			if err != nil {
				return err
			}
			if row.ActorID != a.User.ID || !inside.ownerAllowed(row, data) || !authorization.New(tx).All(row.ActorID, server, "backups.execute", "backups.schedule", "jobs.execute") {
				return ErrDenied
			}
			if server != "" {
				protected, err := authorization.New(tx).Protected(server)
				if err != nil || protected {
					return ErrDenied
				}
			}
			if row.LastSuccessAt == nil && row.LastCheckAt == nil {
				return ErrInput
			}
			if row.NextAt == nil || !row.NextAt.After(time.Now().UTC()) {
				updates["next_at"] = time.Now().UTC()
			}
			updates["last_state"] = "scheduled"
		}
		if err := tx.Model(&row).Updates(updates).Error; err != nil {
			return err
		}
		state := "paused"
		if enabled {
			state = "scheduled"
		}
		return authorization.New(tx).Record(a.User.ID, "backup.schedule.change", id, state, "", a.Session.ID)
	})
}
func (s *Service) Archive(a *auth.Access, server, id string) error {
	if err := s.require(a, server, true, "backups.manage"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.require(a, server, true, "backups.manage"); err != nil {
			return err
		}
		changed := tx.Model(&Policy{}).Where("id=? AND server_id=?", id, server).Updates(map[string]any{"archived": true, "enabled": false})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return authorization.New(tx).Record(a.User.ID, "backup.policy.archive", id, "archived", "", a.Session.ID)
	})
}
