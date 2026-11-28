package ansible

import (
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
)

// A preset remembers a selection, never variables, credentials or approval.
type Preset struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	ServerID  string    `json:"serverId"`
	Name      string    `json:"name"`
	ConfigEnc string    `json:"-"`
	Digest    string    `json:"digest"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	Archived  bool      `json:"archived"`
}

func (Preset) TableName() string { return "ansible_presets" }

type PresetSelection struct {
	Name           string   `json:"name"`
	ProjectID      string   `json:"projectId"`
	RevisionID     string   `json:"revisionId"`
	RevisionDigest string   `json:"revisionDigest"`
	GroupID        string   `json:"groupId"`
	ServerIDs      []string `json:"serverIds"`
	Options        Options  `json:"options"`
}

func (s *Service) Presets(a *auth.Access, server string) ([]Preset, error) {
	if err := s.require(a, server, false, "ansible.projects.read"); err != nil {
		return nil, err
	}
	rows := []Preset{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	if err == nil {
		err = s.require(a, server, false, "ansible.projects.read")
	}
	return rows, err
}

// CreatePreset copies only the selection from the caller's own current plan.
// This keeps validation identical to planning and avoids another target resolver.
func (s *Service) CreatePreset(a *auth.Access, server, name, planID string) (Preset, error) {
	var row Preset
	name = strings.TrimSpace(name)
	if name == "" || !safeText(name, 80) || strings.Contains(name, "\n") || !idPattern.MatchString(planID) {
		return row, ErrInput
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.manage", "secrets.create"); err != nil {
			return err
		}
		var plan Plan
		if err := tx.First(&plan, "id=? AND server_id=?", planID, server).Error; err != nil {
			return err
		}
		cfg, err := inside.config(plan)
		if err != nil {
			return err
		}
		if err := inside.sourceAllowed(a, cfg); err != nil {
			return err
		}
		selection := PresetSelection{Name: name, ProjectID: cfg.ProjectID, RevisionID: cfg.RevisionID, RevisionDigest: cfg.RevisionDigest, GroupID: cfg.GroupID, Options: cfg.Options, ServerIDs: []string{}}
		selection.Options.VaultPassword = nil
		for _, target := range cfg.Targets {
			selection.ServerIDs = append(selection.ServerIDs, target.ServerID)
		}
		id, err := audit.NewID()
		if err != nil {
			return err
		}
		sealed, digest, err := inside.seal("preset", id, server, selection)
		if err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&Preset{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrInput
		}
		row = Preset{ID: id, ServerID: server, Name: name, ConfigEnc: sealed, Digest: digest, CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.preset.create", id, "created", "", a.Session.ID)
	})
	return row, err
}

func (s *Service) preset(server, id string) (PresetSelection, error) {
	var data PresetSelection
	if !idPattern.MatchString(id) {
		return data, ErrInput
	}
	var row Preset
	if err := s.DB.First(&row, "id=? AND server_id=? AND archived=0", id, server).Error; err != nil {
		return data, err
	}
	if err := s.open("preset", id, server, row.ConfigEnc, row.Digest, &data); err != nil {
		return data, err
	}
	if data.Name != row.Name || len(data.ServerIDs) < 1 || len(data.ServerIDs) > 10 || data.Options.VaultPassword != nil || validateOptions(data.Options) != nil {
		return PresetSelection{}, ErrConflict
	}
	return data, nil
}

func (s *Service) PresetContent(a *auth.Access, server, id string) (PresetSelection, error) {
	if err := s.require(a, server, true, "ansible.projects.read", "secrets.reveal"); err != nil {
		return PresetSelection{}, err
	}
	data, err := s.preset(server, id)
	if err != nil {
		return PresetSelection{}, err
	}
	for _, target := range data.ServerIDs {
		if err := s.require(a, target, false, "servers.read"); err != nil {
			return PresetSelection{}, err
		}
	}
	if err := s.require(a, server, true, "ansible.projects.read", "secrets.reveal"); err != nil {
		return PresetSelection{}, err
	}
	return data, nil
}

func (s *Service) PreparePreset(a *auth.Access, server, id string, values map[string]any, password *VaultReference) (PlanView, error) {
	var view PlanView
	// Resolve and use inside one transaction so archiving cannot race creation.
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.read", "ansible.playbooks.execute", "secrets.use"); err != nil {
			return err
		}
		data, err := inside.preset(server, id)
		if err != nil {
			return err
		}
		data.Options.VaultPassword = password
		view, err = inside.prepare(a, server, data.ProjectID, PlanRequest{RevisionID: data.RevisionID, RevisionDigest: data.RevisionDigest, GroupID: data.GroupID, ServerIDs: data.ServerIDs, Options: data.Options, Variables: values}, id)
		return err
	})
	return view, err
}

func (s *Service) ArchivePreset(a *auth.Access, server, id string) error {
	if !idPattern.MatchString(id) {
		return ErrInput
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.manage"); err != nil {
			return err
		}
		result := tx.Model(&Preset{}).Where("id=? AND server_id=?", id, server).Update("archived", true)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.preset.archive", id, "archived", "", a.Session.ID)
	})
}
