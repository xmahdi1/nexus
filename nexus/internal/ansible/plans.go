package ansible

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/automation"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/vault"
	"gorm.io/gorm"
)

func target(server models.Server) (frozenTarget, error) {
	var result frozenTarget
	if !automation.ValidConnection(server.Host, server.Username, server.Port) || !pinPattern.MatchString(server.KnownHostKey) || server.PrivateKeyEnc == "" {
		return result, ErrInput
	}
	data := server.ID + "\x00" + server.Host + "\x00" + strconv.Itoa(server.Port) + "\x00" + server.Username + "\x00" + server.KnownHostKey + "\x00" + server.PrivateKeyEnc
	hash := sha256.Sum256([]byte(data))
	return frozenTarget{Target: Target{server.ID, server.Host, server.Username, server.Port}, Fingerprint: hex.EncodeToString(hash[:])}, nil
}
func (s *Service) sourceAllowed(a *auth.Access, cfg frozenConfig) error {
	if cfg.ActorID != a.User.ID || cfg.SessionID != a.Session.ID {
		return ErrDenied
	}
	if err := s.require(a, cfg.Controller.ServerID, true, "ansible.projects.read", "ansible.playbooks.execute", "ansible.environment.read", "servers.connect", "secrets.use"); err != nil {
		return err
	}
	p, err := s.project(cfg.Controller.ServerID, cfg.ProjectID)
	if err != nil || p.Archived {
		return ErrDenied
	}
	current := append([]frozenTarget{cfg.Controller}, cfg.Targets...)
	for i, wanted := range current {
		if i > 0 {
			if err := s.require(a, wanted.ServerID, true, "servers.read", "servers.connect", "secrets.use", "ansible.playbooks.execute", "ansible.inventory.read"); err != nil {
				return err
			}
			var n int64
			if s.DB.Table("server_group_members m").Joins("JOIN server_groups g ON g.id=m.group_id").Where("m.server_id=? AND m.group_id=?", wanted.ServerID, cfg.GroupID).Count(&n).Error != nil || n != 1 {
				return ErrDenied
			}
		}
		var server models.Server
		if s.DB.First(&server, "id=?", wanted.ServerID).Error != nil {
			return ErrDenied
		}
		frozen, err := target(server)
		if err != nil || frozen.Fingerprint != wanted.Fingerprint {
			return ErrConflict
		}
	}
	return s.checkVaultBindings(a, cfg)
}
func references(values map[string]any, options Options) ([]VaultReference, error) {
	refs := []VaultReference{}
	for _, value := range values {
		switch value.(type) {
		case map[string]any, VaultReference:
			ref, err := validateReference(value)
			if err != nil {
				return nil, err
			}
			refs = append(refs, ref)
		}
	}
	if options.VaultPassword != nil {
		refs = append(refs, *options.VaultPassword)
	}
	return refs, nil
}
func (s *Service) vaultBindings(a *auth.Access, values map[string]any, options Options) (map[string]string, error) {
	refs, err := references(values, options)
	if err != nil {
		return nil, err
	}
	bindings := map[string]string{}
	for _, ref := range refs {
		if !s.VaultEnabled {
			return nil, ErrDisabled
		}
		if err := s.require(a, ref.ServerID, true, "servers.connect", "secrets.use", "integrations.manage"); err != nil {
			return nil, err
		}
		var profile vault.Profile
		var server models.Server
		if s.DB.First(&profile, "server_id=?", ref.ServerID).Error != nil || profile.Validate() != nil || profile.Namespace != "" || s.DB.First(&server, "id=?", ref.ServerID).Error != nil {
			return nil, ErrInput
		}
		binding, err := vaultBinding(profile, server)
		if err != nil {
			return nil, err
		}
		bindings[ref.ServerID] = binding
	}
	return bindings, nil
}

func vaultBinding(profile vault.Profile, server models.Server) (string, error) {
	if profile.Validate() != nil || profile.Namespace != "" || profile.ServerID != server.ID {
		return "", ErrInput
	}
	frozen, err := target(server)
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(struct {
		Profile     vault.Profile
		Fingerprint string
	}{profile, frozen.Fingerprint})
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
func (s *Service) checkVaultBindings(a *auth.Access, cfg frozenConfig) error {
	actual, err := s.vaultBindings(a, cfg.Variables, cfg.Options)
	if err != nil {
		return err
	}
	if len(actual) != len(cfg.VaultBindings) {
		return ErrConflict
	}
	for id, value := range actual {
		if cfg.VaultBindings[id] != value {
			return ErrConflict
		}
	}
	return nil
}
func (s *Service) Prepare(a *auth.Access, server, project string, input PlanRequest) (PlanView, error) {
	return s.prepare(a, server, project, input, "")
}

func (s *Service) prepare(a *auth.Access, server, project string, input PlanRequest, presetID string) (PlanView, error) {
	var view PlanView
	if err := s.require(a, server, true, "ansible.projects.read", "ansible.playbooks.execute"); err != nil {
		return view, err
	}
	if len(input.ServerIDs) < 1 || len(input.ServerIDs) > 10 || !idPattern.MatchString(input.GroupID) || validateOptions(input.Options) != nil {
		return view, ErrInput
	}
	revision, bundle, err := s.revision(server, project, input.RevisionID)
	if err != nil {
		return view, err
	}
	if revision.Digest != input.RevisionDigest {
		return view, ErrConflict
	}
	values, err := Variables(bundle, input.Variables)
	if err != nil {
		return view, err
	}
	preview, err := (&automation.InventoryService{DB: s.DB, Sessions: s.Sessions}).Build(a, input.GroupID)
	if err != nil {
		return view, ErrDenied
	}
	meta, ok := preview.Inventory["_meta"].(automation.Meta)
	if !ok {
		return view, ErrInput
	}
	var controller models.Server
	if s.DB.First(&controller, "id=?", server).Error != nil || controller.Username != "root" {
		return view, ErrInput
	}
	frozenController, err := target(controller)
	if err != nil {
		return view, err
	}
	cfg := frozenConfig{PresetID: presetID, ActorID: a.User.ID, SessionID: a.Session.ID, ProjectID: project, RevisionID: revision.ID, RevisionDigest: revision.Digest, Controller: frozenController, GroupID: input.GroupID, Variables: values, Options: input.Options, Targets: []frozenTarget{}}
	seen := map[string]bool{}
	pins := map[string]bool{controller.KnownHostKey: true}
	ids := append([]string{}, input.ServerIDs...)
	sort.Strings(ids)
	for _, id := range ids {
		if !idPattern.MatchString(id) || seen[id] || id == server {
			return view, ErrInput
		}
		seen[id] = true
		if _, ok := meta.Hostvars[automation.Alias("host", id)]; !ok {
			return view, ErrDenied
		}
		var record models.Server
		if s.DB.First(&record, "id=?", id).Error != nil {
			return view, ErrDenied
		}
		if pins[record.KnownHostKey] {
			return view, ErrInput
		}
		pins[record.KnownHostKey] = true
		frozen, err := target(record)
		if err != nil {
			return view, err
		}
		cfg.Targets = append(cfg.Targets, frozen)
	}
	cfg.VaultBindings, err = s.vaultBindings(a, cfg.Variables, cfg.Options)
	if err != nil {
		return view, err
	}
	if err := s.sourceAllowed(a, cfg); err != nil {
		return view, err
	}
	id, err := audit.NewID()
	if err != nil {
		return view, err
	}
	sealed, digest, err := s.seal("plan", id, server, cfg)
	if err != nil {
		return view, err
	}
	now := time.Now().UTC()
	row := Plan{PresetID: presetID, ID: id, ProjectID: project, RevisionID: revision.ID, ServerID: server, ActorID: a.User.ID, SourceSessionID: a.Session.ID, Digest: digest, ConfigEnc: sealed, State: "prepared", CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute)}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.sourceAllowed(a, cfg); err != nil {
			return err
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.plan.prepare", id, "prepared", "", a.Session.ID)
	})
	if err != nil {
		return view, err
	}
	return planView(row, cfg, false), nil
}
func (s *Service) config(row Plan) (frozenConfig, error) {
	var cfg frozenConfig
	if err := s.open("plan", row.ID, row.ServerID, row.ConfigEnc, row.Digest, &cfg); err != nil {
		return cfg, err
	}
	if cfg.PresetID != row.PresetID || cfg.ActorID != row.ActorID || cfg.SessionID != row.SourceSessionID || cfg.Controller.ServerID != row.ServerID || cfg.ProjectID != row.ProjectID || cfg.RevisionID != row.RevisionID || len(cfg.Targets) < 1 || len(cfg.Targets) > 10 {
		return frozenConfig{}, ErrConflict
	}
	return cfg, nil
}
func planView(row Plan, cfg frozenConfig, reveal bool) PlanView {
	view := PlanView{Plan: row, GroupID: cfg.GroupID, RevisionDigest: cfg.RevisionDigest, Options: cfg.Options, Targets: []Target{}, VariableNames: []string{}}
	for _, t := range cfg.Targets {
		view.Targets = append(view.Targets, t.Target)
	}
	for name := range cfg.Variables {
		view.VariableNames = append(view.VariableNames, name)
	}
	sort.Strings(view.VariableNames)
	if reveal {
		view.Variables = cfg.Variables
	}
	return view
}
func (s *Service) Plan(a *auth.Access, server, id string, reveal bool) (PlanView, error) {
	if err := s.require(a, server, reveal, "ansible.projects.read"); err != nil {
		return PlanView{}, err
	}
	if reveal {
		if err := s.require(a, server, true, "secrets.reveal"); err != nil {
			return PlanView{}, err
		}
	}
	var row Plan
	if err := s.DB.First(&row, "id=? AND server_id=?", id, server).Error; err != nil {
		return PlanView{}, err
	}
	cfg, err := s.config(row)
	if err != nil {
		return PlanView{}, err
	}
	for _, target := range cfg.Targets {
		if err := s.require(a, target.ServerID, false, "servers.read"); err != nil {
			return PlanView{}, err
		}
	}
	if !a.AuthorizedNow() {
		return PlanView{}, ErrDenied
	}
	return planView(row, cfg, reveal), nil
}
func (s *Service) Plans(a *auth.Access, server string) ([]Plan, error) {
	if err := s.require(a, server, false, "ansible.projects.read"); err != nil {
		return nil, err
	}
	rows := []Plan{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}
func (s *Service) Approve(a *auth.Access, server, id, planDigest, revisionDigest string) (PlanView, error) {
	if err := s.require(a, server, true, "ansible.projects.read", "ansible.playbooks.approve", "secrets.reveal"); err != nil {
		return PlanView{}, err
	}
	var row Plan
	var cfg frozenConfig
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&row, "id=? AND server_id=?", id, server).Error; err != nil {
			return err
		}
		if row.State != "prepared" || row.ActorID == a.User.ID || !row.ExpiresAt.After(time.Now().UTC()) || row.Digest != planDigest {
			return ErrConflict
		}
		inside := *s
		inside.DB = tx
		var err error
		cfg, err = inside.config(row)
		if err != nil {
			return err
		}
		if cfg.RevisionDigest != revisionDigest {
			return ErrConflict
		}
		rev, _, err := inside.revision(server, row.ProjectID, row.RevisionID)
		if err != nil || rev.Digest != revisionDigest {
			return ErrConflict
		}
		source, err := s.Sessions.AccessForSession(row.SourceSessionID, row.ActorID)
		if err != nil {
			return ErrDenied
		}
		if err := inside.sourceAllowed(source, cfg); err != nil {
			return err
		}
		for _, target := range cfg.Targets {
			if err := inside.require(a, target.ServerID, true, "servers.read", "ansible.playbooks.approve"); err != nil {
				return err
			}
		}
		now := time.Now().UTC()
		row.State = "approved"
		row.ApprovedBy = a.User.ID
		row.ApproverSessionID = a.Session.ID
		row.ApprovedAt = &now
		if err := tx.Model(&row).Updates(map[string]any{"state": row.State, "approved_by": row.ApprovedBy, "approver_session_id": row.ApproverSessionID, "approved_at": now}).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.plan.approve", id, "approved", "", a.Session.ID)
	})
	if err != nil {
		return PlanView{}, err
	}
	return planView(row, cfg, false), nil
}
func (s *Service) CancelPlan(a *auth.Access, server, id string) error {
	if err := s.require(a, server, true, "ansible.projects.manage"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&Plan{}).Where("id=? AND server_id=?", id, server).Update("state", "cancelled")
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.plan.cancel", id, "cancelled", "", a.Session.ID)
	})
}

// Approval never grants execution by itself. Later execution admission must call
// this again, lock all frozen hosts, and bind a durable no-replay run identity.
func (s *Service) AuthorizedPlan(id string) (Plan, error) {
	var row Plan
	if !s.Enabled || s.Sessions == nil {
		return row, ErrDenied
	}
	if err := s.DB.First(&row, "id=? AND state='approved' AND expires_at>?", id, time.Now().UTC()).Error; err != nil {
		return row, ErrDenied
	}
	cfg, err := s.config(row)
	if err != nil {
		return row, err
	}
	source, err := s.Sessions.AccessForSession(row.SourceSessionID, row.ActorID)
	if err != nil {
		return row, ErrDenied
	}
	if err := s.sourceAllowed(source, cfg); err != nil {
		return row, err
	}
	approver, err := s.Sessions.AccessForSession(row.ApproverSessionID, row.ApprovedBy)
	if err != nil || row.ApprovedBy == row.ActorID || row.ApprovedAt == nil {
		return row, ErrDenied
	}
	if err := s.require(approver, row.ServerID, true, "ansible.projects.read", "ansible.playbooks.approve", "secrets.reveal"); err != nil {
		return row, err
	}
	for _, target := range cfg.Targets {
		if err := s.require(approver, target.ServerID, true, "servers.read", "ansible.playbooks.approve"); err != nil {
			return row, err
		}
	}
	revision, _, err := s.revision(row.ServerID, row.ProjectID, row.RevisionID)
	if err == nil && revision.Digest != cfg.RevisionDigest {
		return row, ErrConflict
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return row, ErrDenied
	}
	return row, err
}
