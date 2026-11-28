package ansible

import (
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
	"strings"
	"time"
)

type Service struct {
	DB           *gorm.DB
	Key          []byte
	Sessions     *auth.Service
	Enabled      bool
	VaultEnabled bool
	Repositories RepositoryReader
}

func (s *Service) require(a *auth.Access, server string, high bool, permissions ...string) error {
	if !s.Enabled {
		return ErrDisabled
	}
	if a == nil || !a.AuthorizedNow() || !authorization.New(s.DB).All(a.User.ID, server, permissions...) {
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
func (s *Service) project(server, id string) (Project, error) {
	var p Project
	if !idPattern.MatchString(id) {
		return p, ErrInput
	}
	err := s.DB.First(&p, "id=? AND server_id=?", id, server).Error
	return p, err
}
func (s *Service) Projects(a *auth.Access, server string) ([]Project, error) {
	if err := s.require(a, server, false, "ansible.projects.read"); err != nil {
		return nil, err
	}
	rows := []Project{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	if err == nil {
		err = s.require(a, server, false, "ansible.projects.read")
	}
	return rows, err
}
func (s *Service) CreateProject(a *auth.Access, server, name string) (Project, error) {
	var row Project
	name = strings.TrimSpace(name)
	if name == "" || !safeText(name, 80) || strings.Contains(name, "\n") {
		return row, ErrInput
	}
	if err := s.require(a, server, true, "ansible.projects.manage"); err != nil {
		return row, err
	}
	id, err := audit.NewID()
	if err != nil {
		return row, err
	}
	row = Project{ID: id, ServerID: server, Name: name, CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&Project{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrInput
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.project.create", id, "created", "", a.Session.ID)
	})
	return row, err
}
func (s *Service) Archive(a *auth.Access, server, id string) error {
	if err := s.require(a, server, true, "ansible.projects.manage"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		var p Project
		if err := tx.First(&p, "id=? AND server_id=?", id, server).Error; err != nil {
			return err
		}
		if err := tx.Model(&p).Update("archived", true).Error; err != nil {
			return err
		}
		if err := tx.Model(&Plan{}).Where("project_id=? AND server_id=?", id, server).Update("state", "cancelled").Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.project.archive", id, "archived", "", a.Session.ID)
	})
}

type revisionData struct {
	ProjectID string          `json:"projectId"`
	Bundle    Bundle          `json:"bundle"`
	Source    *RevisionSource `json:"source,omitempty"`
}

func (s *Service) Revisions(a *auth.Access, server, project string) ([]Revision, error) {
	if err := s.require(a, server, false, "ansible.projects.read"); err != nil {
		return nil, err
	}
	if _, err := s.project(server, project); err != nil {
		return nil, err
	}
	rows := []Revision{}
	err := s.DB.Where("server_id=? AND project_id=?", server, project).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	return rows, err
}
func (s *Service) CreateRevision(a *auth.Access, server, project string, bundle Bundle) (Revision, error) {
	return s.createRevision(a, server, project, bundle, nil)
}
func (s *Service) createRevision(a *auth.Access, server, project string, bundle Bundle, source *RevisionSource) (Revision, error) {
	var row Revision
	if err := ValidateBundle(bundle); err != nil {
		return row, err
	}
	if err := s.require(a, server, true, "ansible.projects.manage", "secrets.create"); err != nil {
		return row, err
	}
	p, err := s.project(server, project)
	if err != nil {
		return row, err
	}
	if p.Archived {
		return row, ErrConflict
	}
	id, err := audit.NewID()
	if err != nil {
		return row, err
	}
	sealed, digest, err := s.seal("revision", id, server, revisionData{ProjectID: project, Bundle: bundle, Source: source})
	if err != nil {
		return row, err
	}
	row = Revision{ID: id, ProjectID: project, ServerID: server, Digest: digest, BundleEnc: sealed, CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	if source != nil {
		row.SourceConnectionID = source.ConnectionID
		row.SourceRepositoryID = source.RepositoryID
		row.SourceCommitSHA = source.CommitSHA
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.manage", "secrets.create"); err != nil {
			return err
		}
		if source != nil {
			if err := inside.require(a, server, true, "github.projects.read", "secrets.use"); err != nil {
				return err
			}
		}
		var current Project
		if err := tx.First(&current, "id=? AND server_id=? AND archived=0", project, server).Error; err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&Revision{}).Where("project_id=?", project).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrInput
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.revision.create", id, "created", "", a.Session.ID)
	})
	return row, err
}
func (s *Service) revision(server, project, id string) (Revision, Bundle, error) {
	var row Revision
	var data revisionData
	if !idPattern.MatchString(id) {
		return row, Bundle{}, ErrInput
	}
	if err := s.DB.First(&row, "id=? AND server_id=? AND project_id=?", id, server, project).Error; err != nil {
		return row, Bundle{}, err
	}
	if err := s.open("revision", id, server, row.BundleEnc, row.Digest, &data); err != nil {
		return row, Bundle{}, err
	}
	if !validRevisionSource(row, data.Source) || data.ProjectID != project || ValidateBundle(data.Bundle) != nil {
		return row, Bundle{}, ErrConflict
	}
	return row, data.Bundle, nil
}
func (s *Service) Content(a *auth.Access, server, project, id string) (Bundle, error) {
	if err := s.require(a, server, true, "ansible.projects.read", "secrets.reveal"); err != nil {
		return Bundle{}, err
	}
	_, bundle, err := s.revision(server, project, id)
	if err == nil {
		err = s.require(a, server, true, "ansible.projects.read", "secrets.reveal")
	}
	return bundle, err
}
