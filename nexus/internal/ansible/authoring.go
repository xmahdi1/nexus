package ansible

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/githubactions"
	"gorm.io/gorm"
)

type RepositoryReader interface {
	ReadProject(context.Context, *auth.Access, string, string, string, []string) (githubactions.ProjectSnapshot, error)
}
type RevisionSource struct {
	ConnectionID string `json:"connectionId"`
	RepositoryID int64  `json:"repositoryId"`
	CommitSHA    string `json:"commitSha"`
}

func validRevisionSource(row Revision, source *RevisionSource) bool {
	if source == nil {
		return row.SourceConnectionID == "" && row.SourceRepositoryID == 0 && row.SourceCommitSHA == ""
	}
	return source.ConnectionID == row.SourceConnectionID && source.RepositoryID == row.SourceRepositoryID && source.CommitSHA == row.SourceCommitSHA
}

type RepositoryImport struct {
	ConnectionID string           `json:"connectionId"`
	CommitSHA    string           `json:"commitSha"`
	Main         string           `json:"main"`
	Paths        []string         `json:"paths"`
	Variables    []Variable       `json:"variables"`
	Collections  []CollectionLock `json:"collections,omitempty"`
}

func (s *Service) ImportRevision(ctx context.Context, a *auth.Access, server, project string, input RepositoryImport) (Revision, error) {
	if err := s.require(a, server, true, "ansible.projects.manage", "github.projects.read", "secrets.create", "secrets.use"); err != nil {
		return Revision{}, err
	}
	if s.Repositories == nil || !githubactions.ValidCommitSHA(input.CommitSHA) || !githubactions.ValidRequestID(input.ConnectionID) || len(input.Paths) < 1 || len(input.Paths) > 32 {
		return Revision{}, ErrInput
	}
	p, err := s.project(server, project)
	if err != nil {
		return Revision{}, err
	}
	if p.Archived {
		return Revision{}, ErrConflict
	}
	selected := map[string]bool{}
	for _, name := range input.Paths {
		if !githubactions.ValidProjectPath(name) || selected[name] {
			return Revision{}, ErrInput
		}
		selected[name] = true
	}
	snapshot, err := s.Repositories.ReadProject(ctx, a, server, input.ConnectionID, input.CommitSHA, input.Paths)
	if err != nil {
		switch {
		case errors.Is(err, githubactions.ErrDenied):
			return Revision{}, ErrDenied
		case errors.Is(err, githubactions.ErrInput):
			return Revision{}, ErrInput
		case errors.Is(err, githubactions.ErrConflict):
			return Revision{}, ErrConflict
		}
		return Revision{}, err
	}
	if ctx.Err() != nil {
		return Revision{}, ErrDenied
	}
	if snapshot.CommitSHA != input.CommitSHA || snapshot.Repository.Validate() != nil || len(snapshot.Files) != len(selected) {
		return Revision{}, ErrConflict
	}
	for name := range snapshot.Files {
		if !selected[name] {
			return Revision{}, ErrConflict
		}
	}
	bundle := Bundle{Main: input.Main, Files: snapshot.Files, Variables: input.Variables, Collections: input.Collections}
	return s.createRevision(a, server, project, bundle, &RevisionSource{ConnectionID: input.ConnectionID, RepositoryID: snapshot.Repository.ID, CommitSHA: snapshot.CommitSHA})
}

type ProjectTemplate struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	ServerID  string    `json:"serverId"`
	Name      string    `json:"name"`
	BundleEnc string    `json:"-"`
	Digest    string    `json:"digest"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	Archived  bool      `json:"archived"`
}

func (ProjectTemplate) TableName() string { return "ansible_templates" }

type templateData struct {
	Name   string `json:"name"`
	Bundle Bundle `json:"bundle"`
}

func (s *Service) Templates(a *auth.Access, server string) ([]ProjectTemplate, error) {
	if err := s.require(a, server, false, "ansible.projects.read"); err != nil {
		return nil, err
	}
	rows := []ProjectTemplate{}
	err := s.DB.Where("server_id=?", server).Order("created_at DESC,id DESC").Limit(100).Find(&rows).Error
	return rows, err
}
func (s *Service) CreateTemplate(a *auth.Access, server, name string, bundle Bundle) (ProjectTemplate, error) {
	if !safeText(name, 100) || strings.TrimSpace(name) == "" || strings.Contains(name, "\n") || ValidateBundle(bundle) != nil {
		return ProjectTemplate{}, ErrInput
	}
	if err := s.require(a, server, true, "ansible.projects.manage", "secrets.create"); err != nil {
		return ProjectTemplate{}, err
	}
	id, err := audit.NewID()
	if err != nil {
		return ProjectTemplate{}, err
	}
	sealed, digest, err := s.seal("template", id, server, templateData{name, bundle})
	if err != nil {
		return ProjectTemplate{}, err
	}
	row := ProjectTemplate{ID: id, ServerID: server, Name: name, BundleEnc: sealed, Digest: digest, CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.manage", "secrets.create"); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&ProjectTemplate{}).Where("server_id=?", server).Count(&count).Error; err != nil {
			return err
		}
		if count >= 100 {
			return ErrInput
		}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.template.create", id, "created", "", a.Session.ID)
	})
	return row, err
}
func (s *Service) TemplateContent(a *auth.Access, server, id string) (Bundle, error) {
	if err := s.require(a, server, true, "ansible.projects.read", "secrets.reveal"); err != nil {
		return Bundle{}, err
	}
	if !idPattern.MatchString(id) {
		return Bundle{}, ErrInput
	}
	var row ProjectTemplate
	if err := s.DB.First(&row, "id=? AND server_id=? AND archived=0", id, server).Error; err != nil {
		return Bundle{}, err
	}
	var data templateData
	if err := s.open("template", id, server, row.BundleEnc, row.Digest, &data); err != nil {
		return Bundle{}, err
	}
	if data.Name != row.Name || ValidateBundle(data.Bundle) != nil {
		return Bundle{}, ErrConflict
	}
	if err := s.require(a, server, true, "ansible.projects.read", "secrets.reveal"); err != nil {
		return Bundle{}, err
	}
	return data.Bundle, nil
}
func (s *Service) ArchiveTemplate(a *auth.Access, server, id string) error {
	if !idPattern.MatchString(id) {
		return ErrInput
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "ansible.projects.manage"); err != nil {
			return err
		}
		result := tx.Model(&ProjectTemplate{}).Where("id=? AND server_id=?", id, server).Update("archived", true)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return authorization.New(tx).Record(a.User.ID, "ansible.template.archive", id, "archived", "", a.Session.ID)
	})
}
