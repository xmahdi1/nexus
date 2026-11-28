package ansible

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/githubactions"
)

type projectReader func(context.Context, *auth.Access, string, string, string, []string) (githubactions.ProjectSnapshot, error)

func (f projectReader) ReadProject(ctx context.Context, a *auth.Access, server, id, sha string, paths []string) (githubactions.ProjectSnapshot, error) {
	return f(ctx, a, server, id, sha, paths)
}
func TestReusableProjectTemplatesAreScopedPrivateAndDoNotCopyApproval(t *testing.T) {
	s, a, _, project, revision := fixture(t)
	bundle, err := s.Content(a, "controller", project.ID, revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	bundle.Collections = []CollectionLock{{Namespace: "fixture", Name: "example", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}}
	template, err := s.CreateTemplate(a, "controller", "Reusable check", bundle)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.Templates(a, "controller")
	if err != nil || len(list) != 1 {
		t.Fatal(err)
	}
	data, _ := json.Marshal(list)
	if strings.Contains(string(data), "main.yml") || strings.Contains(string(data), "bundleEnc") {
		t.Fatal("template list exposed content")
	}
	loaded, err := s.TemplateContent(a, "controller", template.ID)
	if err != nil || len(loaded.Collections) != 1 || loaded.Main != bundle.Main {
		t.Fatal("template lost definition", err)
	}
	if _, err := s.TemplateContent(a, "dev", template.ID); err == nil {
		t.Fatal("template moved across scope")
	}
	copy, err := s.CreateRevision(a, "controller", project.ID, loaded)
	if err != nil || copy.ID == revision.ID || copy.Digest == revision.Digest {
		t.Fatal("template reused immutable approval identity", err)
	}
	if err := s.ArchiveTemplate(a, "controller", template.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TemplateContent(a, "controller", template.ID); err == nil {
		t.Fatal("archived template still loading")
	}
	if _, err := s.Content(a, "controller", project.ID, copy.ID); err != nil {
		t.Fatal("archiving changed project revision", err)
	}
}
func TestRepositoryRevisionBindsVerifiedSourceAndRechecksAuthority(t *testing.T) {
	s, a, _, project, _ := fixture(t)
	grant := authorization.Grant{ID: "source-role", PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: "github-projects-reader", ScopeType: "server", ScopeID: "controller", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}
	if err := s.DB.Create(&grant).Error; err != nil {
		t.Fatal(err)
	}
	input := RepositoryImport{ConnectionID: strings.Repeat("a", 32), CommitSHA: strings.Repeat("b", 40), Main: "main.yml", Paths: []string{"main.yml"}, Variables: []Variable{}}
	revoke := false
	s.Repositories = projectReader(func(ctx context.Context, access *auth.Access, server, id, sha string, paths []string) (githubactions.ProjectSnapshot, error) {
		if server != "controller" || id != input.ConnectionID || sha != input.CommitSHA || len(paths) != 1 {
			t.Fatal("source selection changed")
		}
		if revoke {
			s.DB.Delete(&grant)
		}
		return githubactions.ProjectSnapshot{Repository: githubactions.Repository{Owner: "fixture", Name: "repo", ID: 123}, CommitSHA: sha, Files: map[string]string{"main.yml": "- hosts: all\n  gather_facts: false\n  tasks: []\n"}}, nil
	})
	row, err := s.ImportRevision(context.Background(), a, "controller", project.ID, input)
	if err != nil || row.SourceCommitSHA != input.CommitSHA || row.SourceConnectionID != input.ConnectionID || row.SourceRepositoryID != 123 {
		t.Fatal("source provenance lost", err)
	}
	if _, err := s.Content(a, "controller", project.ID, row.ID); err != nil {
		t.Fatal(err)
	}
	s.DB.Model(&Revision{}).Where("id=?", row.ID).Update("source_commit_sha", strings.Repeat("c", 40))
	if _, err := s.Content(a, "controller", project.ID, row.ID); !errors.Is(err, ErrConflict) {
		t.Fatal("source metadata escaped approval binding", err)
	}
	revoke = true
	if _, err := s.ImportRevision(context.Background(), a, "controller", project.ID, input); !errors.Is(err, ErrDenied) {
		t.Fatal("late source read saved after revoked authority", err)
	}
}
func TestCollectionLocksRejectAmbiguousOrUnboundedSources(t *testing.T) {
	bundle := Bundle{Main: "main.yml", Files: map[string]string{"main.yml": "- hosts: all\n  tasks: []"}, Collections: []CollectionLock{{Namespace: "fixture", Name: "example", Version: "1.0.0", SHA256: strings.Repeat("a", 64)}}}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []CollectionLock{
		{Namespace: "../bad", Name: "example", Version: "1.0.0", SHA256: strings.Repeat("a", 64)},
		{Namespace: "fixture", Name: "example", Version: "latest", SHA256: strings.Repeat("a", 64)},
		{Namespace: "fixture", Name: "example", Version: "1.0.0", SHA256: "missing"},
		{Namespace: "ansible", Name: "builtin", Version: "1.0.0", SHA256: strings.Repeat("a", 64)},
	} {
		copy := bundle
		copy.Collections = []CollectionLock{bad}
		if ValidateBundle(copy) == nil {
			t.Fatal("invalid collection lock admitted", bad.Namespace)
		}
	}
	bundle.Files["collections/ansible_collections/fixture/example/plugins/action/override.py"] = "not permitted beside managed locks"
	if ValidateBundle(bundle) == nil {
		t.Fatal("vendored path can shadow a locked collection")
	}
}
