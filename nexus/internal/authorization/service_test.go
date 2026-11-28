package authorization_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	policy "github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

func fixture(t *testing.T) *gorm.DB {
	t.Helper()
	database, err := db.Init(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	t.Cleanup(func() { c.Close() })
	for _, id := range []string{"dev", "prod"} {
		if err := database.Create(&models.Server{ID: id, Name: id, Host: "192.0.2.10", Username: "fixture"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	return database
}
func user(t *testing.T, db *gorm.DB, id string) {
	t.Helper()
	if err := db.Create(&models.User{ID: id, Username: id, DisplayName: id, Status: "active", PasswordHash: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO account_admissions(user_id,source,admitted_at) VALUES(?,'invitation',?)", id, time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO auth_credentials(user_id,version) VALUES(?,1)", id).Error; err != nil {
		t.Fatal(err)
	}
}
func grant(t *testing.T, db *gorm.DB, actor, role, scope, id string) {
	t.Helper()
	if err := db.Create(&policy.Grant{ID: actor + role + scope + id, PrincipalID: actor, PrincipalKind: "user", RoleID: role, ScopeType: scope, ScopeID: id, CreatedBy: "fixture", CreatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
}
func TestScopedRoleMatrixAndExplicitHostAccess(t *testing.T) {
	database := fixture(t)
	s := policy.New(database)
	for _, id := range []string{"viewer", "operator", "administrator"} {
		user(t, database, id)
	}
	group, err := s.CreateGroup(policy.LegacyPrincipal, "Development", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Membership(policy.LegacyPrincipal, group.ID, "dev", false, ""); err != nil {
		t.Fatal(err)
	}
	grant(t, database, "viewer", "viewer", "server", "dev")
	grant(t, database, "operator", "operator", "server_group", group.ID)
	grant(t, database, "administrator", "admin", "global", "")
	for _, tc := range []struct {
		actor, permission, server string
		allowed                   bool
	}{
		{"viewer", "servers.read", "dev", true}, {"viewer", "docker.manage", "dev", false}, {"viewer", "servers.read", "prod", false},
		{"operator", "docker.manage", "dev", true}, {"operator", "docker.manage", "prod", false}, {"operator", "servers.terminal", "dev", false},
		{"administrator", "servers.terminal", "dev", false}, {"administrator", "secrets.reveal", "dev", false}, {"administrator", "firewall.manage", "prod", true},
		{policy.LegacyPrincipal, "unknown.permission", "dev", false}, {policy.LegacyPrincipal, "servers.read", "missing", false},
	} {
		if actual := s.Check(tc.actor, tc.permission, tc.server); actual != tc.allowed {
			t.Errorf("%+v got %v", tc, actual)
		}
	}
	grant(t, database, "administrator", "host-control", "server", "dev")
	if !s.All("administrator", "dev", "servers.terminal", "servers.execute", "secrets.use") || s.Check("administrator", "servers.terminal", "prod") {
		t.Fatal("explicit host scope not enforced")
	}
	ids, err := s.VisibleIDs("operator", "servers.read")
	if err != nil || !reflect.DeepEqual(ids, []string{"dev"}) {
		t.Fatalf("unscoped list: %v %v", ids, err)
	}
	database.Model(&models.Server{}).Where("id='prod'").Update("tags", "Development")
	if s.Check("operator", "docker.manage", "prod") {
		t.Fatal("tags granted privileges")
	}
	grant(t, database, "operator", "viewer", "server", "prod")
	if !s.Check("operator", "servers.read", "prod") || s.Check("operator", "docker.manage", "prod") {
		t.Fatal("multiple grants escaped their scope")
	}
	database.Model(&models.User{}).Where("id='operator'").Update("status", "disabled")
	if s.Check("operator", "servers.read", "dev") {
		t.Fatal("disabled principal authorized")
	}
}
func TestGrantValidationLastAdminAndSessionInvalidation(t *testing.T) {
	database := fixture(t)
	s := policy.New(database)
	user(t, database, "target")
	for _, input := range []struct{ principal, role, scope, id string }{{"missing", "viewer", "server", "dev"}, {"target", "unknown", "server", "dev"}, {"target", "viewer", "server", "missing"}, {"target", "viewer", "global", "dev"}, {"target", "viewer", "typo", "dev"}, {policy.MonitorPrincipal, "host-control", "global", ""}} {
		if _, err := s.AddGrant(policy.LegacyPrincipal, input.principal, input.role, input.scope, input.id, ""); err == nil {
			t.Fatal("invalid grant accepted")
		}
	}
	if _, err := s.AddGrant("target", "target", "admin", "global", "", ""); !errors.Is(err, policy.ErrDenied) {
		t.Fatal("unprivileged actor assigned roles")
	}
	if err := database.Exec(`INSERT INTO auth_sessions(id,principal_id,token_hash,credential_epoch,created_at,last_used_at,expires_at,device_label,client_ip) VALUES('session','target','hash','1',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,datetime('now','+1 day'),'fixture','192.0.2.1')`).Error; err != nil {
		t.Fatal(err)
	}
	added, err := s.AddGrant(policy.LegacyPrincipal, "target", "viewer", "server", "dev", "")
	if err != nil {
		t.Fatal(err)
	}
	var revoked int64
	database.Table("auth_sessions").Where("id='session' AND revoked_at IS NOT NULL").Count(&revoked)
	if revoked != 1 {
		t.Fatal("policy change retained impacted session")
	}
	if !s.Check("target", "servers.read", "dev") {
		t.Fatal("valid grant not effective")
	}
	if err := s.DeleteGrant(policy.LegacyPrincipal, added.ID, ""); err != nil {
		t.Fatal(err)
	}
	if s.Check("target", "servers.read", "dev") {
		t.Fatal("removed grant still effective")
	}
	if err := s.DeleteGrant(policy.LegacyPrincipal, "compat-admin", ""); !errors.Is(err, policy.ErrLastAdmin) {
		t.Fatalf("last admin removed: %v", err)
	}
	if !s.Check(policy.LegacyPrincipal, "roles.manage", "") {
		t.Fatal("last-admin failure did not roll back")
	}
}
func TestMigrationRoleTemplatesAreVersionedAndMatchCatalog(t *testing.T) {
	database := fixture(t)
	for role, expected := range policy.RoleTemplates {
		actual := []string{}
		if err := database.Table("role_permissions").Where("role_id=?", role).Pluck("permission_key", &actual).Error; err != nil {
			t.Fatal(err)
		}
		sort.Strings(actual)
		copyExpected := append([]string{}, expected...)
		sort.Strings(copyExpected)
		if !reflect.DeepEqual(actual, copyExpected) {
			t.Fatalf("migration required for changed role %s", role)
		}
	}
	for _, p := range policy.Policies {
		if !p.Self {
			for _, permission := range p.Permissions {
				if !policy.Known(permission) {
					t.Fatalf("unknown registry permission %s", permission)
				}
			}
		}
	}
	if _, _, ok := policy.Resolve("POST", "/api/future/unsafe"); ok {
		t.Fatal("unregistered action authorized")
	}
}

func TestMissingGroupsAndRoleChangesFailClosed(t *testing.T) {
	database := fixture(t)
	s := policy.New(database)
	user(t, database, "scoped")
	grant(t, database, "scoped", "operator", "server_group", "missing-group")
	if s.Check("scoped", "docker.manage", "dev") {
		t.Fatal("missing group authorized")
	}
	group, err := s.CreateGroup(policy.LegacyPrincipal, "Temporary", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Membership(policy.LegacyPrincipal, group.ID, "dev", false, ""); err != nil {
		t.Fatal(err)
	}
	grant(t, database, "scoped", "operator", "server_group", group.ID)
	if !s.Check("scoped", "docker.manage", "dev") {
		t.Fatal("group grant not effective")
	}
	if err := s.Membership(policy.LegacyPrincipal, group.ID, "dev", true, ""); err != nil {
		t.Fatal(err)
	}
	if s.Check("scoped", "docker.manage", "dev") {
		t.Fatal("removed membership retained permission")
	}
	closed := make(chan struct{}, 1)
	stop := s.Watch(policy.MonitorPrincipal, "dev", func() { closed <- struct{}{} }, "metrics.read")
	defer stop()
	database.Exec("UPDATE service_principals SET status='disabled' WHERE id=?", policy.MonitorPrincipal)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("disabled collector stayed authorized")
	}
}

func TestGroupEditorCannotEscalateThroughMembership(t *testing.T) {
	database := fixture(t)
	s := policy.New(database)
	user(t, database, "group-editor")
	database.Exec("INSERT INTO roles(id,name) VALUES('group-editor','group-editor')")
	database.Exec("INSERT INTO role_permissions(role_id,permission_key) VALUES('group-editor','groups.manage')")
	grant(t, database, "group-editor", "group-editor", "global", "")
	group, err := s.CreateGroup("group-editor", "Empty group", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Membership("group-editor", group.ID, "prod", false, ""); !errors.Is(err, policy.ErrDenied) {
		t.Fatal("group editor expanded authorization without roles.manage")
	}
}

func TestEmptyAssignedGroupReturnsAnEmptyCollection(t *testing.T) {
	database := fixture(t)
	s := policy.New(database)
	user(t, database, "empty-viewer")
	group, err := s.CreateGroup(policy.LegacyPrincipal, "Empty", "")
	if err != nil {
		t.Fatal(err)
	}
	grant(t, database, "empty-viewer", "viewer", "server_group", group.ID)
	ids, err := s.VisibleIDs("empty-viewer", "servers.read")
	if err != nil || len(ids) != 0 || !s.Collection("empty-viewer", "servers.read") {
		t.Fatal("empty assigned group did not retain safe empty-list access")
	}
}
