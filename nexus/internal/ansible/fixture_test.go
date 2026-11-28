package ansible

import (
	"bytes"
	"encoding/base64"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
	"path/filepath"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Service, *auth.Access, *auth.Access, Project, Revision) {
	t.Helper()
	key := bytes.Repeat([]byte{8}, 32)
	database, err := db.Init(filepath.Join(t.TempDir(), "plans.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	t.Cleanup(func() { connection.Close() })
	password := "Ansible fixture password"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	cfg := &config.Config{EncryptionKey: key, PasswordHash: string(hash)}
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewService(database, cfg)
	login := func(username, password string) *auth.Access {
		t.Helper()
		result, err := sessions.Login(username, password, "fixture", "")
		if err != nil {
			t.Fatal(err)
		}
		access, err := sessions.Authenticate(result.Token)
		if err != nil {
			t.Fatal(err)
		}
		return access
	}
	owner := login("owner", password)
	invite, err := sessions.CreateInvitation(owner, auth.InviteOptions{Username: "approver", RoleID: "viewer", ScopeType: "global"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.AcceptInvitation(invite.Token, password); err != nil {
		t.Fatal(err)
	}
	approver := login("approver", password)
	for i, id := range []string{"controller", "dev", "prod"} {
		cipher, err := nexuscrypto.Encrypt(key, []byte("fixture-private-key-"+id))
		if err != nil {
			t.Fatal(err)
		}
		username := "fixture"
		if id == "controller" {
			username = "root"
		}
		pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 32))
		if err := database.Create(&models.Server{ID: id, Name: id, Host: "192.0.2." + string(rune('1'+i)), Port: 22, Username: username, KnownHostKey: pin, PrivateKeyEnc: cipher}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Exec("INSERT INTO server_groups(id,name,created_at) VALUES('managed','Managed targets',CURRENT_TIMESTAMP);INSERT INTO server_group_members(group_id,server_id) VALUES('managed','dev'),('managed','prod')").Error; err != nil {
		t.Fatal(err)
	}
	grant := func(principal, role, scope, id string) {
		t.Helper()
		gid, err := audit.NewID()
		if err != nil {
			t.Fatal(err)
		}
		if err := database.Create(&authorization.Grant{ID: gid, PrincipalID: principal, PrincipalKind: "user", RoleID: role, ScopeType: scope, ScopeID: id, CreatedBy: owner.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{"ansible-projects", "ansible-executor", "ansible-inventory", "ansible-environment", "ansible-approver", "secret-reader"} {
		grant(owner.User.ID, role, "global", "")
	}
	grant(approver.User.ID, "ansible-approver", "server", "controller")
	grant(approver.User.ID, "ansible-approver", "server_group", "managed")
	grant(approver.User.ID, "secret-reader", "server", "controller")
	service := &Service{DB: database, Key: key, Sessions: sessions, Enabled: true}
	project, err := service.CreateProject(owner, "controller", "Managed playbooks")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := service.CreateRevision(owner, "controller", project.ID, Bundle{Main: "main.yml", Files: map[string]string{"main.yml": "---\n- hosts: all\n  gather_facts: false\n  tasks: []\n# fixture-private-playbook"}, Variables: []Variable{{Name: "message", Kind: "string", Required: true}}})
	if err != nil {
		t.Fatal(err)
	}
	return service, owner, approver, project, revision
}
