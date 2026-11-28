package db

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
)

func TestAutomationRecoveryRewrapsNewFieldsAndRevokesWebhookIntake(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	root := t.TempDir()
	source := filepath.Join(root, "source.db")
	database, err := Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("private-automation-fixture")
	for _, item := range []struct{ kind, id, statement string }{
		{"webhook", "hook", "INSERT INTO github_webhooks(id,server_id,connection_id,endpoint_id,secret_enc,created_by,created_at)VALUES('hook','build','repository','endpoint',?,'owner',CURRENT_TIMESTAMP)"},
		{"organization", "organization", "INSERT INTO github_organizations(id,server_id,login,organization_id,client_id,installation_id,config_enc,created_by,created_at)VALUES('organization','build','fixture',42,'app',1,?,'owner',CURRENT_TIMESTAMP)"},
		{"organization-change", "change", "INSERT INTO github_organization_changes(id,server_id,connection_id,actor_id,source_session_id,kind,input_enc,state,created_at)VALUES('change','build','organization','owner','old-session','registration',?,'unknown',CURRENT_TIMESTAMP)"},
	} {
		sealed, err := nexuscrypto.EncryptGitHubPayload(key, item.kind, item.id, "build", plain)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.Exec(item.statement, sealed).Error; err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := nexuscrypto.EncryptAnsiblePayload(key, "template", "template", "build", plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO ansible_templates(id,server_id,name,bundle_enc,digest,created_by,created_at)VALUES('template','build','Fixture',?,'digest','owner',CURRENT_TIMESTAMP)", sealed).Error; err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	connection.Close()
	destination := filepath.Join(root, "rotated")
	if err := RotateRecoverySet(source, destination, key); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(destination, "encryption-key.base64"))
	if err != nil {
		t.Fatal(err)
	}
	next, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := Init(filepath.Join(destination, "nexus.db"), next)
	if err != nil {
		t.Fatal(err)
	}
	rotatedSQL, _ := rotated.DB()
	defer rotatedSQL.Close()
	var disabled bool
	rotated.Raw("SELECT disabled FROM github_webhooks WHERE id='hook'").Scan(&disabled)
	if !disabled {
		t.Fatal("recovery copy accepts original webhook authority")
	}
	for _, field := range secretFields {
		if field.kind != "github-webhook" && field.kind != "github-organization" && field.kind != "github-organization-change" && field.kind != "ansible-template" {
			continue
		}
		err := walkSecretField(rotated, field, func(id, scope, value string) error { return validateSecret(field, next, id, scope, value) })
		if err != nil {
			t.Fatal("new automation field lost during rotation", field.kind, err)
		}
	}
	original, err := Init(source, key)
	if err != nil {
		t.Fatal(err)
	}
	originalSQL, _ := original.DB()
	defer originalSQL.Close()
	original.Raw("SELECT disabled FROM github_webhooks WHERE id='hook'").Scan(&disabled)
	if disabled {
		t.Fatal("rotation modified original hook")
	}
}
