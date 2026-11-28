package api

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestCustomTemplateCatalogRedactsAndManagementReadIsAudited(t *testing.T) {
	database, router, cookie, actor := rbacFixture(t, "admin", "global", "")
	body := `{"name":"Fixture","compose":"services: {} # private-source-fixture","postDeploy":"private-post-fixture","vars":[{"name":"PASSWORD","type":"password","required":true,"default":"private-default-fixture"}]}`
	created := policyRequest(router, cookie, "POST", "/api/templates/custom", body)
	if created.Code != 201 || strings.Contains(created.Body.String(), "private-") {
		t.Fatal("create exposed definition", created.Code)
	}
	var template models.CustomTemplate
	if err := json.Unmarshal(created.Body.Bytes(), &template); err != nil || template.ID == "" {
		t.Fatal(err)
	}
	if err := database.First(&template, "id=?", template.ID).Error; err != nil {
		t.Fatal(err)
	}
	secret, err := nexuscrypto.DecryptTemplateDefinition(bytes.Repeat([]byte{9}, 32), template.ID, template.DefinitionEnc)
	if err != nil || !strings.Contains(secret.Compose, "private-source") {
		t.Fatal("template not encrypted", err)
	}
	if response := policyRequest(router, cookie, "GET", "/api/templates/custom/"+template.ID, ""); response.Code != 403 {
		t.Fatal("source read lacked execution-side scope", response.Code)
	}
	if err := database.Create(&authorization.Grant{ID: "template-host-control", PrincipalID: actor, PrincipalKind: "user", RoleID: "host-control", ScopeType: "global", CreatedBy: actor, CreatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	catalog := policyRequest(router, cookie, "GET", "/api/templates", "")
	if catalog.Code != 200 || strings.Contains(catalog.Body.String(), "private-") || !strings.Contains(catalog.Body.String(), `"storedDefault":true`) {
		t.Fatal("catalog leaked defaults/source", catalog.Code)
	}
	details := policyRequest(router, cookie, "GET", "/api/templates/custom/"+template.ID, "")
	if details.Code != 200 || !strings.Contains(details.Body.String(), "private-default-fixture") {
		t.Fatal("authorized source unavailable", details.Code)
	}
	var count int64
	database.Table("operation_events").Where("action='GET /api/templates/custom/{id}' AND outcome='response_succeeded'").Count(&count)
	if count != 1 {
		t.Fatal("source read was not audited")
	}
	var metadata []map[string]any
	database.Table("operation_events").Find(&metadata)
	encoded, _ := json.Marshal(metadata)
	if strings.Contains(string(encoded), "private-") {
		t.Fatal("audit leaked definition")
	}
}
