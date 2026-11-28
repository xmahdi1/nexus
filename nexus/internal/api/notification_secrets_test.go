package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
)

func TestNotificationTokenWriteOnlyEncryptedAndScoped(t *testing.T) {
	database, _, cookie, actor := rbacFixture(t, "admin", "global", "")
	key := bytes.Repeat([]byte{9}, 32)
	router := NewRouter(database, &config.Config{EncryptionKey: key}, nil, nil)
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(random)
	body, _ := json.Marshal(map[string]any{"telegramToken": secret, "telegramEnabled": true, "telegramChatId": "fictional-chat"})
	response := policyRequest(router, cookie, "PUT", "/api/monitor/config", string(body))
	if response.Code != 200 || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "telegramTokenEnc") {
		t.Fatal("credential response", response.Code, response.Body.String())
	}
	var sealed string
	if err := database.Raw("SELECT telegram_token_enc FROM alert_configs WHERE id='default'").Scan(&sealed).Error; err != nil {
		t.Fatal(err)
	}
	plain, err := nexuscrypto.DecryptNotificationToken(key, "default", sealed)
	if err != nil || string(plain) != secret || sealed == secret {
		t.Fatal("plaintext or unreadable token", err)
	}
	read := policyRequest(router, cookie, "GET", "/api/monitor/config", "")
	if read.Code != 200 || strings.Contains(read.Body.String(), secret) || !strings.Contains(read.Body.String(), "Configured") {
		t.Fatal("read leaked token", read.Code)
	}
	// The legacy frontend round-trips the safe placeholder with other settings.
	response = policyRequest(router, cookie, "PUT", "/api/monitor/config", read.Body.String())
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var preserved string
	if err := database.Raw("SELECT telegram_token_enc FROM alert_configs WHERE id='default'").Scan(&preserved).Error; err != nil || preserved != sealed {
		t.Fatal("placeholder replaced credential", err)
	}
	var events []map[string]any
	if err := database.Table("operation_events").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), sealed) {
		t.Fatal("audit leaked secret")
	}
	if err := database.Exec("UPDATE role_grants SET role_id='viewer' WHERE principal_id=?", actor).Error; err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "PUT"} {
		if response := policyRequest(router, cookie, method, "/api/monitor/config", string(body)); response.Code != 403 {
			t.Fatal("viewer notification access", method, response.Code)
		}
	}
}
