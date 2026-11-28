package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"github.com/xmahdi1/nexus/internal/vault"
	"golang.org/x/crypto/ssh"
)

func TestVaultTLSOverPinnedSSHAndInFlightRevocation(t *testing.T) {
	var blocked, blockedRead, loseAck atomic.Bool
	enteredRead, releaseRead := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	var adminWrites atomic.Int32
	writeBodies := make(chan []byte, 4)
	entered, release := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/health":
			io.WriteString(w, `{"initialized":true,"sealed":false,"standby":false}`)
		case "/v1/auth/token/lookup-self":
			io.WriteString(w, `{"data":{"policies":["fixture"],"ttl":1200}}`)
		case "/v1/sys/mounts":
			if r.Header.Get("X-Vault-Token") != "short-lived-fixture" {
				t.Error("token missing from tunnel")
			}
			if blocked.Load() {
				close(entered)
				<-release
			}
			io.WriteString(w, `{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`)
		case "/v1/sys/auth":
			io.WriteString(w, `{"data":{"token/":{"type":"token","config":{"default_lease_ttl":0}}}}`)
		case "/v1/sys/policies/acl":
			if r.URL.Query().Get("list") != "true" {
				t.Error("policy listing query missing")
			}
			io.WriteString(w, `{"data":{"keys":["example"]}}`)
		case "/v1/sys/policies/acl/example":
			if r.Method == "PUT" {
				adminWrites.Add(1)
				if loseAck.Load() {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					connection.Close()
					return
				}
				w.WriteHeader(204)
				return
			}
			io.WriteString(w, `{"data":{"policy":"# private-policy-body"}}`)
		case "/v1/sys/capabilities-self":
			io.WriteString(w, `{"data":{"secret/data/key":["read"],"unrequested":["root"]}}`)
		case "/v1/secret/metadata/key":
			io.WriteString(w, `{"data":{"current_version":1}}`)
		case "/v1/secret/data/key":
			if r.Method == "GET" {
				if blockedRead.Load() {
					close(enteredRead)
					<-releaseRead
				}
				io.WriteString(w, `{"data":{"data":{"value":"private-revealed-value","large":9007199254740993,"decimal":0.1000000000000000001},"metadata":{"version":1}}}`)
				return
			}
			payload, _ := io.ReadAll(r.Body)
			writeBodies <- payload
			writes.Add(1)
			if loseAck.Load() {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				connection.Close()
				return
			}
			io.WriteString(w, `{"data":{"version":2}}`)
		default:
			t.Error("unexpected Vault path")
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(private)
	privatePEM, _ := ssh.MarshalPrivateKey(private, "")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sshConfig := &ssh.ServerConfig{NoClientAuth: true}
	sshConfig.AddHostKey(signer)
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				connection, channels, requests, err := ssh.NewServerConn(raw, sshConfig)
				if err != nil {
					return
				}
				defer connection.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					var destination struct {
						Host       string
						Port       uint32
						Origin     string
						OriginPort uint32
					}
					if incoming.ChannelType() != "direct-tcpip" || ssh.Unmarshal(incoming.ExtraData(), &destination) != nil || destination.Host != "127.0.0.1" || destination.Port != 8200 {
						incoming.Reject(ssh.Prohibited, "fixture only")
						t.Error("forward escaped saved loopback port")
						continue
					}
					remote, err := net.Dial("tcp", upstream.Listener.Addr().String())
					if err != nil {
						incoming.Reject(ssh.ConnectionFailed, "fixture unavailable")
						continue
					}
					channel, requests, err := incoming.Accept()
					if err != nil {
						remote.Close()
						continue
					}
					go ssh.DiscardRequests(requests)
					go func() {
						defer channel.Close()
						defer remote.Close()
						go func() { io.Copy(remote, channel); remote.Close() }()
						io.Copy(channel, remote)
					}()
				}
			}()
		}
	}()
	database, _, cookie, actor := rbacFixture(t, "admin", "server", "dev")
	key := bytes.Repeat([]byte{9}, 32)
	ciphertext, err := nexuscrypto.Encrypt(key, pem.EncodeToMemory(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	if err := database.Model(&models.Server{}).Where("id=?", "dev").Updates(map[string]any{"host": host, "port": port, "private_key_enc": ciphertext}).Error; err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	defer pool.Remove("dev")
	pool.SetHostKeyCallback(func(id, fingerprint string) error {
		if id != "dev" || fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			return errors.New("untrusted fixture")
		}
		return nil
	})
	router := NewRouter(database, &config.Config{VaultEnabled: true, EncryptionKey: key}, pool, nil)
	profile := vault.Profile{Port: 8200, TLSName: "127.0.0.1", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}))}
	body, _ := json.Marshal(profile)
	if r := policyRequest(router, cookie, "PUT", "/api/servers/dev/vault", string(body)); r.Code != 200 {
		t.Fatal("settings rejected", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/inspect", `{"token":"short-lived-fixture"}`); r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte(`"mountsStatus":"ok"`)) {
		t.Fatal("tunneled inventory failed", r.Code, r.Body.String())
	}
	for _, call := range []struct{ action, body, want string }{
		{"auth", `{"token":"short-lived-fixture"}`, `"methods"`},
		{"policies", `{"token":"short-lived-fixture"}`, `"example"`},
		{"policy", `{"token":"short-lived-fixture","name":"example"}`, "private-policy-body"},
		{"capabilities", `{"token":"short-lived-fixture","paths":["secret/data/key"]}`, `"read"`},
	} {
		r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/access/"+call.action, call.body)
		if r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte(call.want)) || bytes.Contains(r.Body.Bytes(), []byte("unrequested")) {
			t.Fatal("tunneled access inspection failed", call.action, r.Code)
		}
	}
	readBody := `{"token":"short-lived-fixture","mount":"secret","path":"key"}`
	policyRead := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/policy-read", `{"token":"short-lived-fixture","params":{"name":"example"}}`)
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/policy-read", `{"token":"short-lived-fixture","params":{"name":"\u0065xample"}}`); r.Code != 200 {
		t.Fatal("equivalent JSON name rejected", r.Code)
	}
	var policyRevision vault.AdminResult
	if policyRead.Code != 200 || json.Unmarshal(policyRead.Body.Bytes(), &policyRevision) != nil || len(policyRevision.Revision) != 64 {
		t.Fatal("admin policy read through SSH failed", policyRead.Code)
	}
	policyBody, _ := json.Marshal(map[string]any{"token": "short-lived-fixture", "confirmation": "policy-save", "params": map[string]string{"name": "example", "revision": policyRevision.Revision, "policy": "# private-admin-written-source"}})
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/policy-save", string(policyBody)); r.Code != 200 {
		t.Fatal("scoped policy mutation through SSH failed", r.Code)
	}
	loseAck.Store(true)
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/admin/policy-save", string(policyBody)); r.Code != 502 || !bytes.Contains(r.Body.Bytes(), []byte(`"code":"remote_unknown"`)) {
		t.Fatal("lost admin acknowledgement not uncertain", r.Code)
	}
	loseAck.Store(false)
	if adminWrites.Load() != 2 {
		t.Fatal("admin policy write replayed", adminWrites.Load())
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/read", readBody); r.Code != 403 {
		t.Fatal("admin implicitly revealed values", r.Code)
	}
	if err := database.Create(&authorization.Grant{ID: "fixture-reveal", PrincipalID: actor, PrincipalKind: "user", RoleID: "secret-reader", ScopeType: "server", ScopeID: "dev", CreatedBy: actor, CreatedAt: time.Now().UTC()}).Error; err != nil {
		t.Fatal(err)
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/read", readBody); r.Code != 200 || !bytes.Contains(r.Body.Bytes(), []byte("private-revealed-value")) {
		t.Fatal("explicit reveal failed", r.Code)
	} else {
		var value struct {
			DataJSON string `json:"dataJson"`
		}
		if json.Unmarshal(r.Body.Bytes(), &value) != nil || !strings.Contains(value.DataJSON, "9007199254740993") || !strings.Contains(value.DataJSON, "0.1000000000000000001") {
			t.Fatal("reveal lost JSON precision")
		}
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/metadata", readBody); r.Code != 200 || bytes.Contains(r.Body.Bytes(), []byte("private-revealed-value")) {
		t.Fatal("metadata disclosed values", r.Code)
	}
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/write", `{"token":"short-lived-fixture","mount":"secret","path":"key","version":1,"data":{"number":9007199254740993}}`); r.Code != 400 || writes.Load() != 0 {
		t.Fatal("lossy numeric input reached Vault", r.Code)
	}
	writeBody := `{"token":"short-lived-fixture","mount":"secret","path":"key","version":1,"dataJson":"{\"value\":\"private-written-value\",\"large\":\"9007199254740993\",\"decimal\":\"0.1000000000000000001\"}"}`
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/write", writeBody); r.Code != 200 || bytes.Contains(r.Body.Bytes(), []byte("private-written-value")) {
		t.Fatal("CAS write failed or echoed input", r.Code)
	}
	posted := <-writeBodies
	if !bytes.Contains(posted, []byte("9007199254740993")) || !bytes.Contains(posted, []byte("0.1000000000000000001")) {
		t.Fatal("JSON text numbers changed before Vault")
	}
	loseAck.Store(true)
	if r := policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/write", writeBody); r.Code != 502 || !bytes.Contains(r.Body.Bytes(), []byte(`"code":"remote_unknown"`)) {
		t.Fatal("lost write receipt not uncertain", r.Code)
	}
	if writes.Load() != 2 {
		t.Fatal("write automatically retried", writes.Load())
	}
	var events []audit.Event
	if err := database.Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(events)
	for _, private := range []string{"private-written-value", "private-revealed-value", "short-lived-fixture", "private-policy-body", "private-admin-written-source"} {
		if bytes.Contains(encoded, []byte(private)) {
			t.Fatal("secret in audit")
		}
	}
	accessRecorded := false
	policyIdentity := ""
	policyReadResults := 0
	for _, event := range events {
		if event.ResourceType == "vault_control" && event.Action == "POST /api/servers/{id}/vault/admin/policy-read" {
			policyReadResults++
			if policyIdentity == "" {
				policyIdentity = event.ResourceID
			} else if policyIdentity != event.ResourceID {
				t.Fatal("equivalent JSON encoding changed audit resource identity")
			}
		}
		if event.ResourceType == "vault_control" {
			accessRecorded = true
		}
	}
	if !accessRecorded {
		t.Fatal("access audit identity missing")
	}
	if policyReadResults < 2 {
		t.Fatal("policy resource identity regression was not exercised")
	}
	unknownRecorded := false
	adminUnknownRecorded := false
	for _, event := range events {
		if event.ResourceType == "vault_control" && event.Outcome == "remote_unknown" {
			adminUnknownRecorded = true
		}
		if event.ResourceType == "vault_kv" && event.Outcome == "remote_unknown" {
			unknownRecorded = true
		}
	}
	if !unknownRecorded {
		t.Fatal("uncertain write missing from metadata audit")
	}
	if !adminUnknownRecorded {
		t.Fatal("uncertain admin write missing from metadata audit")
	}
	blockedRead.Store(true)
	readDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { readDone <- policyRequest(router, cookie, "POST", "/api/servers/dev/vault/kv/read", readBody) }()
	select {
	case <-enteredRead:
	case <-time.After(10 * time.Second):
		close(releaseRead)
		t.Fatal("secret read did not reach upstream")
	}
	if err := database.Exec("DELETE FROM role_grants WHERE id='fixture-reveal'").Error; err != nil {
		close(releaseRead)
		t.Fatal(err)
	}
	close(releaseRead)
	select {
	case r := <-readDone:
		if r.Code != 403 || bytes.Contains(r.Body.Bytes(), []byte("private-revealed-value")) {
			t.Fatal("revoked reveal disclosed secret", r.Code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoked reveal did not return")
	}
	blocked.Store(true)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- policyRequest(router, cookie, "POST", "/api/servers/dev/vault/inspect", `{"token":"short-lived-fixture"}`)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("inspection did not reach fixture")
	}
	if err := database.Exec("DELETE FROM role_grants WHERE id='fixture-role'").Error; err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	select {
	case r := <-done:
		if r.Code != 403 || bytes.Contains(r.Body.Bytes(), []byte("secret/")) {
			t.Fatal("revoked response disclosed inventory", r.Code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("revoked request did not stop")
	}
}
