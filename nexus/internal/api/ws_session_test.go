package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

// A loopback SSH fixture only emits canned output. It never executes the
// supplied collection command or accesses a Docker daemon/real managed host.
func TestMetricsWebSocketClosesAfterHTTPLogout(t *testing.T)           { testMetricsWebSocket(t, false) }
func TestMetricsWebSocketClosesAfterGroupScopeRevocation(t *testing.T) { testMetricsWebSocket(t, true) }
func TestMetricsWebSocketClosesAfterInvitedAccountDisablement(t *testing.T) {
	testMetricsWebSocket(t, false, true)
}
func testMetricsWebSocket(t *testing.T, scopeRevocation bool, disable ...bool) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sshConfig := &ssh.ServerConfig{NoClientAuth: true}
	sshConfig.AddHostKey(signer)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, err := ssh.NewServerConn(conn, sshConfig)
		if err != nil {
			return
		}
		defer server.Close()
		go func() {
			for req := range requests {
				req.Reply(true, nil)
			}
		}()
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			go func() {
				defer channel.Close()
				for req := range requests {
					if req.Type != "exec" {
						req.Reply(false, nil)
						continue
					}
					req.Reply(true, nil)
					fmt.Fprintln(channel, "fixture metrics output")
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					return
				}
			}()
		}
	}()
	database, err := db.Init(filepath.Join(t.TempDir(), "ws.db"))
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	defer conn.Close()
	cfg := &config.Config{EncryptionKey: bytes.Repeat([]byte{4}, 32)}
	hash, _ := bcrypt.GenerateFromPassword([]byte("fixture WS password"), bcrypt.MinCost)
	cfg.PasswordHash = string(hash)
	encrypted, err := nexuscrypto.Encrypt(cfg.EncryptionKey, pem.EncodeToMemory(private))
	if err != nil {
		t.Fatal(err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	if err := database.Create(&models.Server{ID: "fixture", Name: "Fixture", Host: host, Port: port, Username: "fixture", PrivateKeyEnc: encrypted}).Error; err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	defer pool.Remove("fixture")
	pool.SetHostKeyCallback(func(_ string, fingerprint string) error {
		if fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			return fmt.Errorf("wrong fixture key")
		}
		return nil
	})
	if err := database.Exec("DELETE FROM role_grants WHERE principal_id=?", auth.LegacyPrincipal).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO server_groups(id,name,created_at) VALUES('development','Development',?)", time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO server_group_members(group_id,server_id) VALUES('development','fixture')").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES('fixture-operator',?,'legacy','operator','server_group','development','fixture',?)", auth.LegacyPrincipal, time.Now().UTC()).Error; err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(NewRouter(database, cfg, pool, nil))
	defer server.Close()
	login, err := auth.NewService(database, cfg).Login("", "fixture WS password", "test", host)
	if err != nil {
		t.Fatal(err)
	}
	var administrator *auth.Access
	service := auth.NewService(database, cfg)
	if len(disable) > 0 && disable[0] {
		if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: cfg.PasswordHash}); err != nil {
			t.Fatal(err)
		}
		if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
			t.Fatal(err)
		}
		ownerLogin, err := service.Login("owner", "fixture WS password", "test", host)
		if err != nil {
			t.Fatal(err)
		}
		administrator, err = service.Authenticate(ownerLogin.Token)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.Exec("INSERT INTO role_grants(id,principal_id,principal_kind,role_id,scope_type,scope_id,created_by,created_at) VALUES('owner-admin',?,'user','admin','global','','fixture',?)", administrator.User.ID, time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		invitation, err := service.CreateInvitation(administrator, auth.InviteOptions{Username: "operator", RoleID: "operator", ScopeType: "server_group", ScopeID: "development"}, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.AcceptInvitation(invitation.Token, "invited operator password"); err != nil {
			t.Fatal(err)
		}
		login, err = service.Login("operator", "invited operator password", "test", host)
		if err != nil {
			t.Fatal(err)
		}
	}
	target, _ := url.Parse(server.URL)
	headers := http.Header{}
	headers.Set("Origin", server.URL)
	headers.Set("Cookie", auth.CookieName()+"="+login.Token)
	dialer := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, HandshakeTimeout: 3 * time.Second}
	ws, _, err := dialer.Dial("wss://"+target.Host+"/ws/metrics/fixture", headers)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := ws.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	// An operator can perform an allowed container action through the actual
	// HTTP/SSH adapter, but cannot execute arbitrary database commands.
	for _, tc := range []struct {
		suffix string
		status int
	}{{"start", 200}, {"exec", 403}} {
		request, _ := http.NewRequest("POST", server.URL+"/api/servers/fixture/containers/"+strings.Repeat("a", 12)+"/"+tc.suffix, strings.NewReader("{}"))
		request.Header.Set("Origin", server.URL)
		request.AddCookie(&http.Cookie{Name: auth.CookieName(), Value: login.Token})
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatalf("operator %s: %d", tc.suffix, response.StatusCode)
		}
	}
	if administrator != nil {
		actor, err := service.Authenticate(login.Token)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.ChangeStatus(administrator, actor.User.ID, "disabled", ""); err != nil {
			t.Fatal(err)
		}
	} else if scopeRevocation {
		if err := database.Exec("DELETE FROM server_group_members WHERE group_id='development'").Error; err != nil {
			t.Fatal(err)
		}
		if _, err := auth.NewService(database, cfg).Authenticate(login.Token); err != nil {
			t.Fatal("scope test unexpectedly revoked the session itself")
		}
	} else {
		request, err := http.NewRequest("POST", server.URL+"/api/auth/logout", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", server.URL)
		request.AddCookie(&http.Cookie{Name: auth.CookieName(), Value: login.Token})
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("HTTP logout failed")
		}
	}

	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				t.Fatal("revoked metrics stream stayed open")
			}
			break
		}
	}
}
