package githubactions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/config"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/identity"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
)

func serviceFixture(t *testing.T) (*Service, *auth.Access, ConnectionInput, *int) {
	t.Helper()
	c, app, repo, _ := fixture(t)
	key := bytes.Repeat([]byte{7}, 32)
	database, err := db.Init(filepath.Join(t.TempDir(), "github.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	connection, _ := database.DB()
	t.Cleanup(func() { connection.Close() })
	password := "GitHub fixture password"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	cfg := &config.Config{EncryptionKey: key, PasswordHash: string(hash)}
	if _, err := identity.BootstrapOwner(database, identity.BootstrapOptions{Username: "owner", PasswordHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	if err := auth.ActivateOwner(database, cfg, "owner"); err != nil {
		t.Fatal(err)
	}
	sessions := auth.NewService(database, cfg)
	login, err := sessions.Login("owner", password, "fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := sessions.Authenticate(login.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&models.Server{ID: "build", Name: "Build"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"github-connections", "github-actions-dispatcher"} {
		if err := database.Create(&authorization.Grant{ID: role, PrincipalID: a.User.ID, PrincipalKind: "user", RoleID: role, ScopeType: "server", ScopeID: "build", CreatedBy: a.User.ID, CreatedAt: time.Now().UTC()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	writes := 0
	c.transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "access_tokens") {
			var input struct {
				Permissions map[string]string `json:"permissions"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			return response(201, fmt.Sprintf(`{"token":"ghs_fixture_scoped_token","expires_at":%q,"permissions":{"actions":%q,"contents":"read"},"repositories":[{"id":123}]}`, c.now().Add(time.Hour).Format(time.RFC3339), input.Permissions["actions"])), nil
		}
		if strings.HasSuffix(r.URL.Path, "dispatches") {
			writes++
			return nil, errors.New("private provider failure")
		}
		return response(200, `{"id":123,"full_name":"fixture/repository"}`), nil
	})
	return &Service{DB: database, Key: key, Sessions: sessions, Enabled: true, Client: c}, a, ConnectionInput{Repository: repo, ClientID: app.ClientID, InstallationID: app.InstallationID, PrivateKey: string(app.PrivateKey)}, &writes
}
func TestConnectionEncryptionAndDispatchNeverReplay(t *testing.T) {
	s, a, input, writes := serviceFixture(t)
	row, err := s.Create(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(row)
	if strings.Contains(string(encoded), "PRIVATE KEY") || strings.Contains(row.ConfigEnc, input.PrivateKey) {
		t.Fatal("key exposed")
	}
	if _, _, err := s.connection("another-server", row.ID); err == nil {
		t.Fatal("connection moved across server scope")
	}
	request := Dispatch{WorkflowID: 7, Ref: "main", Inputs: map[string]any{"name": "private-input-fixture"}}
	id := strings.Repeat("a", 32)
	run, err := s.Submit(context.Background(), a, "build", row.ID, id, request)
	if !errors.Is(err, ErrUnknown) || run.State != "unknown" || *writes != 1 {
		t.Fatal("lost ACK invented success", run, err)
	}
	encoded, _ = json.Marshal(run)
	if strings.Contains(string(encoded), "private-input-fixture") || strings.Contains(string(encoded), "sourceSession") || strings.Contains(string(encoded), "inputEnc") {
		t.Fatal("submission metadata leaked private data")
	}
	if _, err := s.Submit(context.Background(), a, "build", row.ID, id, request); err != nil || *writes != 1 {
		t.Fatal("duplicate identity dispatched again", err)
	}
	request.Inputs["name"] = "changed"
	if _, err := s.Submit(context.Background(), a, "build", row.ID, id, request); !errors.Is(err, ErrConflict) || *writes != 1 {
		t.Fatal("changed input reused identity", err)
	}
	if err := s.Disable(a, "build", row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(context.Background(), a, "build", row.ID, strings.Repeat("b", 32), request); !errors.Is(err, ErrDenied) || *writes != 1 {
		t.Fatal("disabled connection dispatched", err)
	}
}

func TestHistoryRetiresOnlyUnclaimedPreparedRequestsWithoutReplay(t *testing.T) {
	s, a, input, writes := serviceFixture(t)
	connection, err := s.Create(context.Background(), a, "build", input)
	if err != nil {
		t.Fatal(err)
	}
	request := Dispatch{WorkflowID: 7, Ref: "main"}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for index, state := range []string{"prepared", "submitting", "unknown", "prepared"} {
		id := strings.Repeat(string(rune('a'+index)), 32)
		created := now.Add(-3 * time.Minute)
		if index == 3 {
			created = now
		}
		sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "dispatch", id, "build", payload)
		if err != nil {
			t.Fatal(err)
		}
		row := Submission{ID: id, ServerID: "build", ConnectionID: connection.ID, ActorID: a.User.ID, SourceSessionID: a.Session.ID, InputEnc: sealed, State: state, WorkflowID: 7, Ref: "main", CreatedAt: created}
		if err := s.DB.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	history, err := s.Submissions(a, "build")
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, row := range history {
		states[row.ID] = row.State
	}
	for id, want := range map[string]string{strings.Repeat("a", 32): "not_submitted", strings.Repeat("b", 32): "submitting", strings.Repeat("c", 32): "unknown", strings.Repeat("d", 32): "prepared"} {
		if states[id] != want {
			t.Fatal("incorrect recovery state", id, states[id], want)
		}
	}
	row, err := s.Submit(context.Background(), a, "build", connection.ID, strings.Repeat("a", 32), request)
	if err != nil || row.State != "not_submitted" || *writes != 0 {
		t.Fatal("retired request replayed", row.State, err, *writes)
	}
}
