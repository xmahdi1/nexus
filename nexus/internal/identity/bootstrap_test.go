package identity

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func fixtureDB(t *testing.T) *gorm.DB {
	t.Helper()
	database, err := db.Init(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := database.DB()
	t.Cleanup(func() { c.Close() })
	return database
}
func fixtureHash(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy-fixture-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(hash)
}
func TestBootstrapAndRepeatPreserveIdentity(t *testing.T) {
	database := fixtureDB(t)
	hash := fixtureHash(t)
	options := BootstrapOptions{Username: "  OWNER  ", DisplayName: "Lab Owner", PasswordHash: hash}
	first, err := BootstrapOwner(database, options)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.User.ID == "" || first.User.Username != "owner" || first.User.Status != "active" || first.User.PasswordHash != hash {
		t.Fatal("invalid first owner")
	}
	options.DisplayName = "Replacement"
	options.PasswordHash = fixtureHash(t)
	second, err := BootstrapOwner(database, options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Created || second.User.ID != first.User.ID || second.User.PasswordHash != hash || second.User.DisplayName != "Lab Owner" {
		t.Fatal("repeat replaced account state")
	}
	if !VerifyPassword(second.User.PasswordHash, []byte("legacy-fixture-password")) {
		t.Fatal("legacy password lost")
	}
	encoded, err := json.Marshal(second.User)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), hash) || strings.Contains(string(encoded), "password") {
		t.Fatal("serialized password hash")
	}
	if _, err := BootstrapOwner(database, BootstrapOptions{Username: "other", PasswordHash: hash}); !errors.Is(err, ErrBootstrapConflict) {
		t.Fatalf("conflicting owner accepted: %v", err)
	}
}
func TestInterruptedBootstrapCanRetry(t *testing.T) {
	database := fixtureDB(t)
	if err := database.Exec(`CREATE TRIGGER fail_bootstrap BEFORE INSERT ON identity_bootstrap BEGIN SELECT RAISE(ABORT, 'injected failure'); END`).Error; err != nil {
		t.Fatal(err)
	}
	options := BootstrapOptions{Username: "owner", PasswordHash: fixtureHash(t)}
	result, err := BootstrapOwner(database, options)
	if err == nil || result.User.ID != "" {
		t.Fatal("failed bootstrap returned an identity")
	}
	for _, table := range []string{"users", "identity_bootstrap"} {
		var count int64
		database.Table(table).Count(&count)
		if count != 0 {
			t.Fatalf("partial state in %s", table)
		}
	}
	if err := database.Exec("DROP TRIGGER fail_bootstrap").Error; err != nil {
		t.Fatal(err)
	}
	if result, err := BootstrapOwner(database, options); err != nil || !result.Created {
		t.Fatalf("retry failed: %v", err)
	}
}
func TestConcurrentBootstrapHasOneStableOwner(t *testing.T) {
	database := fixtureDB(t)
	options := BootstrapOptions{Username: "owner", PasswordHash: fixtureHash(t)}
	var wg sync.WaitGroup
	type response struct {
		result BootstrapResult
		err    error
	}
	responses := make(chan response, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := BootstrapOwner(database, options)
			responses <- response{result, err}
		}()
	}
	wg.Wait()
	close(responses)
	id := ""
	created := 0
	for response := range responses {
		if response.err != nil {
			t.Fatal(response.err)
		}
		if id == "" {
			id = response.result.User.ID
		}
		if response.result.User.ID != id {
			t.Fatal("multiple owner identities")
		}
		if response.result.Created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("created %d owners", created)
	}
}
func TestBootstrapNeverPromotesOrReactivates(t *testing.T) {
	for _, state := range []string{"unmarked-account", "disabled-owner", "dangling-marker"} {
		t.Run(state, func(t *testing.T) {
			database := fixtureDB(t)
			hash := fixtureHash(t)
			if state == "unmarked-account" {
				if err := database.Create(&models.User{ID: "existing", Username: "existing", DisplayName: "Existing", PasswordHash: hash, Status: "disabled"}).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				result, err := BootstrapOwner(database, BootstrapOptions{Username: "owner", PasswordHash: hash})
				if err != nil {
					t.Fatal(err)
				}
				if state == "disabled-owner" {
					database.Model(&models.User{}).Where("id = ?", result.User.ID).Update("status", "disabled")
				} else {
					database.Exec("UPDATE identity_bootstrap SET owner_user_id = 'missing'")
				}
			}
			if _, err := BootstrapOwner(database, BootstrapOptions{Username: "owner", PasswordHash: hash}); !errors.Is(err, ErrBootstrapConflict) {
				t.Fatalf("unsafe recovery accepted: %v", err)
			}
		})
	}
}
func TestInvalidBootstrapInputsWriteNothing(t *testing.T) {
	database := fixtureDB(t)
	hash := fixtureHash(t)
	for _, options := range []BootstrapOptions{
		{Username: "a", PasswordHash: hash}, {Username: "../owner", PasswordHash: hash},
		{Username: "owner", PasswordHash: "plaintext"}, {Username: "owner", PasswordHash: hash, DisplayName: "bad\nname"},
		{Username: "owner", PasswordHash: hash, DisplayName: strings.Repeat("x", 121)},
	} {
		if _, err := BootstrapOwner(database, options); err == nil {
			t.Fatal("invalid account accepted")
		}
	}
	var count int64
	database.Model(&models.User{}).Count(&count)
	if count != 0 {
		t.Fatal("invalid bootstrap created user")
	}
}

func TestUserDatabaseConstraints(t *testing.T) {
	database := fixtureDB(t)
	user := models.User{ID: "first", Username: "owner", DisplayName: "Owner", Status: "active", PasswordHash: fixtureHash(t)}
	if err := database.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	for i, change := range []func(*models.User){
		func(u *models.User) { u.Username = "owner" },
		func(u *models.User) { u.Username = "UPPER" },
		func(u *models.User) { u.Username = "../bad" },
		func(u *models.User) { u.Status = "administrator" },
		func(u *models.User) { u.PasswordHash = "" },
	} {
		candidate := user
		candidate.ID = strings.Repeat("x", i+1)
		candidate.Username = "other"
		change(&candidate)
		if err := database.Create(&candidate).Error; err == nil {
			t.Fatal("database accepted invalid/duplicate user")
		}
	}
}
