package inventory

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"golang.org/x/crypto/ssh"
)

func TestInventoryVMServicePropertiesAndObservedLinks(t *testing.T) {
	address := os.Getenv("NEXUS_SUPERVISION_SSH")
	if address == "" {
		t.Skip("run scripts/supervision_lab.py --suite inventory")
	}
	host, port, err := net.SplitHostPort(address)
	nonce := os.Getenv("NEXUS_SUPERVISION_NONCE")
	if err != nil || host != "127.0.0.1" || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(nonce) {
		t.Fatal("owned loopback fixture required")
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(os.Getenv("NEXUS_SUPERVISION_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Getenv("NEXUS_SUPERVISION_HOST_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	pool := nexusssh.NewPool()
	defer pool.Remove("dev")
	pool.SetHostKeyCallback(func(id, fingerprint string) error {
		if id != "dev" || fingerprint != ssh.FingerprintSHA256(public) {
			return fmt.Errorf("fixture host key mismatch")
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := pool.GetContext(ctx, nexusssh.ServerConfig{ID: "dev", Host: host, Port: number, User: "root", PrivKey: private})
	if err != nil {
		t.Fatal(err)
	}
	marker, err := nexusssh.Run(ctx, client, "cat /nexus-fixture-nonce", nil, 5*time.Second)
	if err != nil || strings.TrimSpace(marker) != nonce {
		t.Fatal("fixture ownership mismatch")
	}
	s := fixture(t)
	key := bytes.Repeat([]byte{7}, 32)
	sealed, err := nexuscrypto.Encrypt(key, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB.Model(&models.Server{}).Where("id='dev'").Updates(map[string]any{"host": host, "port": number, "username": "root", "private_key_enc": sealed}).Error; err != nil {
		t.Fatal(err)
	}
	s.Adapter = &SSHAdapter{DB: s.DB, Key: key, Pool: pool}
	observation, err := s.Adapter.Collect(ctx, "dev")
	if err != nil || !observation.HostOK || !observation.ServicesOK || len(observation.Services) == 0 {
		t.Fatal("real systemd properties unavailable", err)
	}
	found := false
	for _, unit := range observation.Services {
		if unit.Unit == "ssh.service" && unit.Active == "active" {
			found = true
		}
	}
	if !found {
		t.Fatal("running SSH service was not observed")
	}
	for range 2 {
		if _, err := s.Discover(ctx, authorization.LegacyPrincipal, "dev"); err != nil {
			t.Fatal(err)
		}
	}
	id := resourceID("dev", "service", "ssh.service")
	history, err := s.History(authorization.LegacyPrincipal, "dev", id, "", 100)
	if err != nil || len(history.Items) != 1 || history.Items[0].Kind != "observed" {
		t.Fatal("stable real service generated duplicate changes", err)
	}
	var count int64
	if err := s.DB.Model(&Relationship{}).Where("server_id='dev' AND target_id=? AND kind='manages' AND data_state='fresh'", id).Count(&count).Error; err != nil || count != 1 {
		t.Fatal("observed service relationship missing", err)
	}
	t.Log("Real pinned SSH/systemd property collection, service persistence, stable change history and observed host ownership passed; no service mutation or network reachability inference.")
}
