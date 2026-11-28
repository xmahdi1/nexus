package backups

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
)

//go:embed discovery.py
var discoverySource string

func (r *Runtime) workRoot(server string) string {
	if server == "" {
		return r.WorkRoot
	}
	return "/var/lib/nexus-backups"
}
func (r *Runtime) Discover(ctx context.Context, a *auth.Access, server, prefix string) (Discovery, error) {
	result := Discovery{Sources: []Candidate{}, Tools: map[string]bool{}}
	if err := r.require(a, server, true, "backups.manage", "backups.read", "secrets.use"); err != nil {
		return result, err
	}
	if prefix != "" && !validPath(prefix) {
		return result, ErrInput
	}
	if server == "" {
		if prefix != "" {
			return result, ErrInput
		}
		result.Sources = append(result.Sources, Candidate{ID: "nexus", Source: Source{Kind: "nexus", Label: "Nexus database, matching key and recovery metadata"}, Consistency: "Consistent SQLite recovery copy", State: "ready"})
		result.Tools["python3"] = exec.CommandContext(ctx, "python3", "-I", "-c", "pass").Run() == nil
		return result, nil
	}
	if err := r.require(a, server, true, "servers.connect"); err != nil {
		return result, err
	}
	if _, err := r.hostBinding(server); err != nil {
		return result, err
	}
	var host models.Server
	if err := r.DB.First(&host, "id=?", server).Error; err != nil {
		return result, err
	}
	key, err := nexuscrypto.Decrypt(r.Key, host.PrivateKeyEnc)
	if err != nil {
		return result, err
	}
	defer clear(key)
	if r.Pool == nil {
		return result, ErrDisabled
	}
	client, err := r.Pool.GetContext(ctx, nexusssh.ServerConfig{ID: host.ID, Host: host.Host, Port: host.Port, User: host.Username, PrivKey: key})
	if err != nil {
		return result, ErrDenied
	}
	payload, _ := json.Marshal(map[string]string{"path": prefix, "workRoot": r.workRoot(server)})
	command := fmt.Sprintf("exec /usr/bin/python3 -I -c 'import base64;exec(compile(base64.b64decode(%q),\"backup-discovery\",\"exec\"))'", base64.StdEncoding.EncodeToString([]byte(discoverySource)))
	output, err := nexusssh.Run(ctx, client, command, strings.NewReader(string(payload)), 30*time.Second)
	if err != nil || len(output) > 256<<10 || json.Unmarshal([]byte(output), &result) != nil || len(result.Sources) > 250 {
		return Discovery{}, ErrInput
	}
	if err := r.require(a, server, true, "backups.manage", "backups.read", "servers.connect", "secrets.use"); err != nil {
		return Discovery{}, err
	}
	for _, item := range result.Sources {
		if len(item.ID) > 64 || !text(item.Source.Label, 120) || len(item.Source.Path) > 4096 || len(item.Note) > 500 {
			return Discovery{}, ErrInput
		}
	}
	var apps []models.DeployedApp
	if err := r.DB.Select("id", "name", "compose_path").Where("server_id=?", server).Limit(100).Find(&apps).Error; err != nil {
		return Discovery{}, err
	}
	for _, app := range apps {
		if validPath(app.ComposePath) && len(result.Sources) < 250 {
			source := Source{Kind: "files", Label: "Application: " + app.Name, Path: path.Dir(app.ComposePath)}
			if !text(source.Label, 120) {
				source.Label = "Application data"
			}
			sum := sha256.Sum256([]byte("app:" + app.ID))
			result.Sources = append(result.Sources, Candidate{ID: hex.EncodeToString(sum[:]), Source: source, Consistency: "Files and configuration; use a database export for live databases", State: "ready"})
		}
	}
	return result, nil
}
