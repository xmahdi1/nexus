package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type ExecHandler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

func NewExecHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *ExecHandler {
	return &ExecHandler{db: db, encKey: encKey, pool: pool}
}

var containerIDRe = regexp.MustCompile(`^[0-9a-fA-F]{12,64}$`)

func (h *ExecHandler) DbExec(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "id")
	cid := chi.URLParam(r, "cid")

	if !containerIDRe.MatchString(cid) {
		writeErr(w, "invalid container id", "bad_request", http.StatusBadRequest)
		return
	}

	var body struct {
		Query      string `json:"query"`
		DbUser     string `json:"dbUser"`
		DbPassword string `json:"dbPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Query == "" {
		writeErr(w, "query required", "bad_request", http.StatusBadRequest)
		return
	}

	send, err := h.sshInput(r.Context(), serverID)
	if err != nil {
		writeErr(w, err.Error(), "ssh_error", http.StatusBadGateway)
		return
	}

	imgOut, err := send(fmt.Sprintf("docker inspect --format='{{.Config.Image}}' %s 2>/dev/null", cid), "")
	if err != nil {
		writeErr(w, "Container image lookup failed.", "remote_error", http.StatusBadGateway)
		return
	}
	if imgOut == "" {
		writeErr(w, "container not found", "not_found", http.StatusNotFound)
		return
	}
	image := strings.ToLower(strings.TrimSpace(imgOut))

	execCmd, input, err := databaseCommand(image, cid, body.DbUser, body.DbPassword, body.Query)
	if err != nil {
		writeErr(w, err.Error(), "bad_request", http.StatusBadRequest)
		return
	}
	output, err := send(execCmd, input)
	if err != nil {
		writeErr(w, "Database command failed or was interrupted; inspect remote state before retrying.", "exec_error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"output": output}, http.StatusOK)
}

func execQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func (h *ExecHandler) sshInput(ctx context.Context, serverID string) (func(string, string) (string, error), error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	client, err := h.pool.GetContext(ctx, nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return func(cmd, input string) (string, error) {
		out, err := nexusssh.Run(ctx, client, cmd, strings.NewReader(input), nexusssh.CommandTimeout)
		return strings.TrimSpace(out), err
	}, nil
}

// Keep passwords and queries off SSH/remote process command lines. Container
// client tools receive passwords through their environment after reading stdin.
func databaseCommand(image, cid, user, password, query string) (string, string, error) {
	if len(query) > 1<<20 || len(password) > 4096 || strings.ContainsAny(password, "\r\n\x00") {
		return "", "", fmt.Errorf("invalid database command input")
	}
	if !containerIDRe.MatchString(cid) {
		return "", "", fmt.Errorf("invalid container id")
	}
	var script, input string
	switch {
	case strings.Contains(image, "postgres"):
		if user == "" {
			user = "postgres"
		}
		script = "IFS= read -r PGPASSWORD || exit 1; export PGPASSWORD; exec psql -v ON_ERROR_STOP=1 -U " + execQuote(user)
		input = password + "\n" + query + "\n"
	case strings.Contains(image, "mariadb"), strings.Contains(image, "mysql"):
		if user == "" {
			user = "root"
		}
		script = "IFS= read -r MYSQL_PWD || exit 1; export MYSQL_PWD; exec mysql --batch -u " + execQuote(user)
		input = password + "\n" + query + "\n"
	case strings.Contains(image, "redis"):
		script = `IFS= read -r REDISCLI_AUTH || exit 1; if [ -n "$REDISCLI_AUTH" ]; then export REDISCLI_AUTH; else unset REDISCLI_AUTH; fi; exec redis-cli -e`
		input = password + "\n" + query + "\n"
	case strings.Contains(image, "mongo"):
		script = "exec mongosh --quiet --file /dev/stdin"
		input = query + "\n"
	default:
		return "", "", fmt.Errorf("unsupported database")
	}
	return "docker exec -i " + cid + " sh -c " + execQuote(script) + " 2>&1", input, nil
}
