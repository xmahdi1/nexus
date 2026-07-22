package handlers

import (
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

	run, err := h.sshRun(serverID)
	if err != nil {
		writeErr(w, err.Error(), "ssh_error", http.StatusBadGateway)
		return
	}

	imgOut, err := run(fmt.Sprintf("docker inspect --format='{{.Config.Image}}' %s 2>/dev/null", cid))
	if err != nil || imgOut == "" {
		writeErr(w, "container not found", "not_found", http.StatusNotFound)
		return
	}
	image := strings.ToLower(strings.TrimSpace(imgOut))

	var execCmd string
	switch {
	case strings.Contains(image, "postgres"):
		user := "postgres"
		if body.DbUser != "" {
			user = body.DbUser
		}
		env := ""
		if body.DbPassword != "" {
			env = fmt.Sprintf("-e PGPASSWORD=%s", execQuote(body.DbPassword))
		}
		execCmd = fmt.Sprintf("docker exec %s %s psql -U %s -c %s 2>&1", env, cid, execQuote(user), execQuote(body.Query))

	case strings.Contains(image, "mariadb"), strings.Contains(image, "mysql"):
		user := "root"
		if body.DbUser != "" {
			user = body.DbUser
		}
		env := ""
		if body.DbPassword != "" {
			env = fmt.Sprintf("-e MYSQL_PWD=%s", execQuote(body.DbPassword))
		}
		execCmd = fmt.Sprintf("docker exec %s %s mysql -u %s -e %s 2>&1", env, cid, execQuote(user), execQuote(body.Query))

	case strings.Contains(image, "redis"):
		execCmd = fmt.Sprintf("docker exec %s redis-cli %s 2>&1", cid, execQuote(body.Query))

	case strings.Contains(image, "mongo"):
		execCmd = fmt.Sprintf("docker exec %s mongosh --eval %s --quiet 2>&1", cid, execQuote(body.Query))

	default:
		writeErr(w, "unsupported database: "+image, "unsupported", http.StatusBadRequest)
		return
	}

	output, _ := run(execCmd)
	writeJSON(w, map[string]string{"output": output}, http.StatusOK)
}

func execQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func (h *ExecHandler) sshRun(serverID string) (func(string) (string, error), error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	client, err := h.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return func(cmd string) (string, error) {
		sess, err := client.NewSession()
		if err != nil {
			h.pool.Remove(serverID)
			return "", err
		}
		defer sess.Close()
		out, err := sess.CombinedOutput(cmd)
		return strings.TrimSpace(string(out)), err
	}, nil
}
