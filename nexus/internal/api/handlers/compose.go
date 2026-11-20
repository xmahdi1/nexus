package handlers

import (
	"encoding/json"
	"github.com/xmahdi1/nexus/internal/audit"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/xmahdi1/nexus/internal/compose"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type ComposeHandler struct {
	supervised bool
	db         *gorm.DB
	encKey     []byte
	pool       *nexusssh.Pool
}

func NewComposeHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool, supervised ...bool) *ComposeHandler {
	h := &ComposeHandler{db: db, encKey: encKey, pool: pool}
	if len(supervised) > 0 {
		h.supervised = supervised[0]
	}
	return h
}

func (h *ComposeHandler) sshClient(w http.ResponseWriter, serverID string) (*nexusssh.Pool, *models.Server, []byte, bool) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		writeErr(w, "server not found", "not_found", http.StatusNotFound)
		return nil, nil, nil, false
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		writeErr(w, "key decrypt failed", "internal", http.StatusInternalServerError)
		return nil, nil, nil, false
	}
	return h.pool, &server, privKey, true
}

func (h *ComposeHandler) Read(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/root/docker-compose.yml"
	}

	pool, server, privKey, ok := h.sshClient(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	client, err := pool.GetContext(r.Context(), nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		writeErr(w, "ssh: "+err.Error(), "connection_failed", http.StatusBadGateway)
		return
	}

	content, err := compose.ReadFile(r.Context(), client, path)
	if err != nil {
		writeErr(w, err.Error(), "read_failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]string{"content": content, "path": path}, http.StatusOK)
}

func (h *ComposeHandler) Write(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/root/docker-compose.yml"
	}

	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid body", "bad_request", http.StatusBadRequest)
		return
	}

	pool, server, privKey, ok := h.sshClient(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	client, err := pool.GetContext(r.Context(), nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		writeErr(w, "ssh: "+err.Error(), "connection_failed", http.StatusBadGateway)
		return
	}

	if err := compose.WriteFile(r.Context(), client, path, body.Content); err != nil {
		writeErr(w, err.Error(), "write_failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *ComposeHandler) Up(w http.ResponseWriter, r *http.Request) {
	if h.supervised {
		writeErr(w, "Use supervised operation controls with a request ID.", "supervised_operation_required", 409)
		return
	}
	h.composeAction(w, r, func(c *nexusssh.Pool, s *models.Server, pk []byte, path string) (string, error) {
		client, err := c.GetContext(r.Context(), nexusssh.ServerConfig{ID: s.ID, Host: s.Host, Port: s.Port, User: s.Username, PrivKey: pk})
		if err != nil {
			return "", err
		}
		return compose.Up(r.Context(), client, path)
	})
}

func (h *ComposeHandler) Down(w http.ResponseWriter, r *http.Request) {
	if h.supervised {
		writeErr(w, "Use supervised operation controls with a request ID.", "supervised_operation_required", 409)
		return
	}
	h.composeAction(w, r, func(c *nexusssh.Pool, s *models.Server, pk []byte, path string) (string, error) {
		client, err := c.GetContext(r.Context(), nexusssh.ServerConfig{ID: s.ID, Host: s.Host, Port: s.Port, User: s.Username, PrivKey: pk})
		if err != nil {
			return "", err
		}
		return compose.Down(r.Context(), client, path)
	})
}

func (h *ComposeHandler) composeAction(
	w http.ResponseWriter, r *http.Request,
	fn func(*nexusssh.Pool, *models.Server, []byte, string) (string, error),
) {
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/root/docker-compose.yml"
	}

	pool, server, privKey, ok := h.sshClient(w, chi.URLParam(r, "id"))
	if !ok {
		return
	}

	output, err := fn(pool, server, privKey, path)
	if err != nil {
		audit.MarkFailed(r.Context())
		writeJSON(w, map[string]any{"ok": false, "output": output, "error": err.Error()}, http.StatusOK)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "output": output}, http.StatusOK)
}
