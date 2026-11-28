package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/docker"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type DockerHandler struct {
	supervised bool
	db         *gorm.DB
	encKey     []byte
	pool       *nexusssh.Pool
}

func NewDockerHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool, supervised ...bool) *DockerHandler {
	h := &DockerHandler{db: db, encKey: encKey, pool: pool}
	if len(supervised) > 0 {
		h.supervised = supervised[0]
	}
	return h
}

func (h *DockerHandler) dockerClient(w http.ResponseWriter, r *http.Request, serverID string) (*docker.Client, bool) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		writeErr(w, "server not found", "not_found", http.StatusNotFound)
		return nil, false
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		writeErr(w, "key decrypt failed", "internal", http.StatusInternalServerError)
		return nil, false
	}
	sshClient, err := h.pool.GetContext(r.Context(), nexusssh.ServerConfig{
		ID:      server.ID,
		Host:    server.Host,
		Port:    server.Port,
		User:    server.Username,
		PrivKey: privKey,
	})
	if err != nil {
		writeErr(w, "ssh: "+err.Error(), "connection_failed", http.StatusBadGateway)
		return nil, false
	}
	return docker.NewClientContext(r.Context(), sshClient), true
}

func (h *DockerHandler) ListContainers(w http.ResponseWriter, r *http.Request) {
	client, ok := h.dockerClient(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	containers, err := client.List()
	if err != nil {
		writeErr(w, "docker: "+err.Error(), "docker_error", http.StatusBadGateway)
		return
	}
	writeJSON(w, containers, http.StatusOK)
}

func (h *DockerHandler) Start(w http.ResponseWriter, r *http.Request) {
	h.containerAction(w, r, func(c *docker.Client, cid string) error { return c.Start(cid) })
}

func (h *DockerHandler) Stop(w http.ResponseWriter, r *http.Request) {
	h.containerAction(w, r, func(c *docker.Client, cid string) error { return c.Stop(cid) })
}

func (h *DockerHandler) Restart(w http.ResponseWriter, r *http.Request) {
	h.containerAction(w, r, func(c *docker.Client, cid string) error { return c.Restart(cid) })
}

func (h *DockerHandler) Remove(w http.ResponseWriter, r *http.Request) {
	h.containerAction(w, r, func(c *docker.Client, cid string) error { return c.Remove(cid) })
}

func (h *DockerHandler) containerAction(
	w http.ResponseWriter,
	r *http.Request,
	fn func(*docker.Client, string) error,
) {
	if h.supervised {
		writeErr(w, "Use supervised operation controls with a request ID.", "supervised_operation_required", 409)
		return
	}
	client, ok := h.dockerClient(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	if err := fn(client, chi.URLParam(r, "cid")); err != nil {
		writeErr(w, err.Error(), "docker_error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}
