package handlers

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	"github.com/xmahdi1/nexus/internal/monitor"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	gossh "golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

type ServersHandler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
	mon    *monitor.Monitor
}

func NewServersHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool, mon *monitor.Monitor) *ServersHandler {
	return &ServersHandler{db: db, encKey: encKey, pool: pool, mon: mon}
}

func (h *ServersHandler) GenerateKey(w http.ResponseWriter, r *http.Request) {
	kp, err := nexusssh.GenerateKeyPair()
	if err != nil {
		writeErr(w, "failed to generate key pair", "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"publicKey": kp.PublicKey, "privateKey": kp.PrivateKey}, http.StatusOK)
}

func (h *ServersHandler) List(w http.ResponseWriter, r *http.Request) {
	var servers []models.Server
	if err := h.db.Order("created_at desc").Find(&servers).Error; err != nil {
		writeErr(w, "database error", "internal", http.StatusInternalServerError)
		return
	}
	if servers == nil {
		servers = []models.Server{}
	}
	writeJSON(w, servers, http.StatusOK)
}

func (h *ServersHandler) Get(w http.ResponseWriter, r *http.Request) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		writeErr(w, "server not found", "not_found", http.StatusNotFound)
		return
	}
	writeJSON(w, server, http.StatusOK)
}

func (h *ServersHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		Host       string `json:"host"`
		Port       int    `json:"port"`
		Username   string `json:"username"`
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
		Tags       string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	if body.Name == "" || body.Host == "" || body.Username == "" || body.PrivateKey == "" {
		writeErr(w, "name, host, username and privateKey are required", "bad_request", http.StatusBadRequest)
		return
	}
	if body.Port == 0 {
		body.Port = 22
	}

	encKey, err := nexuscrypto.Encrypt(h.encKey, []byte(body.PrivateKey))
	if err != nil {
		writeErr(w, "failed to encrypt private key", "internal", http.StatusInternalServerError)
		return
	}

	fingerprint := ""
	if body.PublicKey != "" {
		if pub, _, _, _, err := gossh.ParseAuthorizedKey([]byte(body.PublicKey)); err == nil {
			fingerprint = gossh.FingerprintSHA256(pub)
		}
	}

	server := models.Server{
		ID:            newUUID(),
		Name:          body.Name,
		Host:          body.Host,
		Port:          body.Port,
		Username:      body.Username,
		PublicKey:     body.PublicKey,
		PrivateKeyEnc: encKey,
		Fingerprint:   fingerprint,
		Tags:          normalizeTags(body.Tags),
	}
	if err := h.db.Create(&server).Error; err != nil {
		writeErr(w, "failed to save server", "internal", http.StatusInternalServerError)
		return
	}
	writeJSON(w, server, http.StatusCreated)
}

func (h *ServersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result := h.db.Delete(&models.Server{}, "id = ?", id)
	if result.Error != nil {
		writeErr(w, "database error", "internal", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected == 0 {
		writeErr(w, "server not found", "not_found", http.StatusNotFound)
		return
	}
	h.pool.Remove(id)
	h.mon.RemoveServer(id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *ServersHandler) TestConnection(w http.ResponseWriter, r *http.Request) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		writeErr(w, "server not found", "not_found", http.StatusNotFound)
		return
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		writeErr(w, "failed to decrypt private key", "internal", http.StatusInternalServerError)
		return
	}
	start := time.Now()
	_, dialErr := h.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	latency := time.Since(start).Milliseconds()
	if dialErr != nil {
		writeJSON(w, map[string]any{"ok": false, "latencyMs": latency, "error": dialErr.Error()}, http.StatusOK)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "latencyMs": latency}, http.StatusOK)
}

func (h *ServersHandler) UpdateTags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var body struct {
		Tags string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid request body", "bad_request", http.StatusBadRequest)
		return
	}
	result := h.db.Model(&models.Server{}).Where("id = ?", id).Update("tags", normalizeTags(body.Tags))
	if result.Error != nil {
		writeErr(w, "database error", "internal", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected == 0 {
		writeErr(w, "server not found", "not_found", http.StatusNotFound)
		return
	}
	var server models.Server
	h.db.First(&server, "id = ?", id)
	writeJSON(w, server, http.StatusOK)
}

func normalizeTags(raw string) string {
	if raw == "" {
		return ""
	}
	seen := map[string]bool{}
	var result []string
	for _, t := range strings.Split(raw, ",") {
		t = strings.TrimSpace(strings.ToLower(t))
		if t != "" && !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return strings.Join(result, ",")
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
