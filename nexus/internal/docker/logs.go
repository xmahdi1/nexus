package docker

import (
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	nexusauth "github.com/xmahdi1/nexus/internal/auth"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/httpx"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

var logsUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin:     httpx.SameOrigin,
}

type LogsHandler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
	secret []byte
}

func NewLogsHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool, secret []byte) *LogsHandler {
	return &LogsHandler{db: db, encKey: encKey, pool: pool, secret: secret}
}

func (h *LogsHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if _, ok := nexusauth.FromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	serverID := chi.URLParam(r, "id")
	containerID := chi.URLParam(r, "cid")

	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		http.Error(w, "key decrypt failed", http.StatusInternalServerError)
		return
	}

	sshClient, err := h.pool.Get(nexusssh.ServerConfig{
		ID:      server.ID,
		Host:    server.Host,
		Port:    server.Port,
		User:    server.Username,
		PrivKey: privKey,
	})
	if err != nil {
		http.Error(w, "ssh: "+err.Error(), http.StatusBadGateway)
		return
	}

	stream, err := NewClient(sshClient).LogsStream(containerID, 200)
	if err != nil {
		http.Error(w, "logs: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer stream.Close()

	conn, err := logsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("logs ws upgrade: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 << 10)
	defer nexusauth.WatchAccess(r, func() { conn.Close(); stream.Close() })()

	var mu sync.Mutex
	write := func(data []byte) {
		mu.Lock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		conn.WriteMessage(websocket.TextMessage, data)
		mu.Unlock()
	}

	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				stream.Close()
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			b := make([]byte, n)
			copy(b, buf[:n])
			write(b)
		}
		if err != nil {
			if err != io.EOF {
				write([]byte("\r\n[stream error: " + err.Error() + "]\r\n"))
			}
			break
		}
	}
	write([]byte("\r\n[stream ended]\r\n"))
}
