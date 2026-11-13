package metrics

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	nexusauth "github.com/xmahdi1/nexus/internal/auth"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/httpx"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  512,
	WriteBufferSize: 4096,
	CheckOrigin:     httpx.SameOrigin,
}

func (h *Handler) Stream(w http.ResponseWriter, r *http.Request) {
	if _, ok := nexusauth.FromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var server models.Server
	if err := h.db.First(&server, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("metrics ws upgrade: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 << 10)
	defer nexusauth.WatchAccess(r, func() { conn.Close() })()

	gone := make(chan struct{})
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				close(gone)
				return
			}
		}
	}()

	push := func() bool {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
		if err != nil {
			return false
		}
		sshClient, err := h.pool.Get(nexusssh.ServerConfig{
			ID: server.ID, Host: server.Host, Port: server.Port,
			User: server.Username, PrivKey: privKey,
		})
		if err != nil {
			conn.WriteJSON(map[string]string{"error": err.Error()})
			return true
		}
		sess, err := sshClient.NewSession()
		if err != nil {
			h.pool.Remove(server.ID)
			conn.WriteJSON(map[string]string{"error": "session failed"})
			return true
		}
		defer sess.Close()
		workDone := make(chan struct{})
		go func() {
			select {
			case <-gone:
				sess.Close()
			case <-workDone:
			}
		}()
		defer close(workDone)

		out, err := sess.Output(metricsScript)
		if err != nil && len(out) == 0 {
			conn.WriteJSON(map[string]string{"error": "collection failed"})
			return true
		}
		data, _ := json.Marshal(parse(string(out), server.ID))
		return conn.WriteMessage(websocket.TextMessage, data) == nil
	}

	if !push() {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-gone:
			return
		case <-ticker.C:
			if !push() {
				return
			}
		}
	}
}
