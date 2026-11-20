package terminal

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	nexusauth "github.com/xmahdi1/nexus/internal/auth"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/httpx"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     httpx.SameOrigin,
}

type clientMsg struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint32 `json:"cols,omitempty"`
	Rows uint32 `json:"rows,omitempty"`
}

type Handler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
	secret []byte
}

func NewHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool, secret []byte) *Handler {
	return &Handler{db: db, encKey: encKey, pool: pool, secret: secret}
}

func ensureHistoryAppend(ctx context.Context, client *ssh.Client) {
	nexusssh.Run(ctx, client, `grep -qF "history -a" ~/.bashrc 2>/dev/null || echo 'export PROMPT_COMMAND="history -a;${PROMPT_COMMAND}"' >> ~/.bashrc`, nil, 5*time.Second)
}

func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	if _, ok := nexusauth.FromContext(r.Context()); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer nexusauth.WatchAccess(r, cancel)()
	setup, setupCancel := context.WithTimeout(ctx, 15*time.Second)
	defer setupCancel()

	var server models.Server
	if err := h.db.First(&server, "id = ?", chi.URLParam(r, "id")).Error; err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		http.Error(w, "key decrypt failed", http.StatusInternalServerError)
		return
	}

	sshClient, err := h.pool.GetContext(setup, nexusssh.ServerConfig{
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

	ensureHistoryAppend(setup, sshClient)

	sess, err := nexusssh.OpenSession(setup, sshClient)
	if err != nil {
		h.pool.Remove(server.ID)
		http.Error(w, "session: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer sess.Close()
	stopSession := context.AfterFunc(ctx, func() { sess.Close() })
	defer stopSession()

	if err := nexusssh.SessionRequest(setup, sess, func() error {
		return sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 38400,
			ssh.TTY_OP_OSPEED: 38400,
		})
	}); err != nil {
		http.Error(w, "pty: "+err.Error(), http.StatusInternalServerError)
		return
	}

	stdinPipe, err := sess.StdinPipe()
	if err != nil {
		http.Error(w, "stdin: "+err.Error(), http.StatusInternalServerError)
		return
	}
	stdoutPipe, err := sess.StdoutPipe()
	if err != nil {
		http.Error(w, "stdout: "+err.Error(), http.StatusInternalServerError)
		return
	}
	stderrPipe, err := sess.StderrPipe()
	if err != nil {
		http.Error(w, "stderr: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := nexusssh.SessionRequest(setup, sess, sess.Shell); err != nil {
		http.Error(w, "shell: "+err.Error(), http.StatusInternalServerError)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("terminal ws upgrade: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(64 << 10)
	stopConnection := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopConnection()

	var mu sync.Mutex
	write := func(data []byte) {
		mu.Lock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		conn.WriteMessage(websocket.BinaryMessage, data)
		mu.Unlock()
	}

	done := make(chan struct{})

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				write(b)
			}
			if err != nil {
				break
			}
		}
		mu.Lock()
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		conn.WriteMessage(websocket.TextMessage, []byte("\r\n[session ended]\r\n"))
		mu.Unlock()
		conn.Close()
		close(done)
	}()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				write(b)
			}
			if err != nil {
				break
			}
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var msg clientMsg
		if err := json.Unmarshal(raw, &msg); err != nil {
			stdinPipe.Write(raw)
			continue
		}
		switch msg.Type {
		case "input":
			stdinPipe.Write([]byte(msg.Data))
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				sess.WindowChange(int(msg.Rows), int(msg.Cols))
			}
		}
	}

	sess.Close()
	<-done
	sess.Wait()
}
