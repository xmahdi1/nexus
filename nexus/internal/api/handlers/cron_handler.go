package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type CronHandler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

type CronJob struct {
	Index    int    `json:"index"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Raw      string `json:"raw"`
}

func NewCronHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *CronHandler {
	return &CronHandler{db: db, encKey: encKey, pool: pool}
}

func parseCrontab(raw string) []CronJob {
	var jobs []CronJob
	idx := 0
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		job := CronJob{Index: idx, Raw: t}
		if strings.HasPrefix(t, "@") {
			parts := strings.SplitN(t, " ", 2)
			job.Schedule = parts[0]
			if len(parts) > 1 {
				job.Command = strings.TrimSpace(parts[1])
			}
		} else {
			parts := strings.Fields(t)
			if len(parts) >= 6 {
				job.Schedule = strings.Join(parts[:5], " ")
				job.Command = strings.Join(parts[5:], " ")
			} else {
				job.Command = t
			}
		}
		jobs = append(jobs, job)
		idx++
	}
	if jobs == nil {
		jobs = []CronJob{}
	}
	return jobs
}

func (h *CronHandler) List(w http.ResponseWriter, r *http.Request) {
	run, err := h.sshRun(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "ssh_error", http.StatusBadGateway)
		return
	}
	out, _ := run("crontab -l 2>/dev/null || true")
	writeJSON(w, parseCrontab(strings.TrimSpace(out)), http.StatusOK)
}

func (h *CronHandler) Add(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Schedule string `json:"schedule"`
		Command  string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Schedule == "" || body.Command == "" {
		writeErr(w, "schedule and command required", "bad_request", http.StatusBadRequest)
		return
	}
	run, err := h.sshRun(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "ssh_error", http.StatusBadGateway)
		return
	}
	line := fmt.Sprintf("%s %s", body.Schedule, body.Command)
	if _, err := run(fmt.Sprintf("(crontab -l 2>/dev/null; echo %s) | crontab -", cronQuote(line))); err != nil {
		writeErr(w, "failed to add job: "+err.Error(), "exec_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"ok": "added"}, http.StatusOK)
}

func (h *CronHandler) Delete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Raw string `json:"raw"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Raw == "" {
		writeErr(w, "raw line required", "bad_request", http.StatusBadRequest)
		return
	}
	run, err := h.sshRun(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "ssh_error", http.StatusBadGateway)
		return
	}
	if _, err := run(fmt.Sprintf("crontab -l 2>/dev/null | grep -vF %s | crontab -", cronQuote(body.Raw))); err != nil {
		writeErr(w, "failed to delete job", "exec_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"ok": "deleted"}, http.StatusOK)
}

func cronQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func (h *CronHandler) sshRun(serverID string) (func(string) (string, error), error) {
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
