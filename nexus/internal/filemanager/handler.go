package filemanager

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/sftp"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"github.com/xmahdi1/nexus/internal/models"
	nexusssh "github.com/xmahdi1/nexus/internal/ssh"
	"gorm.io/gorm"
)

type FileEntry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	IsDir   bool      `json:"isDir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	Mode    string    `json:"mode"`
}

type Handler struct {
	db     *gorm.DB
	encKey []byte
	pool   *nexusssh.Pool
}

func NewHandler(db *gorm.DB, encKey []byte, pool *nexusssh.Pool) *Handler {
	return &Handler{db: db, encKey: encKey, pool: pool}
}

func (h *Handler) getSFTP(serverID string) (*sftp.Client, error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	sshClient, err := h.pool.Get(nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return sftp.NewClient(sshClient)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}
	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	entries, err := client.ReadDir(dirPath)
	if err != nil {
		writeErr(w, "failed to list directory: "+err.Error(), "list_error", http.StatusInternalServerError)
		return
	}
	result := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		result = append(result, FileEntry{
			Name:    e.Name(),
			Path:    path.Join(dirPath, e.Name()),
			IsDir:   e.IsDir(),
			Size:    e.Size(),
			ModTime: e.ModTime(),
			Mode:    e.Mode().String(),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return result[i].Name < result[j].Name
	})
	writeJSON(w, map[string]any{"path": dirPath, "entries": result}, http.StatusOK)
}

func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		writeErr(w, "path is required", "bad_request", http.StatusBadRequest)
		return
	}
	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	f, err := client.Open(filePath)
	if err != nil {
		writeErr(w, "failed to open file: "+err.Error(), "open_error", http.StatusNotFound)
		return
	}
	defer f.Close()

	const maxBytes = 256 * 1024
	buf := make([]byte, maxBytes+1)
	n, _ := io.ReadFull(f, buf)
	truncated := n > maxBytes
	if truncated {
		n = maxBytes
	}
	data := buf[:n]
	if !utf8.Valid(data) {
		writeJSON(w, map[string]any{"content": "", "truncated": false, "binary": true}, http.StatusOK)
		return
	}
	writeJSON(w, map[string]any{"content": string(data), "truncated": truncated, "binary": false}, http.StatusOK)
}

func (h *Handler) Write(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		writeErr(w, "path is required", "bad_request", http.StatusBadRequest)
		return
	}
	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	f, err := client.Create(body.Path)
	if err != nil {
		writeErr(w, "failed to open file for writing: "+err.Error(), "write_error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.Write([]byte(body.Content)); err != nil {
		writeErr(w, "failed to write file: "+err.Error(), "write_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		writeErr(w, "path is required", "bad_request", http.StatusBadRequest)
		return
	}
	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	f, err := client.Open(filePath)
	if err != nil {
		writeErr(w, "failed to open file: "+err.Error(), "open_error", http.StatusNotFound)
		return
	}
	defer f.Close()

	if stat, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, path.Base(filePath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, "failed to parse upload", "bad_request", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, "file field required", "bad_request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	destPath := path.Join(dirPath, header.Filename)
	dest, err := client.Create(destPath)
	if err != nil {
		writeErr(w, "failed to create file: "+err.Error(), "create_error", http.StatusInternalServerError)
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		writeErr(w, "upload failed: "+err.Error(), "upload_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "path": destPath}, http.StatusOK)
}

func removeAll(client *sftp.Client, p string) error {
	info, err := client.Lstat(p)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return client.Remove(p)
	}
	entries, err := client.ReadDir(p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := removeAll(client, path.Join(p, e.Name())); err != nil {
			return err
		}
	}
	return client.RemoveDirectory(p)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		writeErr(w, "path is required", "bad_request", http.StatusBadRequest)
		return
	}
	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	if err := removeAll(client, filePath); err != nil {
		writeErr(w, "failed to delete: "+err.Error(), "delete_error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Mkdir(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		writeErr(w, "path is required", "bad_request", http.StatusBadRequest)
		return
	}
	client, err := h.getSFTP(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	if err := client.MkdirAll(body.Path); err != nil {
		writeErr(w, "failed to create directory: "+err.Error(), "mkdir_error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"ok": true}, http.StatusOK)
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg, code string, status int) {
	writeJSON(w, map[string]string{"error": msg, "code": code}, status)
}
