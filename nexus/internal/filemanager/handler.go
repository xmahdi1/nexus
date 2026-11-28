package filemanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
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

func (h *Handler) getSFTP(r *http.Request, serverID string) (*fileSession, error) {
	var server models.Server
	if err := h.db.First(&server, "id = ?", serverID).Error; err != nil {
		return nil, fmt.Errorf("server not found")
	}
	privKey, err := nexuscrypto.Decrypt(h.encKey, server.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("key decrypt failed")
	}
	sshClient, err := h.pool.GetContext(r.Context(), nexusssh.ServerConfig{
		ID: server.ID, Host: server.Host, Port: server.Port,
		User: server.Username, PrivKey: privKey,
	})
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	ctx, cancel := context.WithTimeout(r.Context(), transferTimeout)
	stopWatch := auth.WatchAccess(r, cancel)
	client, err := openSFTP(ctx, sshClient)
	if err != nil {
		stopWatch()
		cancel()
		return nil, err
	}
	closeSession := client.closeSession
	client.closeSession = func() { stopWatch(); cancel(); closeSession() }
	return client, nil
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}
	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
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
	if len(entries) > 10000 {
		writeErr(w, "Directory contains more than 10000 entries.", "directory_limit", http.StatusRequestEntityTooLarge)
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
	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
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
	n, readErr := io.ReadFull(f, buf)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		writeErr(w, "Could not read preview.", "read_error", http.StatusBadGateway)
		return
	}
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
	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
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
	if err := f.Close(); err != nil {
		writeErr(w, "Could not finish file write.", "write_error", http.StatusBadGateway)
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
	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
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

	stat, err := f.Stat()
	if err != nil {
		writeErr(w, "Could not read file metadata.", "stat_error", http.StatusBadGateway)
		return
	}
	if !stat.Mode().IsRegular() || stat.Size() < 0 || stat.Size() > maxTransferBytes {
		writeErr(w, "Downloads are limited to regular files of at most 64 MiB.", "download_limit", http.StatusRequestEntityTooLarge)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", stat.Size()))
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, path.Base(filePath)))
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.CopyN(w, f, stat.Size()); err != nil {
		audit.MarkFailed(r.Context())
	}
}

func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	// ParseMultipartForm's memory limit spills larger parts to disk; it does
	// not limit the request. Bound the stream before any form parsing or SSH.
	const maxUploadBytes = maxTransferBytes + (1 << 20)
	if r.ContentLength > maxUploadBytes {
		writeErr(w, "Uploads are limited to 64 MiB plus multipart overhead.", "upload_limit", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			writeErr(w, "Uploads are limited to 64 MiB plus multipart overhead.", "upload_limit", http.StatusRequestEntityTooLarge)
			return
		}
		writeErr(w, "failed to parse upload", "bad_request", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, "file field required", "bad_request", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if header.Size < 0 || header.Size > maxTransferBytes {
		writeErr(w, "Uploads are limited to 64 MiB.", "upload_limit", http.StatusRequestEntityTooLarge)
		return
	}

	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
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
	if err := dest.Close(); err != nil {
		writeErr(w, "Could not finish upload.", "upload_error", http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "path": destPath}, http.StatusOK)
}

func removeAll(client *sftp.Client, p string) error {
	remaining := 10000
	return removeTree(client, p, &remaining)
}
func removeTree(client *sftp.Client, p string, remaining *int) error {
	if *remaining <= 0 {
		return fmt.Errorf("recursive deletion exceeds 10000 entries; inspect partial result")
	}
	*remaining -= 1

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
		if err := removeTree(client, path.Join(p, e.Name()), remaining); err != nil {
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
	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, err.Error(), "sftp_error", http.StatusBadGateway)
		return
	}
	defer client.Close()

	if path.Clean(filePath) == "/" || path.Clean(filePath) == "." {
		writeErr(w, "Refusing to delete a filesystem root.", "unsafe_path", http.StatusBadRequest)
		return
	}
	if err := removeAll(client.Client, filePath); err != nil {
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
	client, err := h.getSFTP(r, chi.URLParam(r, "id"))
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
