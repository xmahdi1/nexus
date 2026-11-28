package static

import (
	"io/fs"
	"net/http"
	"os"
	"strings"
)

var blockedNames = map[string]bool{
	".env":     true,
	"nexus.db": true,
	".git":     true,
}

func Handler(staticDir string) http.Handler {
	if staticDir == "" {
		return nil
	}
	return spaHandler(os.DirFS(staticDir))
}

func DefaultHandler(staticDir string) http.Handler {
	if h := Handler(staticDir); h != nil {
		return h
	}
	return embeddedHandler()
}

func isBlocked(name string) bool {
	for _, seg := range strings.Split(name, "/") {
		if seg == "" {
			continue
		}
		lower := strings.ToLower(seg)
		for _, suffix := range []string{".db", ".db-wal", ".db-shm", ".sqlite", ".sqlite3", ".pem", ".key"} {
			if strings.HasSuffix(lower, suffix) {
				return true
			}
		}
		if strings.HasPrefix(seg, ".") || blockedNames[seg] {
			return true
		}
	}
	return false
}

func spaHandler(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if isBlocked(name) {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(fsys, name); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		// FileServer redirects /index.html to ./; serving the filesystem root
		// internally preserves the browser history route without a redirect.
		r2.URL.Path = "/"
		r2.URL.RawPath = ""
		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r2)
	})
}
