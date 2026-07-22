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
		r2.URL.Path = "/index.html"
		fileServer.ServeHTTP(w, r2)
	})
}
