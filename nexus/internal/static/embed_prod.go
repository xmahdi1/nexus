//go:build production

package static

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

func EmbeddedHandler() http.Handler {
	fsys, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("embedded dist not found: " + err.Error())
	}
	return spaHandler(fsys)
}

func embeddedHandler() http.Handler {
	return EmbeddedHandler()
}
