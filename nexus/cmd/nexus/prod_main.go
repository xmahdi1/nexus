//go:build production

package main

import (
	"net/http"

	"github.com/xmahdi1/nexus/internal/config"
)

func init() {
	mountFrontend = func(r http.Handler, _ *config.Config) http.Handler {
		return r
	}
}
