//go:build !production

package static

import "net/http"

func embeddedHandler() http.Handler { return nil }
