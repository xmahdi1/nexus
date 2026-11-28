package api

import (
	"context"
	"net/http"
	"time"

	"gorm.io/gorm"
)

func healthResponse(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	healthResponse(w, http.StatusOK, `{"status":"ok"}`)
}

// Readiness checks local database access only. It never contacts managed hosts.
// This is not a guarantee that every management operation will succeed.
func readiness(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		sqlDB, err := db.DB()
		if err == nil {
			err = sqlDB.PingContext(ctx)
		}
		if err == nil {
			err = db.WithContext(ctx).Exec("SELECT 1 FROM servers LIMIT 1").Error
		}
		if err != nil {
			healthResponse(w, http.StatusServiceUnavailable, `{"status":"unavailable"}`)
			return
		}
		healthResponse(w, http.StatusOK, `{"status":"ok"}`)
	}
}
