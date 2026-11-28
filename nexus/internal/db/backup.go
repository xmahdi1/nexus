package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// Backup snapshots an existing database, including committed WAL data. The
// destination must not exist. It does not load configuration or start workers.
func Backup(source, destination string) (err error) {
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	if info, statErr := os.Stat(source); statErr != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("source must be an existing regular database file")
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		os.Remove(destination)
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(destination)
		}
	}()
	uri := url.URL{Scheme: "file", Path: source, RawQuery: "mode=ro&_busy_timeout=5000"}
	conn, err := sql.Open("sqlite3", uri.String())
	if err != nil {
		return err
	}
	defer conn.Close()
	// VACUUM INTO uses SQLite's consistent snapshot and parameter binding.
	if _, err = conn.Exec("VACUUM INTO ?", destination); err != nil {
		return err
	}
	return nil
}
