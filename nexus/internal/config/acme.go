package config

import (
	"errors"
	"net/url"
	"path"
	"strings"
)

const DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// ACMECAFile names a CA bundle on the managed Linux host, not on the Nexus host.
type ACMEConfig struct {
	DirectoryURL string
	CAFile       string
}

func (settings ACMEConfig) Validate() error {
	if settings.DirectoryURL == "" && settings.CAFile == "" {
		return nil
	}
	directory, err := url.Parse(settings.DirectoryURL)
	if err != nil || len(settings.DirectoryURL) > 2048 || directory.Scheme != "https" || directory.Hostname() == "" || directory.User != nil || directory.RawQuery != "" || directory.Fragment != "" || strings.ContainsAny(settings.DirectoryURL, "\r\n\x00") {
		return errors.New("NEXUS_ACME_DIRECTORY_URL must be an HTTPS directory URL without credentials, query or fragment")
	}
	if settings.CAFile != "" && (!path.IsAbs(settings.CAFile) || path.Clean(settings.CAFile) != settings.CAFile || len(settings.CAFile) > 4096 || strings.ContainsAny(settings.CAFile, "\r\n\x00")) {
		return errors.New("NEXUS_ACME_CA_FILE must be a clean absolute CA bundle path on the managed host")
	}
	return nil
}
