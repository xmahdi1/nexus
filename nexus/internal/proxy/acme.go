package proxy

import (
	"github.com/xmahdi1/nexus/internal/config"
	"strings"
)

// Wrap the runner so every Certbot operation, including installation, receives
// the same CA policy. Validation fails before any route write or remote command.
func acmeCommandPolicy(settings config.ACMEConfig) (func(string) string, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	directory := settings.DirectoryURL
	if directory == "" {
		directory = config.DefaultACMEDirectory
	}
	environment := ""
	if settings.CAFile != "" {
		environment = "env REQUESTS_CA_BUNDLE=" + shellQuote(settings.CAFile) + " "
	}
	return func(command string) string {
		// All adapter commands below are authored by Nexus. Limit rewriting to the
		// executable token rather than plugin names or unrelated command arguments.
		return strings.ReplaceAll(command, "certbot ", environment+"certbot --server "+shellQuote(directory)+" ")
	}, nil
}
