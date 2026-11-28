package config

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestACMEConfigValidation(t *testing.T) {
	for _, settings := range []ACMEConfig{{}, {DirectoryURL: DefaultACMEDirectory}, {DirectoryURL: "https://127.0.0.1:14000/dir", CAFile: "/private/ca.pem"}} {
		if err := settings.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, settings := range []ACMEConfig{
		{CAFile: "/private/ca.pem"}, {DirectoryURL: "http://ca.test/dir"},
		{DirectoryURL: "https://user:password@ca.test/dir"}, {DirectoryURL: "https://ca.test/dir?token=secret"},
		{DirectoryURL: "https://ca.test/dir#fragment"}, {DirectoryURL: "https:///dir"},
		{DirectoryURL: DefaultACMEDirectory, CAFile: "relative.pem"},
		{DirectoryURL: DefaultACMEDirectory, CAFile: "/private/../ca.pem"},
		{DirectoryURL: DefaultACMEDirectory, CAFile: "/private/ca\n.pem"},
	} {
		if err := settings.Validate(); err == nil {
			t.Fatalf("invalid settings accepted: %#v", settings)
		}
	}
}

func TestLoadACMEPolicy(t *testing.T) {
	t.Setenv("NEXUS_PASSWORD_HASH", "fixture")
	t.Setenv("NEXUS_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("NEXUS_ACME_DIRECTORY_URL", "https://ca.nexus.test/dir")
	t.Setenv("NEXUS_ACME_CA_FILE", "/private/ca.pem")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACME.DirectoryURL != "https://ca.nexus.test/dir" || cfg.ACME.CAFile != "/private/ca.pem" {
		t.Fatal("ACME environment ignored")
	}
	t.Setenv("NEXUS_ACME_DIRECTORY_URL", "http://ca.nexus.test/dir")
	if _, err := Load(); err == nil {
		t.Fatal("insecure configured directory accepted")
	}
}
