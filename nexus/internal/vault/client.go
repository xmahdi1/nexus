// Package vault implements a deliberately narrow, typed Vault adapter.
package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Profile contains public connection metadata only. Tokens are never persisted.
type Profile struct {
	ServerID  string `json:"serverId" gorm:"primaryKey"`
	Port      int    `json:"port"`
	TLSName   string `json:"tlsName" gorm:"column:tls_name"`
	CAPEM     string `json:"caPem" gorm:"column:ca_pem"`
	Namespace string `json:"namespace"`
}

func (Profile) TableName() string { return "vault_connections" }

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
var namespacePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*/?$`)

func (p Profile) Validate() error {
	if p.Port < 1024 || p.Port > 65535 || !namePattern.MatchString(p.TLSName) || len(p.CAPEM) > 65536 || len(p.Namespace) > 256 || (p.Namespace != "" && !namespacePattern.MatchString(p.Namespace)) {
		return errors.New("invalid Vault connection settings")
	}
	if p.CAPEM != "" {
		pool := x509.NewCertPool()
		remaining := []byte(p.CAPEM)
		for len(strings.TrimSpace(string(remaining))) > 0 {
			remaining = []byte(strings.TrimSpace(string(remaining)))
			if !strings.HasPrefix(string(remaining), "-----BEGIN CERTIFICATE-----") {
				return errors.New("only CA certificates may be saved")
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return errors.New("only CA certificates may be saved")
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return errors.New("invalid Vault CA certificate")
			}
			remaining = rest
		}
		if !pool.AppendCertsFromPEM([]byte(p.CAPEM)) {
			return errors.New("invalid Vault CA certificate")
		}
	}
	return nil
}

type Health struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Standby     bool `json:"standby"`
	Status      int  `json:"status"`
}
type Mount struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Version     string `json:"version"`
}
type Observation struct {
	Health       Health  `json:"health"`
	Mounts       []Mount `json:"mounts"`
	MountsStatus string  `json:"mountsStatus"`
}
type Dial func(context.Context, string, string) (net.Conn, error)

// NewClient only dials the managed host's loopback listener through the supplied
// verified SSH connection. Neither request paths nor destinations come from users.
func NewClient(p Profile, dial Dial) (*http.Client, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if dial == nil {
		return nil, errors.New("Vault transport unavailable")
	}
	var roots *x509.CertPool
	if p.CAPEM != "" {
		roots = x509.NewCertPool()
		roots.AppendCertsFromPEM([]byte(p.CAPEM))
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: p.TLSName}, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port)))
		}}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func read(ctx context.Context, client *http.Client, p Profile, path, token string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+p.TLSName+path, nil)
	if err != nil {
		return 0, errors.New("Vault request failed")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if p.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", p.Namespace)
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, errors.New("Vault TLS or transport verification failed")
	}
	defer response.Body.Close()
	// Never return raw upstream errors: some servers reflect request credentials.
	if response.StatusCode != 200 && path != "/v1/sys/health" {
		return response.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil || len(data) > 1048576 {
		return 0, errors.New("Vault response exceeded bounds or was incomplete")
	}
	defer clear(data)
	if json.Unmarshal(data, out) != nil {
		return 0, errors.New("Vault returned an invalid response")
	}
	return response.StatusCode, nil
}

func Inspect(ctx context.Context, client *http.Client, p Profile, token string) (Observation, error) {
	result := Observation{Mounts: []Mount{}, MountsStatus: "token_required"}
	if len(token) > 8192 || strings.ContainsAny(token, "\r\n\x00") {
		return result, errors.New("invalid Vault token")
	}
	var health struct {
		Initialized *bool `json:"initialized"`
		Sealed      *bool `json:"sealed"`
		Standby     *bool `json:"standby"`
	}
	code, err := read(ctx, client, p, "/v1/sys/health", "", &health)
	if err != nil {
		return result, err
	}
	if health.Initialized == nil || health.Sealed == nil || health.Standby == nil {
		return result, errors.New("Vault returned incomplete health data")
	}
	result.Health.Initialized = *health.Initialized
	result.Health.Sealed = *health.Sealed
	result.Health.Standby = *health.Standby
	result.Health.Status = code
	switch code {
	case 200, 429, 472, 473, 501, 503, 530:
	default:
		return result, errors.New("unexpected Vault health status")
	}
	if !result.Health.Initialized || result.Health.Sealed {
		result.MountsStatus = "unavailable"
		return result, nil
	}
	if token == "" {
		return result, nil
	}
	allowed, err := checkToken(ctx, client, p, token)
	if err != nil {
		return result, err
	}
	if !allowed {
		result.MountsStatus = "permission_denied"
		return result, nil
	}
	var mounts struct {
		Data map[string]struct {
			Type        string            `json:"type"`
			Description string            `json:"description"`
			Options     map[string]string `json:"options"`
		} `json:"data"`
	}
	code, err = read(ctx, client, p, "/v1/sys/mounts", token, &mounts)
	if err != nil {
		return result, err
	}
	if code == 403 || code == 401 {
		result.MountsStatus = "permission_denied"
		return result, nil
	}
	if code != 200 {
		return result, errors.New("Vault engine inventory unavailable")
	}
	if len(mounts.Data) > 1024 {
		return result, errors.New("Vault engine inventory exceeded bounds")
	}
	for path, mount := range mounts.Data {
		if len(path) > 1024 || len(mount.Type) > 128 || len(mount.Description) > 2048 || len(mount.Options["version"]) > 32 {
			return result, errors.New("invalid Vault engine metadata")
		}
		result.Mounts = append(result.Mounts, Mount{Path: strings.ReplaceAll(path, token, "[redacted]"), Type: strings.ReplaceAll(mount.Type, token, "[redacted]"), Description: strings.ReplaceAll(mount.Description, token, "[redacted]"), Version: strings.ReplaceAll(mount.Options["version"], token, "[redacted]")})
	}
	sort.Slice(result.Mounts, func(i, j int) bool { return result.Mounts[i].Path < result.Mounts[j].Path })
	result.MountsStatus = "ok"
	return result, nil
}
