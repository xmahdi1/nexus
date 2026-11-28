package inventory

import (
	"context"
	"crypto/x509"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const (
	nginxSource          = "nginx-config"
	caddySource          = "caddy-config"
	nginxTLSSource       = "nginx-certificates"
	caddyTLSSource       = "caddy-certificates"
	nginxCommand         = "LC_ALL=C python3 -IB - nginx"
	caddyCommand         = "LC_ALL=C python3 -IB - caddy"
	maxProxyRoutes       = 256
	maxProxyCertificates = 32
)

//go:embed proxy_scan.py
var proxyScanner string

var (
	dnsLabel  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	proxyPath = regexp.MustCompile(`^/[a-zA-Z0-9_.~/*-]{0,255}$`)
)

type ProxyRoute struct {
	Engine    string   `json:"engine"`
	Host      string   `json:"host"`
	Path      string   `json:"path"`
	MatchKind string   `json:"match"`
	Port      int      `json:"port"`
	TLS       bool     `json:"tls"`
	Upstreams []string `json:"upstreams" gorm:"serializer:json"`
}

func (route ProxyRoute) source() string {
	if route.Engine == "nginx" {
		return nginxSource
	}
	return caddySource
}

func (route ProxyRoute) key() string {
	return fmt.Sprintf("%s %s %s %s %d %t", route.Engine, route.Host, route.Path, route.MatchKind, route.Port, route.TLS)
}

func (route ProxyRoute) name() string {
	return net.JoinHostPort(route.Host, strconv.Itoa(route.Port)) + route.Path
}

type ProxyCertificate struct {
	Engine            string    `json:"engine"`
	Slot              string    `json:"-" gorm:"-"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	Issuer            string    `json:"issuer,omitempty"`
	FingerprintSHA256 string    `json:"fingerprintSha256"`
	NotBefore         time.Time `json:"notBefore"`
	NotAfter          time.Time `json:"notAfter"`
	NameMatches       bool      `json:"nameMatches"`
}

func (certificate ProxyCertificate) key() string {
	return certificate.Engine + " " + certificate.name() + " " + certificate.Slot
}

func (certificate ProxyCertificate) source() string {
	if certificate.Engine == "nginx" {
		return nginxTLSSource
	}
	return caddyTLSSource
}

func (certificate ProxyCertificate) name() string {
	return net.JoinHostPort(certificate.Host, strconv.Itoa(certificate.Port))
}

type proxyRouteRow struct {
	ResourceID string `gorm:"primaryKey"`
	ProxyRoute
}

func (proxyRouteRow) TableName() string { return "inventory_proxy_routes" }

type proxyCertificateRow struct {
	ResourceID string `gorm:"primaryKey"`
	ProxyCertificate
}

func (proxyCertificateRow) TableName() string { return "inventory_tls_certificates" }

type proxyScan struct {
	routes                               []ProxyRoute
	certificates                         []ProxyCertificate
	routesComplete, certificatesComplete bool
}

type publicCertificate struct {
	Host string
	Port int
	Slot string
	DER  []byte
}

func collectProxy(ctx context.Context, client *ssh.Client, obs *Observation) {
	for _, scanner := range []struct {
		engine, command string
		routesOK, tlsOK *bool
	}{{"nginx", nginxCommand, &obs.NginxOK, &obs.NginxTLSOK},
		{"caddy", caddyCommand, &obs.CaddyOK, &obs.CaddyTLSOK}} {
		raw, err := runInput(ctx, client, scanner.command, strings.NewReader(proxyScanner))
		if err != nil {
			continue
		}
		result := parseProxyScan(raw, scanner.engine)
		obs.ProxyRoutes = append(obs.ProxyRoutes, result.routes...)
		obs.ProxyCertificates = append(obs.ProxyCertificates, result.certificates...)
		*scanner.routesOK, *scanner.tlsOK = result.routesComplete, result.certificatesComplete
	}
}

func parseProxyScan(raw, engine string) proxyScan {
	var result struct {
		Routes       []ProxyRoute        `json:"routes"`
		Certificates []publicCertificate `json:"certificates"`
		Complete     bool                `json:"complete"`
		TLSComplete  bool                `json:"tlsComplete"`
	}
	if !decodeInventoryJSON(raw, &result) || result.Routes == nil || result.Certificates == nil ||
		len(result.Routes) > maxProxyRoutes || len(result.Certificates) > maxProxyCertificates {
		return proxyScan{}
	}
	routes, validRoutes := normalizedProxyRoutes(result.Routes, engine)
	scan := proxyScan{routes: routes, routesComplete: result.Complete && validRoutes,
		certificatesComplete: result.TLSComplete && result.Complete && validRoutes}
	tlsRoutes := make(map[string]bool)
	for _, route := range routes {
		if route.TLS {
			tlsRoutes[net.JoinHostPort(route.Host, strconv.Itoa(route.Port))] = true
		}
	}
	seen := make(map[string]bool)
	for _, raw := range result.Certificates {
		name := net.JoinHostPort(raw.Host, strconv.Itoa(raw.Port))
		if !tlsRoutes[name] || !imageDigest.MatchString(raw.Slot) || len(raw.DER) > 16*1024 {
			scan.certificatesComplete = false
			continue
		}
		certificate, ok := parsePublicCertificate(raw, engine)
		if !ok || seen[certificate.key()] {
			scan.certificatesComplete = false
			continue
		}
		seen[certificate.key()] = true
		scan.certificates = append(scan.certificates, certificate)
	}
	return scan
}

func normalizedProxyRoutes(input []ProxyRoute, engine string) ([]ProxyRoute, bool) {
	valid := make(map[string]ProxyRoute, len(input))
	conflicts := make(map[string]bool)
	complete := true
	for _, route := range input {
		route.Engine = engine
		if !validProxyRoute(route) {
			complete = false
			continue
		}
		slices.Sort(route.Upstreams)
		route.Upstreams = slices.Compact(route.Upstreams)
		key := route.key()
		if conflicts[key] {
			continue
		}
		if previous, exists := valid[key]; exists && !slices.Equal(previous.Upstreams, route.Upstreams) {
			delete(valid, key)
			conflicts[key] = true
			complete = false
			continue
		}
		valid[key] = route
	}
	routes := make([]ProxyRoute, 0, len(valid))
	for _, route := range valid {
		routes = append(routes, route)
	}
	slices.SortFunc(routes, func(a, b ProxyRoute) int { return strings.Compare(a.key(), b.key()) })
	return routes, complete
}

func parsePublicCertificate(raw publicCertificate, engine string) (ProxyCertificate, bool) {
	leaf, err := x509.ParseCertificate(raw.DER)
	if err != nil {
		return ProxyCertificate{}, false
	}
	issuer := leaf.Issuer.CommonName
	if len(issuer) > 255 || strings.ContainsFunc(issuer, unicode.IsControl) {
		issuer = ""
	}
	matches := leaf.VerifyHostname(raw.Host) == nil
	if strings.HasPrefix(raw.Host, "*.") {
		matches = slices.ContainsFunc(leaf.DNSNames, func(name string) bool { return strings.EqualFold(name, raw.Host) })
	}
	return ProxyCertificate{Engine: engine, Slot: raw.Slot, Host: raw.Host, Port: raw.Port, Issuer: issuer,
		FingerprintSHA256: hash(string(leaf.Raw)), NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(), NameMatches: matches}, true
}

func validProxyRoute(route ProxyRoute) bool {
	if route.Engine != "nginx" && route.Engine != "caddy" {
		return false
	}
	if route.MatchKind != "exact" && route.MatchKind != "prefix" && route.MatchKind != "caddy" {
		return false
	}
	if !validProxyHost(route.Host, true) || !proxyPath.MatchString(route.Path) || route.Port < 1 || route.Port > 65535 ||
		len(route.Upstreams) == 0 || len(route.Upstreams) > 8 {
		return false
	}
	for _, address := range route.Upstreams {
		if len(address) > 270 {
			return false
		}
		u, err := url.Parse(address)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || !validProxyHost(u.Hostname(), false) {
			return false
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 || net.JoinHostPort(u.Hostname(), strconv.Itoa(port)) != u.Host {
			return false
		}
	}
	return true
}

func validProxyHost(host string, wildcard bool) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == "" && ip.String() == host
	}
	if len(host) > 253 {
		return false
	}
	if wildcard {
		host = strings.TrimPrefix(host, "*.")
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func proxyRelationships(server, host string, obs Observation, put func(from, to, kind, source string) error) error {
	type endpoint struct {
		engine, host string
		port         int
	}
	certificates := make(map[endpoint][]ProxyCertificate)
	for _, cert := range obs.ProxyCertificates {
		key := endpoint{cert.Engine, cert.Host, cert.Port}
		certificates[key] = append(certificates[key], cert)
	}
	for _, route := range obs.ProxyRoutes {
		id := resourceID(server, "proxy_route", route.key())
		if err := put(host, id, "has_configured_route", route.source()); err != nil {
			return err
		}
		if !route.TLS {
			continue
		}
		for _, cert := range certificates[endpoint{route.Engine, route.Host, route.Port}] {
			target := resourceID(server, "tls_certificate", cert.key())
			if err := put(id, target, "has_certificate_candidate", cert.source()); err != nil {
				return err
			}
		}
	}
	return nil
}
