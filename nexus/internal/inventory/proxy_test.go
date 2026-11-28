package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
)

func TestProxyInventoryPreservesCertificateOnIncompleteScan(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture CA"},
		DNSNames: []string{"app.example.test"}, NotBefore: now, NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	route := ProxyRoute{Host: "app.example.test", Port: 443, TLS: true, Path: "/", MatchKind: "prefix",
		Upstreams: []string{"http://127.0.0.1:8080"}}
	cert := publicCertificate{Host: route.Host, Port: route.Port, Slot: hash("fixture slot"), DER: der}
	raw, err := json.Marshal(map[string]any{"routes": []ProxyRoute{route}, "certificates": []publicCertificate{cert},
		"complete": true, "tlsComplete": true})
	if err != nil {
		t.Fatal(err)
	}
	expected := parseProxyScan(string(raw), "nginx")
	if !expected.routesComplete || !expected.certificatesComplete || len(expected.certificates) != 1 ||
		!expected.certificates[0].NameMatches || !expected.certificates[0].NotAfter.Equal(leaf.NotAfter) {
		t.Fatal("public cert was not decoded", expected)
	}
	service := fixture(t)
	obs := observation()
	obs.ProxyRoutes, obs.ProxyCertificates = expected.routes, expected.certificates
	service.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	actor := authorization.LegacyPrincipal
	scan := func(status string) {
		t.Helper()
		run, err := service.Discover(context.Background(), actor, "dev")
		if err != nil || run.Status != status {
			t.Fatal(run, err)
		}
	}
	scan("succeeded")
	obs.ProxyRoutes[0].Upstreams = []string{"http://127.0.0.1:8081"}
	obs.ProxyCertificates = nil
	obs.NginxTLSOK = false
	scan("partial")
	report, err := service.Document(context.Background(), actor, "dev")
	if err != nil || !strings.Contains(report.Markdown, "http://127.0.0.1:8081") ||
		!strings.Contains(report.Markdown, "nginx-certificates, stale") ||
		strings.Contains(report.Markdown, "fixture slot") {
		t.Fatal("updated route or stale cert missing from report", err)
	}
	links, err := service.Relationships(actor, "dev", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links.Items {
		if link.Kind == "has_certificate_candidate" && link.DataState == "stale" {
			return
		}
	}
	t.Fatal("certificate relationship was not preserved")
}

func TestProxyProjectionRejectsCredentialsAndUnexpectedRoutes(t *testing.T) {
	raw := `{"routes":[{"host":"app.example.test","path":"/","match":"caddy","port":443,"tls":true,
		"upstreams":["https://user:secret@backend:8443"]}],"certificates":[],"complete":true,"tlsComplete":true}`
	scan := parseProxyScan(raw, "caddy")
	if scan.routesComplete || scan.certificatesComplete || len(scan.routes) != 0 {
		t.Fatal("unsafe route was admitted", scan)
	}
}
