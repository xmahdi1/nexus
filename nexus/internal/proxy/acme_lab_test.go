package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// Protocol fixture only: it does not certify the production Certbot/Cloudflare
// adapter or enable unattended renewal. Run through scripts/acme_lab.py.
func TestDisposableACMEDNS01(t *testing.T) {
	directory := os.Getenv("NEXUS_ACME_LAB_DIRECTORY")
	if directory == "" {
		t.Skip("isolated Pebble lab not configured")
	}
	management, dns := os.Getenv("NEXUS_ACME_LAB_MANAGEMENT"), os.Getenv("NEXUS_ACME_LAB_DNS")
	for _, value := range []string{directory, management} {
		if !strings.HasPrefix(value, "https://127.0.0.1:") && !strings.HasPrefix(value, "http://127.0.0.1:") {
			t.Fatal("lab requires loopback endpoints")
		}
	}
	ca, err := os.ReadFile(os.Getenv("NEXUS_ACME_LAB_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid private CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	compat := &labOrderTransport{base: transport}
	client := &http.Client{Transport: compat, Timeout: 15 * time.Second}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &acme.Client{Key: key, DirectoryURL: directory, HTTPClient: client}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := issuer.Register(ctx, &acme.Account{Contact: []string{"mailto:fixture@example.test"}}, acme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	manage := func(path, host, value string) error {
		body, _ := json.Marshal(map[string]string{"host": host, "value": value})
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, management+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode != 200 {
			return fmt.Errorf("challenge fixture status %d", response.StatusCode)
		}
		return nil
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dns)
	}}
	unrelated := "_acme-challenge.unrelated.test."
	if err := manage("/set-txt", unrelated, "preserve-me"); err != nil {
		t.Fatal(err)
	}
	defer manage("/clear-txt", unrelated, "")
	for _, mode := range []string{"issue", "renew", "missing-txt", "dns-failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			name := mode + ".nexus.test"
			if mode == "renew" {
				name = "issue.nexus.test"
			}
			order, err := issuer.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: name}})
			if err != nil {
				t.Fatal(err)
			}
			host := "_acme-challenge." + name + "."
			if mode == "dns-failure" {
				if err := manage("/set-servfail", host, ""); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := manage("/clear-servfail", host, ""); err != nil {
						t.Error(err)
					}
				}()
			}
			for _, url := range order.AuthzURLs {
				authorization, err := issuer.GetAuthorization(ctx, url)
				if err != nil {
					t.Fatal(err)
				}
				if authorization.Status == acme.StatusValid {
					continue
				}
				var challenge *acme.Challenge
				for _, candidate := range authorization.Challenges {
					if candidate.Type == "dns-01" {
						challenge = candidate
					}
				}
				if challenge == nil {
					t.Fatal("missing DNS challenge")
				}
				value, err := issuer.DNS01ChallengeRecord(challenge.Token)
				if err != nil {
					t.Fatal(err)
				}
				if mode != "missing-txt" && mode != "dns-failure" {
					if err := manage("/set-txt", host, value); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if err := manage("/clear-txt", host, ""); err != nil {
							t.Error("cleanup", err)
						}
					}()
					records, err := resolver.LookupTXT(ctx, host)
					if err != nil || len(records) != 1 || records[0] != value {
						t.Fatal("TXT not propagated", err)
					}
				}
				if mode == "cancel" {
					canceled, stop := context.WithCancel(ctx)
					stop()
					if _, err := issuer.Accept(canceled, challenge); err == nil {
						t.Fatal("canceled challenge succeeded")
					}
					return
				}
				if _, err := issuer.Accept(ctx, challenge); err != nil {
					t.Fatal(err)
				}
				_, err = issuer.WaitAuthorization(ctx, url)
				if mode == "missing-txt" || mode == "dns-failure" {
					var denied *acme.AuthorizationError
					if !errors.As(err, &denied) {
						t.Fatalf("expected validation rejection, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = issuer.WaitOrder(ctx, order.URI)
			if err != nil {
				t.Fatal(err)
			}
			certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, certificateKey)
			if err != nil {
				t.Fatal(err)
			}
			compat.finalize, compat.order = order.FinalizeURL, order.URI
			chain, _, err := issuer.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(chain[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := certificate.VerifyHostname(name); err != nil {
				t.Fatal(err)
			}
		})
		records, err := resolver.LookupTXT(ctx, unrelated)
		if err != nil || len(records) != 1 || records[0] != "preserve-me" {
			t.Fatal("unrelated TXT lost", err)
		}
		host := "_acme-challenge." + mode + ".nexus.test."
		if mode == "renew" {
			host = "_acme-challenge.issue.nexus.test."
		}
		records, _ = resolver.LookupTXT(ctx, host)
		if len(records) != 0 {
			t.Fatal("challenge TXT leaked after cleanup")
		}
	}
}

// Pebble omits Location on its processing finalize response. x/crypto/acme
// expects it when polling. Supply the already authenticated original order URL
// in the fixture transport; DNS validation and certificate verification remain real.
type labOrderTransport struct {
	base            http.RoundTripper
	finalize, order string
}

func (transport *labOrderTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err == nil && request.URL.String() == transport.finalize && response.Header.Get("Location") == "" {
		response.Header.Set("Location", transport.order)
	}
	return response, err
}
