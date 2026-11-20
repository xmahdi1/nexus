package vault

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestKVPathsAndCASAreRequired(t *testing.T) {
	zero := 0
	for _, request := range []KVRequest{
		{Token: "fixture", Mount: "secret", Path: "../sys", Version: &zero, Data: json.RawMessage(`{}`)},
		{Token: "fixture", Mount: "secret", Path: "%2e%2e", Version: &zero, Data: json.RawMessage(`{}`)},
		{Token: "fixture", Mount: "secret/data", Path: "x"},
		{Token: "fixture", Mount: "secret", Path: "x", Version: &zero, Data: json.RawMessage(`null`)},
	} {
		if request.Validate("write") == nil {
			t.Fatal("unsafe KV write accepted")
		}
	}
	if (KVRequest{Token: "fixture", Mount: "secret", Path: "", Version: &zero, Data: json.RawMessage(`{}`)}).Validate("write") == nil {
		t.Fatal("empty write path accepted")
	}
}

func TestKVBoundsJSONDepthWithoutLosingNumberSpelling(t *testing.T) {
	zero := 0
	input := KVRequest{Token: "fixture", Mount: "secret", Path: "key", Version: &zero}
	input.Data = json.RawMessage(strings.Repeat(`{"x":`, 33) + "0" + strings.Repeat("}", 33))
	if input.Validate("write") == nil {
		t.Fatal("deep object accepted")
	}
	for _, number := range []string{"9007199254740993", "0.1000000000000000001", "1e9999", "1e-9999", "1e-1000000000"} {
		input.Data = json.RawMessage(`{"number":` + number + `}`)
		if input.Validate("write") == nil {
			t.Fatal("lossy numeric write accepted", number)
		}
	}
	for _, number := range []string{"0.1", "1.25", "1e20", "-0", "0e999999999", "9007199254740992"} {
		input.Data = json.RawMessage(`{"number":` + number + `}`)
		if err := input.Validate("write"); err != nil {
			t.Fatal("round-trip-safe number rejected", number, err)
		}
	}
	input.Data = json.RawMessage(`{"large":"9007199254740993","decimal":"0.1000000000000000001"}`)
	if err := input.Validate("write"); err != nil {
		t.Fatal("exact strings rejected", err)
	}

}

func TestKVUnknownWriteIsNeverRetriedOrReflected(t *testing.T) {
	for _, scenario := range []string{"lost-ack", "truncated-ack", "wrong-version", "conflict", "denied", "revoked-before-write"} {
		t.Run(scenario, func(t *testing.T) {
			var writes atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/sys/health":
					w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
				case "/v1/auth/token/lookup-self":
					w.Write([]byte(`{"data":{"policies":["fixture"],"ttl":1200}}`))
				case "/v1/sys/mounts":
					w.Write([]byte(`{"data":{"secret/":{"type":"kv","options":{"version":"2"}}}}`))
				case "/v1/secret/data/key":
					writes.Add(1)
					if r.Method != "POST" {
						t.Error("wrong write method")
					}
					var body struct {
						Options struct {
							CAS *int `json:"cas"`
						} `json:"options"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Options.CAS == nil || *body.Options.CAS != 0 {
						t.Error("CAS omitted")
					}
					switch scenario {
					case "lost-ack":
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						connection.Close()
					case "truncated-ack":
						w.Write([]byte(`{"data":`))
					case "wrong-version":
						w.Write([]byte(`{"data":{"version":3}}`))
					case "conflict":
						w.WriteHeader(400)
						w.Write([]byte("fixture-token private-write-value"))
					case "denied":
						w.WriteHeader(403)
						w.Write([]byte("fixture-token private-write-value"))
					default:
						t.Error("write proceeded after revocation")
					}
				default:
					t.Error("unexpected upstream path", r.URL.Path)
				}
			}))
			defer server.Close()
			profile := Profile{Port: 8200, TLSName: "127.0.0.1", CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
			client, err := NewClient(profile, func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			zero := 0
			_, err = KV(context.Background(), client, profile, "write", KVRequest{Token: "fixture-token", Mount: "secret", Path: "key", Version: &zero, Data: json.RawMessage(`{"value":"private-write-value"}`)}, func() bool { return scenario != "revoked-before-write" })
			want := ErrRemoteUnknown
			if scenario == "conflict" {
				want = ErrConflict
			}
			if scenario == "denied" || scenario == "revoked-before-write" {
				want = ErrDenied
			}
			if !errors.Is(err, want) || strings.Contains(err.Error(), "fixture-token") || strings.Contains(err.Error(), "private-write-value") {
				t.Fatal("unsafe write outcome", err)
			}
			count := int32(1)
			if scenario == "revoked-before-write" {
				count = 0
			}
			if writes.Load() != count {
				t.Fatal("write was replayed or revocation ignored", writes.Load())
			}
		})
	}
}
