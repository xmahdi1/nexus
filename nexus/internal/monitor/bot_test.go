package monitor

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelegramFailuresDoNotRevealCredentialsOrUpstreamBody(t *testing.T) {
	secret := "fixture-" + strings.Repeat("private", 8)
	bot := NewBot(secret, "fictional-chat")
	for _, status := range []int{0, 200, 302, 400, 500} {
		bot.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if status == 0 {
				return nil, errors.New("failure with " + secret)
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{"ok":false,"description":"` + secret + `"}`)), Header: http.Header{}}, nil
		})
		for _, send := range []func() error{func() error { return bot.Send("private message") }, func() error { _, err := bot.GetMe(); return err }} {
			err := send()
			if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "api.telegram.org") {
				t.Fatal("unsafe delivery outcome", status, err)
			}
		}
	}
	if bot.client.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("redirect allowed")
	}
}

func TestTelegramEscapesObservedLabelsAndRequiresConfirmation(t *testing.T) {
	bot := NewBot("fixture-only-token", "fictional-chat")
	bot.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body["text"], "&lt;a") || strings.Contains(body["text"], `<a href=`) {
			t.Fatal("untrusted label rendered as markup")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: http.Header{}}, nil
	})
	if err := bot.Notify(Alert{Type: AlertServerDown, ServerName: `<a href="https://example.invalid">spoof</a>`}); err != nil {
		t.Fatal(err)
	}
}
