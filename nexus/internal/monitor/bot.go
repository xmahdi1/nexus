package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"time"
)

type AlertType string

const (
	AlertServerDown    AlertType = "server_down"
	AlertServerUp      AlertType = "server_up"
	AlertContainerDown AlertType = "container_down"
	AlertContainerUp   AlertType = "container_up"
	AlertHighResource  AlertType = "high_resource"
	AlertSSLExpiry     AlertType = "ssl_expiry"
)

type Alert struct {
	ServerID   string
	Type       AlertType
	ServerName string
	ServerHost string
	Detail     string
	Extra      map[string]string
	OccurredAt time.Time
}

type Bot struct {
	token  string
	chatID string
	client *http.Client
}

func NewBot(token, chatID string) *Bot {
	return &Bot{
		token:  token,
		chatID: chatID,
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (b *Bot) Send(text string) error {
	if b.token == "" || b.chatID == "" {
		return fmt.Errorf("bot not configured")
	}
	payload, _ := json.Marshal(map[string]string{
		"chat_id":    b.chatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	resp, err := b.client.Post(
		fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", url.PathEscape(b.token)),
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		// net/http errors include the request URL, which contains the bot token.
		return errors.New("Telegram transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Telegram API returned status %d", resp.StatusCode)
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil || !result.OK {
		return errors.New("Telegram delivery was not confirmed")
	}
	return nil
}

func (b *Bot) Notify(a Alert) error {
	a.ServerName = html.EscapeString(a.ServerName)
	a.ServerHost = html.EscapeString(a.ServerHost)
	a.Detail = html.EscapeString(a.Detail)
	ts := a.OccurredAt.Format("15:04:05 MST")
	switch a.Type {
	case AlertServerDown:
		return b.Send(fmt.Sprintf(
			"🔴 <b>Server Down</b>\n<b>%s</b> (<code>%s</code>) is unreachable.\n🕐 %s",
			a.ServerName, a.ServerHost, ts,
		))
	case AlertServerUp:
		downtime := ""
		if a.Detail != "" {
			downtime = "\n⏱ Downtime: " + a.Detail
		}
		return b.Send(fmt.Sprintf(
			"🟢 <b>Server Online</b>\n<b>%s</b> (<code>%s</code>) is back online.%s",
			a.ServerName, a.ServerHost, downtime,
		))
	case AlertContainerDown:
		return b.Send(fmt.Sprintf(
			"🟠 <b>Container Stopped</b>\nContainer <code>%s</code> on <b>%s</b> is no longer running.\n🕐 %s",
			a.Detail, a.ServerName, ts,
		))
	case AlertContainerUp:
		return b.Send(fmt.Sprintf(
			"🟢 <b>Container Started</b>\nContainer <code>%s</code> on <b>%s</b> is running again.",
			a.Detail, a.ServerName,
		))
	case AlertHighResource:
		return b.Send(fmt.Sprintf(
			"⚠️ <b>High Resource Usage</b>\n<b>%s</b> (<code>%s</code>)\n%s\n🕐 %s",
			a.ServerName, a.ServerHost, a.Detail, ts,
		))
	case AlertSSLExpiry:
		return b.Send(fmt.Sprintf(
			"🔐 <b>SSL Certificate Expiring</b>\nDomain <code>%s</code> on <b>%s</b>\nExpires in: %s",
			a.Detail, a.ServerName, a.Extra["daysLeft"],
		))
	default:
		return b.Send(fmt.Sprintf(
			"ℹ️ <b>Nexus Alert</b> [%s]\n%s on %s\n%s",
			a.Type, a.Detail, a.ServerName, ts,
		))
	}
}

func (b *Bot) Test() error {
	return b.Send("✅ <b>Nexus</b> — Telegram notifications are working correctly!")
}

func (b *Bot) GetMe() (map[string]any, error) {
	resp, err := b.client.Get(fmt.Sprintf("https://api.telegram.org/bot%s/getMe", url.PathEscape(b.token)))
	if err != nil {
		return nil, errors.New("Telegram transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("Telegram identity request failed")
	}
	var result struct {
		OK     bool           `json:"ok"`
		Result map[string]any `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil || !result.OK {
		return nil, fmt.Errorf("invalid token")
	}
	return result.Result, nil
}
