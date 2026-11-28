package githubactions

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	nexuscrypto "github.com/xmahdi1/nexus/internal/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrWebhookCapacity = errors.New("webhook receipt capacity reached; rotate the endpoint after inspection")

type Webhook struct {
	ID           string    `gorm:"primaryKey" json:"id"`
	ServerID     string    `json:"-"`
	ConnectionID string    `json:"connectionId"`
	EndpointID   string    `json:"-"`
	SecretEnc    string    `json:"-"`
	Disabled     bool      `json:"disabled"`
	CreatedBy    string    `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

func (Webhook) TableName() string { return "github_webhooks" }

type WebhookInfo struct {
	Configured bool      `json:"configured"`
	Disabled   bool      `json:"disabled"`
	Path       string    `json:"path"`
	CreatedAt  time.Time `json:"createdAt"`
}

func webhookInfo(row Webhook) WebhookInfo {
	return WebhookInfo{Configured: row.ID != "", Disabled: row.Disabled, Path: "/api/hooks/github/" + row.EndpointID, CreatedAt: row.CreatedAt}
}

type webhookSecret struct{ ConnectionID, EndpointID, Secret string }
type webhookReceipt struct {
	ID, HookID, DeliveryHash, BodyHash, Event string
	ReceivedAt                                time.Time
}

func (webhookReceipt) TableName() string { return "github_webhook_receipts" }

type RunObservation struct {
	ID              string    `gorm:"primaryKey" json:"-"`
	ServerID        string    `json:"-"`
	ConnectionID    string    `json:"connectionId"`
	RunID           int64     `json:"runId"`
	RunAttempt      int64     `json:"runAttempt"`
	WorkflowID      int64     `json:"workflowId"`
	Status          string    `json:"status"`
	Conclusion      string    `json:"conclusion"`
	HeadSHA         string    `json:"headSha"`
	SourceUpdatedAt time.Time `json:"sourceUpdatedAt"`
	StateRank       int       `json:"-"`
	ReceivedAt      time.Time `json:"receivedAt"`
}

func (RunObservation) TableName() string { return "github_run_observations" }
func (s *Service) webhookConnection(server, id string) (Connection, error) {
	var row Connection
	if !ValidRequestID(id) {
		return row, ErrInput
	}
	err := s.DB.First(&row, "id=? AND server_id=? AND disabled=0", id, server).Error
	if err != nil {
		return row, ErrDenied
	}
	return row, nil
}
func (s *Service) Webhook(a *auth.Access, server, id string) (WebhookInfo, error) {
	if err := s.require(a, server, true, "github.webhooks.manage"); err != nil {
		return WebhookInfo{}, err
	}
	if _, err := s.webhookConnection(server, id); err != nil {
		return WebhookInfo{}, err
	}
	var row Webhook
	err := s.DB.First(&row, "connection_id=? AND server_id=?", id, server).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return WebhookInfo{}, nil
	}
	return webhookInfo(row), err
}

// RotateWebhook creates a fresh endpoint and secret, disclosed in this reply only.
// It never registers a hook at GitHub or requests provider credentials.
func (s *Service) RotateWebhook(a *auth.Access, server, connectionID string) (WebhookInfo, string, error) {
	permissions := []string{"github.webhooks.manage", "secrets.create", "secrets.reveal"}
	if err := s.require(a, server, true, permissions...); err != nil {
		return WebhookInfo{}, "", err
	}
	endpoint, err := audit.NewID()
	if err != nil {
		return WebhookInfo{}, "", err
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, err = rand.Read(key); err != nil {
		return WebhookInfo{}, "", err
	}
	secret := hex.EncodeToString(key)
	var row Webhook
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, permissions...); err != nil {
			return err
		}
		if _, err := inside.webhookConnection(server, connectionID); err != nil {
			return err
		}
		err := tx.First(&row, "connection_id=? AND server_id=?", connectionID, server).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			id, err := audit.NewID()
			if err != nil {
				return err
			}
			row = Webhook{ID: id, ServerID: server, ConnectionID: connectionID, CreatedBy: a.User.ID}
		} else if err != nil {
			return err
		}
		data, _ := json.Marshal(webhookSecret{connectionID, endpoint, secret})
		defer clear(data)
		sealed, err := nexuscrypto.EncryptGitHubPayload(s.Key, "webhook", row.ID, server, data)
		if err != nil {
			return err
		}
		row.EndpointID = endpoint
		row.SecretEnc = sealed
		row.Disabled = false
		row.CreatedAt = time.Now().UTC()
		row.CreatedBy = a.User.ID
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if err := tx.Where("hook_id=?", row.ID).Delete(&webhookReceipt{}).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "github.webhook.rotate", row.ID, "configured", "", a.Session.ID)
	})
	if err != nil {
		return WebhookInfo{}, "", err
	}
	if err := s.require(a, server, true, permissions...); err != nil {
		return WebhookInfo{}, "", err
	}
	return webhookInfo(row), secret, nil
}
func (s *Service) DisableWebhook(a *auth.Access, server, id string) error {
	if err := s.require(a, server, true, "github.webhooks.manage"); err != nil {
		return err
	}
	return s.DB.Transaction(func(tx *gorm.DB) error {
		inside := *s
		inside.DB = tx
		if err := inside.require(a, server, true, "github.webhooks.manage"); err != nil {
			return err
		}
		if _, err := inside.webhookConnection(server, id); err != nil {
			return err
		}
		if err := tx.Model(&Webhook{}).Where("connection_id=? AND server_id=?", id, server).Update("disabled", true).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(a.User.ID, "github.webhook.disable", id, "disabled", "", a.Session.ID)
	})
}
func (s *Service) WebhookRuns(a *auth.Access, server, id string) ([]RunObservation, error) {
	if err := s.require(a, server, false, "github.actions.read"); err != nil {
		return nil, err
	}
	if _, err := s.webhookConnection(server, id); err != nil {
		return nil, err
	}
	rows := []RunObservation{}
	err := s.DB.Where("server_id=? AND connection_id=?", server, id).Order("received_at DESC,id DESC").Limit(50).Find(&rows).Error
	return rows, err
}
func hashString(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func validDelivery(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ReceiveWebhook verifies before decoding and stores only fixed metadata. The
// delivery header is unsigned: body digests independently prevent header swaps.
func (s *Service) ReceiveWebhook(ctx context.Context, endpoint, event, delivery, signature string, body []byte) (bool, error) {
	inside := *s
	inside.DB = s.DB.WithContext(ctx)
	return inside.receiveWebhook(endpoint, event, delivery, signature, body)
}
func (s *Service) receiveWebhook(endpoint, event, delivery, signature string, body []byte) (bool, error) {
	if !s.Enabled {
		return false, ErrDisabled
	}
	if !ValidRequestID(endpoint) || !validDelivery(delivery) || len(body) > 512<<10 || !utf8.Valid(body) || (event != "ping" && event != "workflow_run") {
		return false, ErrInput
	}
	var hook Webhook
	if err := s.DB.First(&hook, "endpoint_id=? AND disabled=0", endpoint).Error; err != nil {
		return false, ErrDenied
	}
	conn, err := s.webhookConnection(hook.ServerID, hook.ConnectionID)
	if err != nil {
		return false, err
	}
	data, err := nexuscrypto.DecryptGitHubPayload(s.Key, "webhook", hook.ID, hook.ServerID, hook.SecretEnc)
	if err != nil {
		return false, ErrDenied
	}
	defer clear(data)
	var config webhookSecret
	if json.Unmarshal(data, &config) != nil || config.EndpointID != endpoint || config.ConnectionID != conn.ID || len(config.Secret) != 64 {
		return false, ErrDenied
	}
	mac := hmac.New(sha256.New, []byte(config.Secret))
	mac.Write(body)
	if !strings.HasPrefix(signature, "sha256=") || len(signature) != 71 {
		return false, ErrDenied
	}
	signed, err := hex.DecodeString(signature[7:])
	if err != nil || !hmac.Equal(mac.Sum(nil), signed) {
		return false, ErrDenied
	}
	var payload struct {
		Action     string `json:"action"`
		Repository struct {
			ID       int64  `json:"id"`
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation *struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		HookID      int64 `json:"hook_id"`
		WorkflowRun *struct {
			Run
			UpdatedAt time.Time `json:"updated_at"`
		} `json:"workflow_run"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Repository.ID != conn.RepositoryID || !strings.EqualFold(payload.Repository.FullName, conn.Owner+"/"+conn.Name) || (payload.Installation != nil && payload.Installation.ID != conn.InstallationID) {
		return false, ErrInput
	}
	now := time.Now().UTC()
	var observed *RunObservation
	if event == "ping" {
		if payload.WorkflowRun != nil || payload.Action != "" || !validID(payload.HookID) {
			return false, ErrInput
		}
	} else {
		run := payload.WorkflowRun
		if run == nil || !validRun(run.Run) || !validID(run.RunAttempt) || run.UpdatedAt.Before(now.Add(-15*time.Minute)) || run.UpdatedAt.After(now.Add(2*time.Minute)) {
			return false, ErrInput
		}
		rank := 0
		switch payload.Action {
		case "requested":
			if run.Status == "queued" || run.Status == "requested" || run.Status == "pending" || run.Status == "waiting" {
				rank = 1
			}
		case "in_progress":
			if run.Status == "in_progress" {
				rank = 2
			}
		case "completed":
			if run.Status == "completed" && run.Conclusion != nil {
				switch *run.Conclusion {
				case "success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure":
					rank = 3
				}
			}
		}
		if rank == 0 || (rank != 3 && run.Conclusion != nil) {
			return false, ErrInput
		}
		conclusion := ""
		if run.Conclusion != nil {
			conclusion = *run.Conclusion
		}
		observed = &RunObservation{ID: conn.ID + ":" + strconv.FormatInt(run.ID, 10), ServerID: hook.ServerID, ConnectionID: conn.ID, RunID: run.ID, RunAttempt: run.RunAttempt, WorkflowID: run.WorkflowID, Status: run.Status, Conclusion: conclusion, HeadSHA: run.HeadSHA, SourceUpdatedAt: run.UpdatedAt, StateRank: rank, ReceivedAt: now}
	}
	receiptID, err := audit.NewID()
	if err != nil {
		return false, err
	}
	receipt := webhookReceipt{ID: receiptID, HookID: hook.ID, DeliveryHash: hashString([]byte(strings.ToLower(delivery))), BodyHash: hashString(body), Event: event, ReceivedAt: now}
	duplicate := false
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		// Rotation/disable, delegated actor authority and connection changes all
		// serialize against this transaction. Intake needs no ongoing login session.
		if !authorization.New(tx).All(hook.CreatedBy, hook.ServerID, "servers.read", "github.webhooks.manage") {
			return ErrDenied
		}
		var count int64
		if err := tx.Model(&Webhook{}).Where("id=? AND endpoint_id=? AND secret_enc=? AND disabled=0", hook.ID, endpoint, hook.SecretEnc).Count(&count).Error; err != nil || count != 1 {
			return ErrDenied
		}
		if err := tx.Model(&Connection{}).Where("id=? AND server_id=? AND disabled=0 AND repository_id=? AND owner=? AND name=? AND installation_id=?", conn.ID, hook.ServerID, conn.RepositoryID, conn.Owner, conn.Name, conn.InstallationID).Count(&count).Error; err != nil || count != 1 {
			return ErrDenied
		}
		if err := tx.Where("hook_id=? AND event='workflow_run' AND received_at<?", hook.ID, now.Add(-24*time.Hour)).Delete(&webhookReceipt{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&webhookReceipt{}).Where("hook_id=? AND (delivery_hash=? OR body_hash=?)", hook.ID, receipt.DeliveryHash, receipt.BodyHash).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			duplicate = true
			return nil
		}
		if err := tx.Model(&webhookReceipt{}).Where("hook_id=?", hook.ID).Count(&count).Error; err != nil {
			return err
		}
		if count >= 5000 {
			return ErrWebhookCapacity
		}
		if err := tx.Create(&receipt).Error; err != nil {
			return err
		}
		if observed != nil {
			if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "connection_id"}, {Name: "run_id"}}, DoNothing: true}).Create(observed).Error; err != nil {
				return err
			}
			updates := map[string]any{"run_attempt": observed.RunAttempt, "workflow_id": observed.WorkflowID, "status": observed.Status, "conclusion": observed.Conclusion, "head_sha": observed.HeadSHA, "source_updated_at": observed.SourceUpdatedAt, "state_rank": observed.StateRank, "received_at": now}
			if err := tx.Model(&RunObservation{}).Where("id=? AND (run_attempt<? OR (run_attempt=? AND state_rank<=? AND (source_updated_at<? OR (source_updated_at=? AND state_rank<?))))", observed.ID, observed.RunAttempt, observed.RunAttempt, observed.StateRank, observed.SourceUpdatedAt, observed.SourceUpdatedAt, observed.StateRank).Updates(updates).Error; err != nil {
				return err
			}
			if err := tx.Exec("DELETE FROM github_run_observations WHERE id IN (SELECT id FROM github_run_observations WHERE connection_id=? ORDER BY received_at DESC,id DESC LIMIT -1 OFFSET 1000)", conn.ID).Error; err != nil {
				return err
			}
		}
		return nil
	})
	return duplicate, err
}
