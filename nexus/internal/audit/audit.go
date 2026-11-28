// Package audit persists deliberately narrow metadata. Bodies, queries, command
// strings, transport output and error messages are never accepted by its API.
package audit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

type Event struct {
	ID           uint64    `gorm:"primaryKey" json:"id"`
	OperationID  string    `json:"operationId"`
	At           time.Time `json:"at"`
	ActorID      string    `json:"actorId"`
	SessionID    string    `json:"sessionId"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId"`
	ServerID     string    `json:"serverId"`
	Source       string    `json:"source"`
	Outcome      string    `json:"outcome"`
	RequestID    string    `json:"requestId"`
	HTTPStatus   int       `json:"httpStatus"`
	DurationMS   int64     `json:"durationMs"`
}

func (Event) TableName() string { return "operation_events" }
func NewID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

// Identifier keeps generated/natural IDs, hashes arbitrary client-controlled data.
func Identifier(value string) string {
	if len(value) <= 128 && !strings.ContainsAny(value, "\r\n\t") {
		valid := true
		for _, c := range value {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("_.:-", c)) {
				valid = false
				break
			}
		}
		if valid {
			return value
		}
	}
	hash := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(hash[:])
}
func RequestIdentifier(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func Append(db *gorm.DB, event Event) error {
	event.ID = 0
	event.At = time.Now().UTC()
	event.ActorID = Identifier(event.ActorID)
	event.SessionID = Identifier(event.SessionID)
	event.ResourceID = Identifier(event.ResourceID)
	event.ServerID = Identifier(event.ServerID)
	event.RequestID = RequestIdentifier(event.RequestID)
	return db.Create(&event).Error
}

type Filter struct {
	Before                                             uint64
	Limit                                              int
	Actor, Server, Outcome, Action, Operation, Request string
}
type Page struct {
	Items []Event `json:"items"`
	Next  string  `json:"next"`
}

func Query(db *gorm.DB, f Filter) (Page, error) {
	page := Page{Items: []Event{}}
	if f.Limit == 0 {
		f.Limit = 50
	}
	if f.Limit < 1 || f.Limit > 200 {
		return page, errors.New("limit must be 1 to 200")
	}
	q := db.Model(&Event{})
	if f.Before > 0 {
		q = q.Where("id < ?", f.Before)
	}
	for column, value := range map[string]string{"actor_id": Identifier(f.Actor), "server_id": Identifier(f.Server), "outcome": f.Outcome, "action": f.Action, "operation_id": Identifier(f.Operation), "request_id": f.Request} {
		if value != "" {
			if len(value) > 256 {
				return page, errors.New("filter too long")
			}
			q = q.Where(column+" = ?", value)
		}
	}
	if err := q.Order("id DESC").Limit(f.Limit + 1).Find(&page.Items).Error; err != nil {
		return page, err
	}
	if len(page.Items) > f.Limit {
		page.Items = page.Items[:f.Limit]
		page.Next = strconv.FormatUint(page.Items[len(page.Items)-1].ID, 10)
	}
	return page, nil
}

// Prune is intentionally local-only. There is no HTTP audit deletion endpoint.
func Prune(db *gorm.DB, before time.Time) (int64, error) {
	r := db.Where("at < ?", before.UTC()).Delete(&Event{})
	return r.RowsAffected, r.Error
}

type resultKey struct{}
type Result struct {
	failed                   atomic.Bool
	remoteUnknown            atomic.Bool
	mu                       sync.Mutex
	resourceType, resourceID string
}

func WithResult(ctx context.Context) (context.Context, *Result) {
	result := &Result{}
	return context.WithValue(ctx, resultKey{}, result), result
}
func MarkFailed(ctx context.Context) {
	if result, ok := ctx.Value(resultKey{}).(*Result); ok {
		result.failed.Store(true)
	}
}
func (r *Result) Failed() bool { return r.failed.Load() }

func MarkResource(ctx context.Context, kind, id string) {
	switch kind {
	case "github_dispatch", "github_cancellation", "github_change", "github_connection", "server", "service", "proxy_rule", "application", "template", "invitation", "user", "server_group", "grant", "task", "job_run", "discovery_run", "vault_kv", "vault_control":
	default:
		return
	}
	if r, ok := ctx.Value(resultKey{}).(*Result); ok {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.resourceType = kind
		r.resourceID = Identifier(id)
	}
}
func (r *Result) Resource() (string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resourceType, r.resourceID
}

// MarkRemoteUnknown records loss of a remote result after dispatch. It does not
// assert rollback, process termination or permission to replay the operation.
func MarkRemoteUnknown(ctx context.Context) {
	if result, ok := ctx.Value(resultKey{}).(*Result); ok {
		result.remoteUnknown.Store(true)
	}
}
func (r *Result) RemoteUnknown() bool { return r.remoteUnknown.Load() }
