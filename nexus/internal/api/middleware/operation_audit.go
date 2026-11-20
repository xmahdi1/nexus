package middleware

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
)

func audited(policy authorization.Policy) bool {
	if policy.Method != "GET" {
		return true
	}
	if strings.HasPrefix(policy.Path, "/ws/") {
		return true
	}
	for _, permission := range policy.Permissions {
		if permission == "files.read" || permission == "compose.read" || permission == "logs.read" || permission == "secrets.reveal" || permission == "audit.read" {
			return true
		}
	}
	return false
}
func operationEvent(r *http.Request, a *auth.Access, p authorization.Policy, params map[string]string) audit.Event {
	resourceType, resourceID := "global", ""
	if strings.HasPrefix(p.Path, "/api/services") {
		resourceType = "service"
	}
	if strings.HasPrefix(p.Path, "/api/templates/custom") {
		resourceType = "template"
	}
	server := ""
	if p.Scope == "server" {
		server = params["id"]
		resourceType = "server"
		resourceID = server
	}
	for _, key := range []string{"cid", "tid", "appId", "ruleId", "containerId", "uid", "inviteId", "grantId", "gid", "sid"} {
		if id := params[key]; id != "" {
			resourceType = map[string]string{"cid": "container", "tid": "task", "appId": "application", "ruleId": "proxy_rule", "containerId": "container", "uid": "user", "inviteId": "invitation", "grantId": "grant", "gid": "server_group", "sid": "session"}[key]
			resourceID = id
			break
		}
	}
	if resourceID == "" {
		resourceID = params["id"]
	}
	source := "http"
	if strings.HasPrefix(p.Path, "/ws/") {
		source = "websocket"
	}
	return audit.Event{ActorID: a.User.ID, SessionID: a.Session.ID, Action: p.Method + " " + p.Path, ResourceType: resourceType, ResourceID: resourceID, ServerID: server, Source: source, RequestID: wRequestID(r)}
}
func wRequestID(r *http.Request) string { return chimw.GetReqID(r.Context()) }

// Intent is durable before handlers execute. Completion records the handler's
// HTTP result, not a claim that a remote host reached an independently verified
// state. A crash or failed completion write leaves an explicit unpaired intent.
func serveAudited(db *gorm.DB, w http.ResponseWriter, r *http.Request, next http.Handler, event audit.Event) {
	id, err := audit.NewID()
	if err != nil {
		authError(w, 503, "audit_unavailable", "Audit unavailable.")
		return
	}
	event.OperationID = id
	event.Outcome = "started"
	if err := audit.Append(db, event); err != nil {
		authError(w, 503, "audit_unavailable", "Audit unavailable.")
		return
	}
	w.Header().Set("X-Operation-ID", id)
	wrapped := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
	ctx, result := audit.WithResult(r.Context())
	r = r.WithContext(ctx)
	tracker := &auditWriter{WrapResponseWriter: wrapped}

	started := time.Now()
	returned := false
	defer func() {
		event.DurationMS = time.Since(started).Milliseconds()
		if kind, id := result.Resource(); kind != "" && id != "" {
			event.ResourceType = kind
			event.ResourceID = id
			if kind == "server" {
				event.ServerID = id
			}
		}
		event.HTTPStatus = wrapped.Status()
		if !returned {
			event.Outcome = "interrupted"
		} else if result.RemoteUnknown() && !strings.HasPrefix(event.Action, "GET ") && !strings.HasPrefix(event.Action, "HEAD ") {
			event.Outcome = "remote_unknown"
		} else if wrapped.Status() >= 400 || result.Failed() {
			event.Outcome = "response_failed"
		} else if tracker.upgraded {
			event.Outcome = "stream_closed"
			event.HTTPStatus = 101
		} else {
			event.Outcome = "response_succeeded"
		}
		if event.HTTPStatus == 0 && returned {
			event.HTTPStatus = 200
		}
		if err := audit.Append(db, event); err != nil {
			// Never print error text, request data or transport output. The durable
			// started row remains pending; an HTTP response already sent cannot be undone.
			log.Printf("operation audit completion unavailable operation_id=%s", id)
		}
	}()
	next.ServeHTTP(tracker, r)
	returned = true
}

// Gorilla writes its upgrade response directly after Hijack, so Status alone
// cannot distinguish a successful upgrade from an empty HTTP 200 response.
type auditWriter struct {
	chimw.WrapResponseWriter
	upgraded bool
}

func (w *auditWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.WrapResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking unavailable")
	}
	conn, rw, err := hj.Hijack()
	if err == nil {
		w.upgraded = true
	}
	return conn, rw, err
}
