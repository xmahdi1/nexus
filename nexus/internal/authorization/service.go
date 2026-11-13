package authorization

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

var ErrInvalid = errors.New("invalid authorization change")
var ErrDenied = errors.New("permission denied")
var ErrLastAdmin = errors.New("cannot remove the last active administrator")

type Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (Role) TableName() string { return "roles" }

type Grant struct {
	ID            string    `gorm:"primaryKey" json:"id"`
	PrincipalID   string    `json:"principalId"`
	PrincipalKind string    `json:"principalKind"`
	RoleID        string    `json:"roleId"`
	ScopeType     string    `json:"scopeType"`
	ScopeID       string    `json:"scopeId"`
	CreatedBy     string    `json:"createdBy"`
	CreatedAt     time.Time `json:"createdAt"`
}

func (Grant) TableName() string { return "role_grants" }

type Group struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}

func (Group) TableName() string { return "server_groups" }

type Event struct {
	ID         uint      `json:"id"`
	At         time.Time `json:"at"`
	ActorID    string    `json:"actorId"`
	Action     string    `json:"action"`
	ResourceID string    `json:"resourceId"`
	Outcome    string    `json:"outcome"`
	RequestID  string    `json:"requestId"`
}

func (Event) TableName() string { return "authorization_events" }

type Service struct{ DB *gorm.DB }

func New(db *gorm.DB) *Service { return &Service{DB: db} }
func (s *Service) principal(id string, invited bool) (string, bool) {
	if id == LegacyPrincipal {
		var count int64
		err := s.DB.Table("auth_state").Where("id=1 AND mode='legacy'").Count(&count).Error
		return "legacy", err == nil && count == 1
	}
	var count int64
	states := []string{"active"}
	if invited {
		states = append(states, "invited")
	}
	if err := s.DB.Model(&models.User{}).Where("id=? AND status IN ?", id, states).Count(&count).Error; err != nil {
		return "", false
	}
	if count == 1 {
		if invited {
			return "user", true
		}
		err := s.DB.Table("account_admissions a").Joins("JOIN auth_credentials c ON c.user_id=a.user_id").Where("a.user_id=? AND c.recovery_required=0", id).Count(&count).Error
		return "user", err == nil && count == 1
	}
	err := s.DB.Table("service_principals").Where("id=? AND status='active'", id).Count(&count).Error
	return "service", err == nil && count == 1
}
func (s *Service) Check(actor, permission, server string) bool {
	if !Known(permission) {
		return false
	}
	kind, ok := s.principal(actor, false)
	if !ok {
		return false
	}
	if server != "" {
		var count int64
		if err := s.DB.Model(&models.Server{}).Where("id=?", server).Count(&count).Error; err != nil || count != 1 {
			return false
		}
	}
	query := s.DB.Table("role_grants AS g").Joins("JOIN role_permissions AS p ON p.role_id=g.role_id").Joins("JOIN roles AS roles ON roles.id=g.role_id").Where("g.principal_id=? AND g.principal_kind=? AND p.permission_key=?", actor, kind, permission)
	if server == "" {
		query = query.Where("g.scope_type='global' AND g.scope_id=''")
	} else {
		query = query.Where(`((g.scope_type='global' AND g.scope_id='') OR (g.scope_type='server' AND g.scope_id=?) OR (g.scope_type='server_group' AND EXISTS (SELECT 1 FROM server_group_members m JOIN server_groups sg ON sg.id=m.group_id WHERE m.server_id=? AND m.group_id=g.scope_id)))`, server, server)
	}
	var count int64
	return query.Count(&count).Error == nil && count > 0
}
func (s *Service) All(actor, server string, permissions ...string) bool {
	for _, p := range permissions {
		if !s.Check(actor, p, server) {
			return false
		}
	}
	return len(permissions) > 0
}
func (s *Service) ServerQuery(actor, permission string) *gorm.DB {
	kind, ok := s.principal(actor, false)
	q := s.DB.Model(&models.Server{})
	if !ok || !Known(permission) {
		return q.Where("1=0")
	}
	return q.Where(`EXISTS (SELECT 1 FROM role_grants g JOIN role_permissions p ON p.role_id=g.role_id JOIN roles r ON r.id=g.role_id WHERE g.principal_id=? AND g.principal_kind=? AND p.permission_key=? AND ((g.scope_type='global' AND g.scope_id='') OR (g.scope_type='server' AND g.scope_id=servers.id) OR (g.scope_type='server_group' AND EXISTS(SELECT 1 FROM server_group_members m JOIN server_groups sg ON sg.id=m.group_id WHERE m.server_id=servers.id AND m.group_id=g.scope_id))))`, actor, kind, permission)
}
func (s *Service) VisibleIDs(actor, permission string) ([]string, error) {
	ids := []string{}
	err := s.ServerQuery(actor, permission).Pluck("servers.id", &ids).Error
	return ids, err
}
func (s *Service) Collection(actor, permission string) bool {
	if !Known(permission) {
		return false
	}
	kind, ok := s.principal(actor, false)
	if !ok {
		return false
	}
	var count int64
	return s.DB.Table("role_grants g").Joins("JOIN role_permissions p ON p.role_id=g.role_id").Joins("JOIN roles r ON r.id=g.role_id").Where("g.principal_id=? AND g.principal_kind=? AND p.permission_key=?", actor, kind, permission).Where(`((g.scope_type='global' AND g.scope_id='') OR (g.scope_type='server' AND EXISTS(SELECT 1 FROM servers s WHERE s.id=g.scope_id)) OR (g.scope_type='server_group' AND EXISTS(SELECT 1 FROM server_groups sg WHERE sg.id=g.scope_id)))`).Count(&count).Error == nil && count > 0
}

func (s *Service) Record(actor, action, resource, outcome, request string) error {
	return s.DB.Create(&Event{At: time.Now().UTC(), ActorID: actor, Action: action, ResourceID: resource, Outcome: outcome, RequestID: request}).Error
}
func (s *Service) Allowed(actor string, policy Policy, server string) bool {
	if policy.Self {
		_, ok := s.principal(actor, false)
		return ok
	}
	if policy.Scope == "collection" {
		for _, p := range policy.Permissions {
			if !s.Collection(actor, p) {
				return false
			}
		}
		return len(policy.Permissions) > 0
	}
	if policy.Scope != "server" && policy.Scope != "global" {
		return false
	}
	if policy.Scope == "server" && server == "" {
		return false
	}
	return s.All(actor, server, policy.Permissions...)
}

type requestScope struct {
	Actor   string
	Service *Service
}
type scopeKey struct{}

func Bind(r *http.Request, s *Service, actor string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), scopeKey{}, requestScope{actor, s}))
}
func Request(r *http.Request) (*Service, string, bool) {
	v, ok := r.Context().Value(scopeKey{}).(requestScope)
	return v.Service, v.Actor, ok
}
func ScopedServers(r *http.Request, fallback *gorm.DB, permission string) *gorm.DB {
	s, actor, ok := Request(r)
	if !ok {
		return fallback.Model(&models.Server{}).Where("1=0")
	}
	return s.ServerQuery(actor, permission)
}

// Watch revalidates the scope of a background collector with no browser session.
func (s *Service) Watch(actor, server string, closeWork func(), permissions ...string) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if !s.All(actor, server, permissions...) {
					closeWork()
					return
				}
			}
		}
	}()
	return func() { close(stop) }
}
