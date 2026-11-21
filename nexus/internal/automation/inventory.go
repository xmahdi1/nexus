// Package automation separates public automation inventory from execution
// credentials. Inventory authority never authorizes remote commands.
package automation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
	"gorm.io/gorm"
)

var ErrDenied = errors.New("automation access unavailable")
var ErrInventory = errors.New("inventory contains invalid or excessive public metadata")

const MaxHosts = 1000

type InventoryToken struct {
	ID        string    `gorm:"primaryKey" json:"id"`
	TokenHash string    `json:"-"`
	ActorID   string    `json:"-"`
	SessionID string    `json:"-"`
	GroupID   string    `json:"groupId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (InventoryToken) TableName() string { return "ansible_inventory_tokens" }

type InventoryService struct {
	DB       *gorm.DB
	Sessions *auth.Service
}
type Group struct {
	Hosts    []string `json:"hosts"`
	Children []string `json:"children,omitempty"`
}
type Meta struct {
	Hostvars map[string]Hostvars `json:"hostvars"`
}
type Hostvars struct {
	Host     string `json:"ansible_host"`
	Port     int    `json:"ansible_port"`
	User     string `json:"ansible_user"`
	ServerID string `json:"nexus_server_id"`
}
type Inventory map[string]any
type Preview struct {
	Revision  string    `json:"revision"`
	Inventory Inventory `json:"inventory"`
	// No arbitrary names/vars reach Ansible's variable templating machinery.
	Groups map[string]string `json:"groups"`
}

type InventoryGroupSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *InventoryService) Groups(access *auth.Access) ([]InventoryGroupSummary, error) {
	if !access.AuthorizedNow() {
		return nil, ErrDenied
	}
	policy := authorization.New(s.DB)
	visible := policy.ServerQuery(access.User.ID, "ansible.inventory.read").Where("servers.id IN (?)", policy.ServerQuery(access.User.ID, "servers.read").Select("servers.id")).Select("servers.id")
	rows := []InventoryGroupSummary{}
	err := s.DB.Table("server_groups").Select("id,name").Where("EXISTS (SELECT 1 FROM server_group_members m WHERE m.group_id=server_groups.id AND m.server_id IN (?))", visible).Order("name,id").Limit(1001).Find(&rows).Error
	if len(rows) > 1000 {
		return nil, ErrInventory
	}
	if err == nil && !access.AuthorizedNow() {
		return nil, ErrDenied
	}
	return rows, err
}

var username = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?$`)
var dnsname = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func Alias(kind, id string) string {
	sum := sha256.Sum256([]byte(id))
	return "nexus_" + kind + "_" + hex.EncodeToString(sum[:])
}
func validHost(h string) bool {
	return len(h) > 0 && len(h) <= 253 && (net.ParseIP(h) != nil || dnsname.MatchString(h))
}
func validLabel(v string) bool {
	if len(v) == 0 || len(v) > 80 {
		return false
	}
	for _, r := range v {
		if r < ' ' || r == 127 || strings.ContainsRune("{}", r) {
			return false
		}
	}
	return true
}

// Build reads a fresh transaction snapshot. It never reads secret/key columns,
// imports arbitrary Ansible variables, or falls back to a previous inventory.
func (s *InventoryService) Build(access *auth.Access, groupID string) (Preview, error) {
	var result Preview
	if !identifier.MatchString(groupID) || !access.AuthorizedNow() {
		return result, ErrDenied
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		policy := authorization.New(tx)
		var group authorization.Group
		if tx.First(&group, "id=?", groupID).Error != nil {
			return ErrDenied
		}
		var servers []models.Server
		query := policy.ServerQuery(access.User.ID, "ansible.inventory.read").
			Where("EXISTS (SELECT 1 FROM server_group_members m WHERE m.server_id=servers.id AND m.group_id=?)", groupID).
			Select("servers.id, servers.host, servers.port, servers.username, servers.tags").Order("servers.id").Limit(MaxHosts + 1)
		if err := query.Find(&servers).Error; err != nil {
			return err
		}
		if len(servers) == 0 {
			return ErrDenied
		}
		if len(servers) > MaxHosts || !validLabel(group.Name) {
			return ErrInventory
		}
		hostvars := map[string]Hostvars{}
		groups := map[string][]string{}
		names := map[string]string{}
		groupAlias := Alias("group", group.ID)
		groups[groupAlias] = []string{}
		names[groupAlias] = group.Name
		for _, server := range servers {
			if !policy.Check(access.User.ID, "servers.read", server.ID) {
				continue
			}
			if !identifier.MatchString(server.ID) || !validHost(server.Host) || !username.MatchString(server.Username) || server.Port < 1 || server.Port > 65535 || len(server.Tags) > 2600 {
				return ErrInventory
			}
			alias := Alias("host", server.ID)
			hostvars[alias] = Hostvars{server.Host, server.Port, server.Username, server.ID}
			groups[groupAlias] = append(groups[groupAlias], alias)
			seen := map[string]bool{}
			if server.Tags == "" {
				continue
			}
			tags := strings.Split(server.Tags, ",")
			if len(tags) > 32 {
				return ErrInventory
			}
			for _, tag := range tags {
				tag = strings.TrimSpace(tag)
				if !validLabel(tag) {
					return ErrInventory
				}
				tagAlias := Alias("tag", tag)
				if !seen[tagAlias] {
					groups[tagAlias] = append(groups[tagAlias], alias)
					seen[tagAlias] = true
				}
				names[tagAlias] = tag
			}
		}
		if len(hostvars) == 0 {
			return ErrDenied
		}
		inventory := Inventory{"_meta": Meta{hostvars}}
		children := make([]string, 0, len(groups))
		for name, hosts := range groups {
			inventory[name] = Group{Hosts: hosts}
			children = append(children, name)
		}
		sort.Strings(children)
		inventory["all"] = Group{Hosts: []string{}, Children: children}
		encoded, err := json.Marshal(inventory)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(encoded)
		result = Preview{hex.EncodeToString(sum[:]), inventory, names}
		return nil
	})
	if err != nil {
		return Preview{}, err
	}
	if !access.AuthorizedNow() {
		return Preview{}, ErrDenied
	}
	return result, nil
}

func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func (s *InventoryService) Issue(access *auth.Access, group string, ttl time.Duration) (InventoryToken, string, error) {
	if ttl < time.Minute || ttl > 15*time.Minute {
		return InventoryToken{}, "", ErrDenied
	}
	if _, err := s.Build(access, group); err != nil {
		return InventoryToken{}, "", err
	}
	raw := make([]byte, 48)
	if _, err := rand.Read(raw); err != nil {
		return InventoryToken{}, "", err
	}
	token := "nxi_" + hex.EncodeToString(raw[:32])
	now := time.Now().UTC()
	row := InventoryToken{ID: hex.EncodeToString(raw[32:]), TokenHash: digest(token), ActorID: access.User.ID, SessionID: access.Session.ID, GroupID: group, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if access.Session.ExpiresAt.Before(row.ExpiresAt) {
		row.ExpiresAt = access.Session.ExpiresAt
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("actor_id=? AND expires_at<=?", row.ActorID, now).Delete(&InventoryToken{}).Error; err != nil {
			return err
		}
		var n int64
		if err := tx.Model(&InventoryToken{}).Where("actor_id=?", row.ActorID).Count(&n).Error; err != nil {
			return err
		}
		if n >= 32 {
			return ErrDenied
		}
		if err := authorization.New(tx).Record(row.ActorID, "ansible.inventory.token.create", row.ID, "created", "", row.SessionID); err != nil {
			return err
		}
		return tx.Create(&row).Error
	})
	return row, token, err
}

func (s *InventoryService) Authenticate(token string) (*auth.Access, string, error) {
	if len(token) != 68 || !strings.HasPrefix(token, "nxi_") {
		return nil, "", ErrDenied
	}
	var row InventoryToken
	if s.DB.First(&row, "token_hash=? AND expires_at>?", digest(token), time.Now().UTC()).Error != nil {
		return nil, "", ErrDenied
	}
	access, err := s.Sessions.AccessForSession(row.SessionID, row.ActorID)
	if err != nil {
		return nil, "", ErrDenied
	}
	access.CheckAuthorization = func() bool {
		var count int64
		return s.DB.Model(&InventoryToken{}).Where("id=? AND token_hash=? AND expires_at>?", row.ID, row.TokenHash, time.Now().UTC()).Count(&count).Error == nil && count == 1
	}
	return access, row.GroupID, nil
}
