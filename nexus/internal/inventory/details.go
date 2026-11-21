package inventory

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ServiceUnit contains runtime state only, never unit files, environment,
// descriptions or command lines. The fixed show glob observes loaded units, not every
// service installed on disk.
type ServiceUnit struct {
	Unit   string `json:"unit"`
	Load   string `json:"load"`
	Active string `json:"active"`
	Sub    string `json:"sub"`
}
type serviceRow struct {
	ResourceID string `gorm:"primaryKey"`
	ServiceUnit
}

func (serviceRow) TableName() string { return "inventory_services" }

type Relationship struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	ServerID       string    `json:"serverId"`
	SourceID       string    `json:"sourceId"`
	TargetID       string    `json:"targetId"`
	Kind           string    `json:"kind"`
	Source         string    `json:"source"`
	FirstSeenAt    time.Time `json:"firstSeenAt"`
	LastVerifiedAt time.Time `json:"lastVerifiedAt"`
	DataState      string    `json:"dataState"`
	SourceName     string    `gorm:"->;-:migration" json:"sourceName"`
	TargetName     string    `gorm:"->;-:migration" json:"targetName"`
}

func (Relationship) TableName() string { return "inventory_relationships" }

type RelationshipPage struct {
	Items []Relationship `json:"items"`
	Next  string         `json:"next"`
}
type HistoryPage struct {
	Items []Change `json:"items"`
	Next  string   `json:"next"`
}

var resourceIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ErrPage = errors.New("invalid inventory page")

func resourceID(server, kind, key string) string { return hash(server + "\x00" + kind + "\x00" + key) }
func portNaturalKey(p Port) string {
	return p.ContainerID + ":" + p.Protocol + ":" + p.Address + ":" + strconv.Itoa(p.Port) + ":" + strconv.Itoa(p.TargetPort) + ":" + p.Exposure
}
func collectorAvailable(source string, obs Observation) bool {
	switch source {
	case "ssh":
		return obs.HostOK
	case "docker":
		return obs.DockerOK
	case "ss":
		return obs.SocketsOK
	case "systemd":
		return obs.ServicesOK
	default:
		return false
	}
}
func detailsFor(tx *gorm.DB, r Resource) (any, error) {
	switch r.Kind {
	case "host":
		var row hostRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.Host, err
	case "container":
		var row containerRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return Container{ID: row.EngineID, Name: r.DisplayName, Image: row.Image, State: row.State}, err
	case "port":
		var row portRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.Port, err
	case "service":
		var row serviceRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.ServiceUnit, err
	default:
		return nil, errors.New("unsupported inventory kind")
	}
}
func summary(name string, details any) (string, error) {
	raw, err := json.Marshal(struct {
		Name    string `json:"name"`
		Details any    `json:"details"`
	}{name, details})
	if err != nil {
		return "", err
	}
	if len(raw) > 8192 {
		return "", errors.New("inventory summary too large")
	}
	return string(raw), nil
}
func hydrateChanges(changes []Change) {
	for i := range changes {
		if changes[i].BeforeJSON != "" {
			changes[i].Before = json.RawMessage(changes[i].BeforeJSON)
		}
		if changes[i].AfterJSON != "" {
			changes[i].After = json.RawMessage(changes[i].AfterJSON)
		}
	}
}
func (s *Service) persistRelationships(tx *gorm.DB, run Run, obs Observation, now time.Time) error {
	host := resourceID(run.ServerID, "host", "registered-host")
	put := func(from, to, kind, source string) error {
		id := hash(run.ServerID + "\x00" + from + "\x00" + kind + "\x00" + to)
		row := Relationship{ID: id, ServerID: run.ServerID, SourceID: from, TargetID: to, Kind: kind, Source: source, FirstSeenAt: now, LastVerifiedAt: now, DataState: "fresh"}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoUpdates: clause.AssignmentColumns([]string{"last_verified_at", "data_state"})}).Create(&row).Error
	}
	containers := map[string]bool{}
	if obs.DockerOK {
		for _, c := range obs.Containers {
			containers[c.ID] = true
			if err := put(host, resourceID(run.ServerID, "container", c.ID), "runs", "docker"); err != nil {
				return err
			}
		}
	}
	if obs.ServicesOK {
		for _, unit := range obs.Services {
			if err := put(host, resourceID(run.ServerID, "service", unit.Unit), "manages", "systemd"); err != nil {
				return err
			}
		}
	}
	for _, p := range obs.Ports {
		port := resourceID(run.ServerID, "port", portNaturalKey(p))
		if p.Exposure == "listener" && obs.SocketsOK {
			if err := put(host, port, "listens", "ss"); err != nil {
				return err
			}
		}
		if p.Exposure != "listener" && obs.DockerOK && containers[p.ContainerID] {
			if err := put(resourceID(run.ServerID, "container", p.ContainerID), port, "exposes", "docker"); err != nil {
				return err
			}
		}
	}
	for _, source := range []string{"ssh", "docker", "ss", "systemd"} {
		if collectorAvailable(source, obs) {
			if err := tx.Model(&Relationship{}).Where("server_id=? AND source=? AND data_state='stale'", run.ServerID, source).Update("data_state", "retired").Error; err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Service) Relationships(actor, server, after string, limit int) (RelationshipPage, error) {
	page := RelationshipPage{Items: []Relationship{}}
	if limit < 1 || limit > 200 || (after != "" && !resourceIDPattern.MatchString(after)) {
		return page, ErrPage
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if !authorization.New(tx).All(actor, server, "inventory.read") {
			return authorization.ErrDenied
		}
		err := tx.Table("inventory_relationships AS link").Select("link.*, src.display_name AS source_name, dst.display_name AS target_name").Joins("JOIN inventory_resources src ON src.id=link.source_id AND src.server_id=link.server_id").Joins("JOIN inventory_resources dst ON dst.id=link.target_id AND dst.server_id=link.server_id").Where("link.server_id=? AND link.id>?", server, after).Order("link.id").Limit(limit + 1).Scan(&page.Items).Error
		if err != nil {
			return err
		}
		if len(page.Items) > limit {
			page.Items = page.Items[:limit]
			page.Next = page.Items[len(page.Items)-1].ID
		}
		for i := range page.Items {
			if page.Items[i].DataState == "fresh" && page.Items[i].LastVerifiedAt.Before(time.Now().Add(-15*time.Minute)) {
				page.Items[i].DataState = "stale"
			}
		}
		return nil
	})
	return page, err
}
func (s *Service) History(actor, server, resource, before string, limit int) (HistoryPage, error) {
	page := HistoryPage{Items: []Change{}}
	var cursor uint64
	if before != "" {
		var err error
		cursor, err = strconv.ParseUint(before, 10, 64)
		if err != nil || cursor == 0 {
			return page, ErrPage
		}
	}
	if limit < 1 || limit > 100 || (resource != "" && !resourceIDPattern.MatchString(resource)) {
		return page, ErrPage
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if !authorization.New(tx).All(actor, server, "inventory.read") {
			return authorization.ErrDenied
		}
		q := tx.Where("server_id=?", server)
		if resource != "" {
			q = q.Where("resource_id=?", resource)
		}
		if cursor != 0 {
			q = q.Where("id<?", cursor)
		}
		if err := q.Order("id desc").Limit(limit + 1).Find(&page.Items).Error; err != nil {
			return err
		}
		if len(page.Items) > limit {
			page.Items = page.Items[:limit]
			page.Next = strconv.FormatUint(page.Items[len(page.Items)-1].ID, 10)
		}
		hydrateChanges(page.Items)
		return nil
	})
	return page, err
}
