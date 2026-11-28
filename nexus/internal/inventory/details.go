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
	LastRunID      string    `json:"lastRunId"`
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

var collectorSources = [...]string{
	"ssh", "docker", "ss", "systemd", addressSource, routes4Source, routes6Source,
	blockDevicesSource, mountsSource, resolversSource, dockerNetworkSource, dockerVolumeSource, dockerImageSource,
	nginxSource, caddySource, nginxTLSSource, caddyTLSSource,
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
	case addressSource:
		return obs.AddressesOK
	case routes4Source:
		return obs.Routes4OK
	case routes6Source:
		return obs.Routes6OK
	case blockDevicesSource:
		return obs.BlockDevicesOK
	case mountsSource:
		return obs.MountsOK
	case resolversSource:
		return obs.ResolversOK
	case dockerNetworkSource:
		return obs.DockerNetworksOK
	case dockerVolumeSource:
		return obs.DockerVolumesOK
	case dockerImageSource:
		return obs.DockerImagesOK
	case nginxSource:
		return obs.NginxOK
	case caddySource:
		return obs.CaddyOK
	case nginxTLSSource:
		return obs.NginxTLSOK
	case caddyTLSSource:
		return obs.CaddyTLSOK
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
		return Container{ID: row.EngineID, Name: r.DisplayName, Image: row.Image, State: row.State,
			ImageID: row.ImageID, Health: row.Health, ComposeProject: row.ComposeProject}, err
	case "port":
		var row portRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.Port, err
	case "service":
		var row serviceRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.ServiceUnit, err
	case "interface":
		var row interfaceRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.NetworkInterface, err
	case "address":
		var row addressRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.NetworkAddress, err
	case "route":
		var row routeRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.NetworkRoute, err
	case "block_device":
		var row blockDeviceRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.BlockDevice, err
	case "mount":
		var row mountRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.Mount, err
	case "resolver":
		var row resolverRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.Resolver, err
	case "docker_network":
		var row dockerNetworkRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.DockerNetwork, err
	case "docker_volume":
		var row dockerVolumeRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.DockerVolume, err
	case "docker_image":
		var row dockerImageRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.DockerImage, err
	case "compose_project":
		var row composeProjectRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.ComposeProject, err
	case "proxy_route":
		var row proxyRouteRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.ProxyRoute, err
	case "tls_certificate":
		var row proxyCertificateRow
		err := tx.First(&row, "resource_id=?", r.ID).Error
		return row.ProxyCertificate, err
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
		row := Relationship{ID: id, ServerID: run.ServerID, SourceID: from, TargetID: to, Kind: kind, Source: source, LastRunID: run.ID, FirstSeenAt: now, LastVerifiedAt: now, DataState: "fresh"}
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "id"}}, DoUpdates: clause.AssignmentColumns([]string{"last_verified_at", "data_state", "last_run_id"})}).Create(&row).Error
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
	interfaces := make(map[string]string, len(obs.Interfaces))
	if obs.AddressesOK {
		for _, iface := range obs.Interfaces {
			id := resourceID(run.ServerID, "interface", iface.Name)
			interfaces[iface.Name] = id
			if err := put(host, id, "has_interface", addressSource); err != nil {
				return err
			}
		}
		for _, address := range obs.Addresses {
			if iface := interfaces[address.InterfaceName]; iface != "" {
				if err := put(iface, resourceID(run.ServerID, "address", address.key()), "has_address", addressSource); err != nil {
					return err
				}
			}
		}
	}
	for _, route := range obs.Routes {
		source := route.source()
		if !collectorAvailable(source, obs) {
			continue
		}
		id := resourceID(run.ServerID, "route", route.key())
		if err := put(host, id, "has_route", source); err != nil {
			return err
		}
		if iface := interfaces[route.InterfaceName]; iface != "" {
			if err := put(id, iface, "uses_interface", source); err != nil {
				return err
			}
		}
	}
	devices := make(map[string]string, len(obs.BlockDevices))
	if obs.BlockDevicesOK {
		for _, device := range obs.BlockDevices {
			id := resourceID(run.ServerID, "block_device", device.Name)
			devices[device.DeviceNumber] = id
			if err := put(host, id, "has_device", blockDevicesSource); err != nil {
				return err
			}
		}
	}
	if obs.MountsOK {
		for _, mount := range obs.Mounts {
			id := resourceID(run.ServerID, "mount", mount.key())
			if err := put(host, id, "has_mount", mountsSource); err != nil {
				return err
			}
			if device := devices[mount.DeviceNumber]; device != "" {
				if err := put(id, device, "uses_device", mountsSource); err != nil {
					return err
				}
			}
		}
	}
	if obs.ResolversOK {
		for _, resolver := range obs.Resolvers {
			if err := put(host, resourceID(run.ServerID, "resolver", resolver.Address), "configured_resolver", resolversSource); err != nil {
				return err
			}
		}
	}
	if err := dockerRelationships(run.ServerID, host, obs, put); err != nil {
		return err
	}
	if err := proxyRelationships(run.ServerID, host, obs, put); err != nil {
		return err
	}
	for _, source := range collectorSources {
		if collectorAvailable(source, obs) {
			missing := tx.Model(&Relationship{}).Where("server_id=? AND source=? AND data_state='stale'", run.ServerID, source)
			if !obs.AddressesOK {
				missing = missing.Where("kind != ?", "uses_interface")
			}
			if !obs.BlockDevicesOK {
				missing = missing.Where("kind != ?", "uses_device")
			}
			if source == "docker" {
				if !obs.DockerNetworksOK {
					missing = missing.Where("kind != ?", "attached_to_network")
				}
				if !obs.DockerVolumesOK {
					missing = missing.Where("kind != ?", "mounts_volume")
				}
				if !obs.DockerImagesOK {
					missing = missing.Where("kind != ?", "uses_image")
				}
			}
			if err := missing.Updates(map[string]any{"data_state": "retired", "last_run_id": run.ID}).Error; err != nil {
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
		cutoff, err := freshnessCutoff(tx, server)
		if err != nil {
			return err
		}
		for i := range page.Items {
			if page.Items[i].DataState == "fresh" && page.Items[i].LastVerifiedAt.Before(cutoff) {
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
