// Package inventory stores only allowlisted observations from registered hosts.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xmahdi1/nexus/internal/audit"
	"github.com/xmahdi1/nexus/internal/auth"
	"github.com/xmahdi1/nexus/internal/authorization"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Host struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
}
type Container struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Image          string `json:"image"`
	State          string `json:"state"`
	ImageID        string `json:"imageId,omitempty"`
	Health         string `json:"health,omitempty"`
	ComposeProject string `json:"composeProject,omitempty"`
	networkIDs     []string
	volumeNames    []string
}
type Port struct {
	ContainerID string `json:"containerId"`
	Protocol    string `json:"protocol"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	TargetPort  int    `json:"targetPort"`
	Exposure    string `json:"exposure"`
}
type Observation struct {
	Host                                              Host
	Containers                                        []Container
	Ports                                             []Port
	Services                                          []ServiceUnit
	Interfaces                                        []NetworkInterface
	Addresses                                         []NetworkAddress
	Routes                                            []NetworkRoute
	BlockDevices                                      []BlockDevice
	Mounts                                            []Mount
	Resolvers                                         []Resolver
	DockerNetworks                                    []DockerNetwork
	DockerVolumes                                     []DockerVolume
	DockerImages                                      []DockerImage
	ProxyRoutes                                       []ProxyRoute
	ProxyCertificates                                 []ProxyCertificate
	NginxOK, CaddyOK, NginxTLSOK, CaddyTLSOK          bool
	ServicesOK                                        bool
	HostOK, DockerOK, SocketsOK                       bool
	AddressesOK, Routes4OK, Routes6OK                 bool
	BlockDevicesOK, MountsOK, ResolversOK             bool
	DockerNetworksOK, DockerVolumesOK, DockerImagesOK bool
}
type Adapter interface {
	Collect(context.Context, string) (Observation, error)
}
type Resource struct {
	ID             string    `gorm:"primaryKey" json:"id"`
	ServerID       string    `json:"serverId"`
	Kind           string    `json:"kind"`
	NaturalKey     string    `json:"-"`
	DisplayName    string    `json:"displayName"`
	Source         string    `json:"source"`
	LastRunID      string    `json:"lastRunId"`
	Fingerprint    string    `json:"-"`
	FirstSeenAt    time.Time `json:"firstSeenAt"`
	LastSeenAt     time.Time `json:"lastSeenAt"`
	LastVerifiedAt time.Time `json:"lastVerifiedAt"`
	DataState      string    `json:"dataState"`
}

func (Resource) TableName() string { return "inventory_resources" }

type hostRow struct {
	ResourceID string `gorm:"primaryKey"`
	Host
}

func (hostRow) TableName() string { return "inventory_hosts" }

type containerRow struct {
	ResourceID                      string `gorm:"primaryKey"`
	EngineID, Image, State          string
	ImageID, Health, ComposeProject string
}

func (containerRow) TableName() string { return "inventory_containers" }

type portRow struct {
	ResourceID string `gorm:"primaryKey"`
	Port
}

func (portRow) TableName() string { return "inventory_ports" }

type Run struct {
	ID         string     `gorm:"primaryKey" json:"id"`
	ServerID   string     `json:"serverId"`
	ActorID    string     `json:"actorId"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	Warning    string     `json:"warning"`
	Trigger    string     `json:"trigger"`
}

func (Run) TableName() string { return "discovery_runs" }

type Change struct {
	ID         uint64          `json:"id"`
	ServerID   string          `json:"serverId"`
	RunID      string          `json:"runId"`
	ResourceID string          `json:"resourceId"`
	Kind       string          `json:"kind"`
	At         time.Time       `json:"at"`
	BeforeJSON string          `json:"-"`
	AfterJSON  string          `json:"-"`
	Before     json.RawMessage `gorm:"-" json:"before,omitempty"`
	After      json.RawMessage `gorm:"-" json:"after,omitempty"`
}

func (Change) TableName() string { return "inventory_changes" }

type Item struct {
	Resource
	Details any `json:"details"`
}
type Snapshot struct {
	Next    string         `json:"next"`
	Items   []Item         `json:"items"`
	Runs    []Run          `json:"runs"`
	Changes []Change       `json:"changes"`
	Sources []SourceResult `json:"sources"`
}

var ErrBusy = errors.New("discovery already running")

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type Service struct {
	DB       *gorm.DB
	Adapter  Adapter
	Sessions *auth.Service
}

func (s *Service) Discover(ctx context.Context, actor, server string) (Run, error) {
	return s.discover(ctx, actor, server, "manual", nil)
}

func (s *Service) discover(ctx context.Context, actor, server, trigger string, guard func(*gorm.DB) bool) (Run, error) {
	var run Run
	allowedNow := func(tx *gorm.DB) bool {
		return authorization.New(tx).All(actor, server, "inventory.discover", "secrets.use") && (guard == nil || guard(tx))
	}
	id, err := audit.NewID()
	if err != nil {
		return run, err
	}
	now := time.Now().UTC()
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		if ctx.Err() != nil || !allowedNow(tx) {
			return authorization.ErrDenied
		}
		// Crashed read-only collectors cannot hold the host claim forever. A new
		// manual request or an explicitly enabled schedule may collect again.
		if err := tx.Model(&Run{}).Where("server_id=? AND status='running' AND started_at < ?", server, now.Add(-2*time.Minute)).Updates(map[string]any{"status": "interrupted", "finished_at": now, "warning": "Collector interrupted; observations may be stale."}).Error; err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&Run{}).Where("server_id=? AND status='running'", server).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return ErrBusy
		}
		run = Run{ID: id, ServerID: server, ActorID: actor, Status: "running", StartedAt: now, Trigger: trigger}
		if err := tx.Create(&run).Error; err != nil {
			return err
		}
		return authorization.New(tx).Record(actor, "inventory.discover", server, "started", id)
	})
	if err != nil {
		return run, err
	}
	collectCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	stop := make(chan struct{})
	watchDone := make(chan struct{})
	defer func() { close(stop); cancel(); <-watchDone }()
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-collectCtx.Done():
				return
			case <-ticker.C:
				if !allowedNow(s.DB) {
					cancel()
					return
				}
			}
		}
	}()
	var observation Observation
	var collectErr error
	if !allowedNow(s.DB) {
		collectErr = authorization.ErrDenied
	} else {
		observation, collectErr = s.Adapter.Collect(collectCtx, server)
	}
	if collectCtx.Err() != nil {
		collectErr = collectCtx.Err()
	}
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		// Recheck live scope before publishing any newly collected data.
		allowed := allowedNow(tx)
		finished := time.Now().UTC()
		run.FinishedAt = &finished
		if err := tx.Model(&Resource{}).Where("server_id=? AND data_state!='retired'", server).Update("data_state", "stale").Error; err != nil {
			return err
		}
		if err := tx.Model(&Relationship{}).Where("server_id=? AND data_state!='retired'", server).Update("data_state", "stale").Error; err != nil {
			return err
		}
		run.Status = "failed"
		run.Warning = "Collection failed; previous observations retained as stale."
		if !allowed {
			run.Status = "denied"
			run.Warning = "Collector authority was revoked."
		} else if collectErr == nil && observation.HostOK {
			run.Status = "succeeded"
			run.Warning = ""
			var unavailable []string
			for _, source := range collectorSources {
				if !collectorAvailable(source, observation) {
					unavailable = append(unavailable, source)
				}
			}
			if len(unavailable) > 0 {
				run.Status = "partial"
				run.Warning = "Incomplete collectors: " + strings.Join(unavailable, ", ") + ". Unconfirmed observations stay stale."
			}
			if err := s.persist(tx, run, observation, finished); err != nil {
				return err
			}
		}
		if err := tx.Save(&run).Error; err != nil {
			return err
		}
		if err := recordSources(tx, run, observation, finished); err != nil {
			return err
		}
		policy, err := collectionPolicy(tx, server)
		if err != nil {
			return err
		}
		if err := retainHistory(tx, policy, finished); err != nil {
			return err
		}
		return authorization.New(tx).Record(actor, "inventory.discover", server, run.Status, id)
	})
	if err != nil {
		finished := time.Now().UTC()
		_ = s.DB.Transaction(func(tx *gorm.DB) error {
			if e := tx.Model(&Resource{}).Where("server_id=? AND data_state!='retired'", server).Update("data_state", "stale").Error; e != nil {
				return e
			}
			if e := tx.Model(&Relationship{}).Where("server_id=? AND data_state!='retired'", server).Update("data_state", "stale").Error; e != nil {
				return e
			}
			if e := tx.Model(&Run{}).Where("id=? AND status='running'", run.ID).Updates(map[string]any{"status": "failed", "finished_at": finished, "warning": "Could not publish observations; previous data retained."}).Error; e != nil {
				return e
			}
			failed := run
			failed.Status = "failed"
			if e := recordSources(tx, failed, Observation{}, finished); e != nil {
				return e
			}
			return authorization.New(tx).Record(actor, "inventory.discover", server, "failed", run.ID)
		})
		return run, err
	}
	if run.Status == "denied" {
		return run, authorization.ErrDenied
	}
	return run, nil
}
func (s *Service) persist(tx *gorm.DB, run Run, obs Observation, now time.Time) error {
	if len(obs.Containers) > 500 || len(obs.Ports) > 10000 || len(obs.Services) > 1000 ||
		len(obs.Interfaces) > maxInterfaces || len(obs.Addresses) > maxAddresses || len(obs.Routes) > 2*maxRoutes ||
		len(obs.BlockDevices) > maxBlockDevices || len(obs.Mounts) > maxMounts || len(obs.Resolvers) > maxResolvers ||
		len(obs.DockerNetworks) > maxDockerObjects || len(obs.DockerVolumes) > maxDockerObjects || len(obs.DockerImages) > maxDockerObjects ||
		len(obs.ProxyRoutes) > 2*maxProxyRoutes || len(obs.ProxyCertificates) > 2*maxProxyCertificates {
		return errors.New("observation limit exceeded")
	}
	seen := map[string]bool{}
	put := func(kind, key, name, source string, details any, row func(string) any) error {
		if len(key) > 1024 || len(name) > 1024 {
			return errors.New("observation too long")
		}
		raw, err := json.Marshal(details)
		if err != nil {
			return err
		}
		if len(raw) > 4096 {
			return errors.New("observation too large")
		}
		id := resourceID(run.ServerID, kind, key)
		if seen[id] {
			return nil
		}
		seen[id] = true
		var old Resource
		err = tx.First(&old, "id=?", id).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		resource := Resource{ID: id, ServerID: run.ServerID, Kind: kind, NaturalKey: key, DisplayName: name, Source: source, LastRunID: run.ID, Fingerprint: hash(string(raw)), FirstSeenAt: now, LastSeenAt: now, LastVerifiedAt: now, DataState: "fresh"}
		change := "observed"
		before := ""
		if err == nil {
			resource.FirstSeenAt = old.FirstSeenAt
			change = ""
			if old.Fingerprint != resource.Fingerprint || old.DataState == "retired" {
				change = "updated"
				previous, e := detailsFor(tx, old)
				if e != nil {
					return e
				}
				before, e = summary(old.DisplayName, previous)
				if e != nil {
					return e
				}
			}
		}
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&resource).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(row(id)).Error; err != nil {
			return err
		}
		if change != "" {
			after, e := summary(name, details)
			if e != nil {
				return e
			}
			return tx.Create(&Change{ServerID: run.ServerID, RunID: run.ID, ResourceID: id, Kind: change, At: now, BeforeJSON: before, AfterJSON: after}).Error
		}
		return nil
	}
	if err := put("host", "registered-host", obs.Host.Hostname, "ssh", obs.Host, func(id string) any { return &hostRow{ResourceID: id, Host: obs.Host} }); err != nil {
		return err
	}
	for _, container := range obs.Containers {
		c := container
		if !obs.DockerOK {
			break
		}
		if err := put("container", c.ID, c.Name, "docker", c, func(id string) any {
			return &containerRow{ResourceID: id, EngineID: c.ID, Image: c.Image, State: c.State,
				ImageID: c.ImageID, Health: c.Health, ComposeProject: c.ComposeProject}
		}); err != nil {
			return err
		}
		if c.ComposeProject != "" {
			project := ComposeProject{Name: c.ComposeProject}
			if err := put("compose_project", project.Name, project.Name, "docker", project, func(id string) any {
				return &composeProjectRow{ResourceID: id, ComposeProject: project}
			}); err != nil {
				return err
			}
		}
	}
	if obs.ServicesOK {
		for _, unit := range obs.Services {
			u := unit
			if !validService(u) {
				return errors.New("invalid service observation")
			}
			if err := put("service", u.Unit, u.Unit, "systemd", u, func(id string) any { return &serviceRow{ResourceID: id, ServiceUnit: u} }); err != nil {
				return err
			}
		}
	}
	for _, port := range obs.Ports {
		p := port
		if (p.Exposure == "listener" && !obs.SocketsOK) || (p.Exposure != "listener" && !obs.DockerOK) {
			continue
		}
		if p.Port < 1 || p.Port > 65535 || p.TargetPort < 0 || p.TargetPort > 65535 {
			return errors.New("invalid port")
		}
		key := portNaturalKey(p)
		if err := put("port", key, fmt.Sprintf("%s %s:%d", p.Protocol, p.Address, p.Port), map[bool]string{true: "ss", false: "docker"}[p.Exposure == "listener"], p, func(id string) any { return &portRow{ResourceID: id, Port: p} }); err != nil {
			return err
		}
	}
	if obs.AddressesOK {
		for _, iface := range obs.Interfaces {
			if err := put("interface", iface.Name, iface.Name, addressSource, iface, func(id string) any {
				return &interfaceRow{ResourceID: id, NetworkInterface: iface}
			}); err != nil {
				return err
			}
		}
		for _, address := range obs.Addresses {
			if err := put("address", address.key(), address.cidr(), addressSource, address, func(id string) any {
				return &addressRow{ResourceID: id, NetworkAddress: address}
			}); err != nil {
				return err
			}
		}
	}
	for _, route := range obs.Routes {
		if !collectorAvailable(route.source(), obs) {
			continue
		}
		if err := put("route", route.key(), route.Destination, route.source(), route, func(id string) any {
			return &routeRow{ResourceID: id, NetworkRoute: route}
		}); err != nil {
			return err
		}
	}
	if obs.BlockDevicesOK {
		for _, device := range obs.BlockDevices {
			if err := put("block_device", device.Name, device.Name, blockDevicesSource, device, func(id string) any {
				return &blockDeviceRow{ResourceID: id, BlockDevice: device}
			}); err != nil {
				return err
			}
		}
	}
	if obs.MountsOK {
		for _, mount := range obs.Mounts {
			if err := put("mount", mount.key(), mount.Target, mountsSource, mount, func(id string) any {
				return &mountRow{ResourceID: id, Mount: mount}
			}); err != nil {
				return err
			}
		}
	}
	if obs.ResolversOK {
		for _, resolver := range obs.Resolvers {
			if err := put("resolver", resolver.Address, resolver.Address, resolversSource, resolver, func(id string) any {
				return &resolverRow{ResourceID: id, Resolver: resolver}
			}); err != nil {
				return err
			}
		}
	}
	if obs.DockerNetworksOK {
		for _, network := range obs.DockerNetworks {
			if err := put("docker_network", network.ID, network.Name, dockerNetworkSource, network, func(id string) any {
				return &dockerNetworkRow{ResourceID: id, DockerNetwork: network}
			}); err != nil {
				return err
			}
		}
	}
	if obs.DockerVolumesOK {
		for _, volume := range obs.DockerVolumes {
			if err := put("docker_volume", volume.Name, volume.Name, dockerVolumeSource, volume, func(id string) any {
				return &dockerVolumeRow{ResourceID: id, DockerVolume: volume}
			}); err != nil {
				return err
			}
		}
	}
	if obs.DockerImagesOK {
		for _, image := range obs.DockerImages {
			if err := put("docker_image", image.ID, image.name(), dockerImageSource, image, func(id string) any {
				return &dockerImageRow{ResourceID: id, DockerImage: image}
			}); err != nil {
				return err
			}
		}
	}
	for _, route := range obs.ProxyRoutes {
		if err := put("proxy_route", route.key(), route.name(), route.source(), route, func(id string) any {
			return &proxyRouteRow{ResourceID: id, ProxyRoute: route}
		}); err != nil {
			return err
		}
	}
	for _, certificate := range obs.ProxyCertificates {
		if err := put("tls_certificate", certificate.key(), certificate.name(), certificate.source(), certificate, func(id string) any {
			return &proxyCertificateRow{ResourceID: id, ProxyCertificate: certificate}
		}); err != nil {
			return err
		}
	}
	var missing []Resource
	if err := tx.Where("server_id=? AND data_state='stale'", run.ServerID).Find(&missing).Error; err != nil {
		return err
	}
	for _, r := range missing {
		if !collectorAvailable(r.Source, obs) {
			continue
		}
		if err := tx.Model(&r).Updates(map[string]any{"data_state": "retired", "last_run_id": run.ID}).Error; err != nil {
			return err
		}
		previous, e := detailsFor(tx, r)
		if e != nil {
			return e
		}
		before, e := summary(r.DisplayName, previous)
		if e != nil {
			return e
		}
		if err := tx.Create(&Change{ServerID: run.ServerID, RunID: run.ID, ResourceID: r.ID, Kind: "retired", At: now, BeforeJSON: before}).Error; err != nil {
			return err
		}
	}
	return s.persistRelationships(tx, run, obs, now)
}
func (s *Service) Read(actor, server string) (Snapshot, error) {
	return s.ReadPage(actor, server, "", 200)
}
func (s *Service) ReadPage(actor, server, after string, limit int) (Snapshot, error) {
	result := Snapshot{Items: []Item{}, Runs: []Run{}, Changes: []Change{}, Sources: []SourceResult{}}
	if limit < 1 || limit > 200 || (after != "" && !resourceIDPattern.MatchString(after)) {
		return result, ErrPage
	}
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		if !authorization.New(tx).All(actor, server, "inventory.read") {
			return authorization.ErrDenied
		}
		var resources []Resource
		if err := tx.Where("server_id=? AND id>?", server, after).Order("id").Limit(limit + 1).Find(&resources).Error; err != nil {
			return err
		}
		if len(resources) > limit {
			resources = resources[:limit]
			result.Next = resources[len(resources)-1].ID
		}
		cutoff, err := freshnessCutoff(tx, server)
		if err != nil {
			return err
		}
		for _, resource := range resources {
			if resource.DataState == "fresh" && resource.LastVerifiedAt.Before(cutoff) {
				resource.DataState = "stale"
			}
			details, err := detailsFor(tx, resource)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, Item{resource, details})
		}
		if err := tx.Where("server_id=?", server).Order("started_at desc, id desc").Limit(20).Find(&result.Runs).Error; err != nil {
			return err
		}
		if len(result.Runs) > 0 {
			if err := tx.Where("server_id=? AND run_id=?", server, result.Runs[0].ID).Order("source").Find(&result.Sources).Error; err != nil {
				return err
			}
		}
		if err := tx.Where("server_id=?", server).Order("id desc").Limit(100).Find(&result.Changes).Error; err != nil {
			return err
		}
		hydrateChanges(result.Changes)
		return nil
	})
	return result, err
}

// Only normalized summaries are persisted. No raw command output is retained.
func clean(value string) string { return strings.Trim(strings.TrimSpace(value), "\"") }
