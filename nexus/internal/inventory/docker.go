package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

const (
	dockerCLI        = "docker --host unix:///var/run/docker.sock "
	dockerContainers = dockerCLI + "ps -aq --no-trunc"
	dockerInspect    = dockerCLI + `inspect --type container --format '{"id":{{json .Id}},"name":{{json .Name}},` +
		`"image":{{json .Config.Image}},"imageId":{{json .Image}},"state":{{json .State.Status}},` +
		`"health":{{with index .State "Health"}}{{json (index . "Status")}}{{else}}""{{end}},` +
		`"composeProject":{{with index .Config "Labels"}}{{json (index . "com.docker.compose.project")}}{{else}}""{{end}},` +
		`"networks":[{{$sep := ""}}{{range index .NetworkSettings "Networks"}}{{$sep}}{{json (index . "NetworkID")}}{{$sep = ","}}{{end}}],` +
		`"volumes":[{{$sep := ""}}{{range index . "Mounts"}}{{if eq .Type "volume"}}{{$sep}}{{json (index . "Name")}}{{$sep = ","}}{{end}}{{end}}],` +
		`"exposed":{{json (index .Config "ExposedPorts")}},"published":{{json (index .NetworkSettings "Ports")}}}' `
	dockerNetworks      = dockerCLI + `network ls --no-trunc --format '{"id":{{json .ID}},"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}}}'`
	dockerVolumes       = dockerCLI + `volume ls --format '{"name":{{json .Name}},"driver":{{json .Driver}},"scope":{{json .Scope}}}'`
	dockerImages        = dockerCLI + `image ls --all --digests --no-trunc --format '{"id":{{json .ID}},"repository":{{json .Repository}},"tag":{{json .Tag}},"digest":{{json .Digest}}}'`
	dockerNetworkSource = "docker-network"
	dockerVolumeSource  = "docker-volume"
	dockerImageSource   = "docker-image"
	maxDockerObjects    = 2000
	maxContainerLinks   = 256
	maxDockerLinks      = 10000
)

var (
	dockerNetworkID    = regexp.MustCompile(`^[a-z0-9]{12,64}$`)
	dockerObjectName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)
	composeProjectName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
	imageDigest        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	imageRepository    = regexp.MustCompile(`^[a-zA-Z0-9_.:/\[\]-]{1,255}$`)
	imageTag           = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}$`)
	errDockerList      = errors.New("invalid or oversized Docker observation")
)

type DockerNetwork struct {
	ID     string `json:"id" gorm:"column:engine_id"`
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Scope  string `json:"scope"`
}

type DockerVolume struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Scope  string `json:"scope"`
}

type DockerImage struct {
	ID         string   `json:"id" gorm:"column:engine_id"`
	References []string `json:"references" gorm:"serializer:json"`
}

func (image DockerImage) name() string {
	if len(image.References) != 0 {
		return image.References[0]
	}
	return image.ID
}

type ComposeProject struct {
	Name string `json:"name"`
}

type dockerNetworkRow struct {
	ResourceID string `gorm:"primaryKey"`
	DockerNetwork
}

func (dockerNetworkRow) TableName() string { return "inventory_docker_networks" }

type dockerVolumeRow struct {
	ResourceID string `gorm:"primaryKey"`
	DockerVolume
}

func (dockerVolumeRow) TableName() string { return "inventory_docker_volumes" }

type dockerImageRow struct {
	ResourceID string `gorm:"primaryKey"`
	DockerImage
}

func (dockerImageRow) TableName() string { return "inventory_docker_images" }

type composeProjectRow struct {
	ResourceID string `gorm:"primaryKey"`
	ComposeProject
}

func (composeProjectRow) TableName() string { return "inventory_compose_projects" }

func collectDocker(ctx context.Context, client *ssh.Client, obs *Observation) {
	if _, err := run(ctx, client, "command -v docker"); err != nil {
		return
	}
	if containers, ports, err := collectContainers(ctx, client); err == nil {
		obs.Containers, obs.DockerOK = containers, true
		obs.Ports = append(obs.Ports, ports...)
	}
	if raw, err := run(ctx, client, dockerNetworks); err == nil {
		if rows, err := parseDockerNetworks(raw); err == nil {
			obs.DockerNetworks, obs.DockerNetworksOK = rows, true
		}
	}
	if raw, err := run(ctx, client, dockerVolumes); err == nil {
		if rows, err := parseDockerVolumes(raw); err == nil {
			obs.DockerVolumes, obs.DockerVolumesOK = rows, true
		}
	}
	if raw, err := run(ctx, client, dockerImages); err == nil {
		if rows, err := parseDockerImages(raw); err == nil {
			obs.DockerImages, obs.DockerImagesOK = rows, true
		}
	}
}

func collectContainers(ctx context.Context, client *ssh.Client) ([]Container, []Port, error) {
	raw, err := run(ctx, client, dockerContainers)
	if err != nil {
		return nil, nil, err
	}
	ids := strings.Fields(raw)
	if len(ids) > 500 {
		return nil, nil, errDockerList
	}
	for _, id := range ids {
		if !containerID.MatchString(id) {
			return nil, nil, errDockerList
		}
	}
	if len(ids) == 0 {
		return nil, nil, nil
	}
	raw, err = run(ctx, client, dockerInspect+strings.Join(ids, " "))
	if err != nil {
		return nil, nil, err
	}
	containers, ports, err := parseDocker(raw)
	if err != nil || len(containers) != len(ids) {
		return nil, nil, errDockerList
	}
	for i, id := range ids {
		if containers[i].ID != id {
			return nil, nil, errDockerList
		}
	}
	return containers, ports, nil
}

func decodeDockerList[T any](raw string) ([]T, error) {
	if len(raw) > 1<<20 {
		return nil, errDockerList
	}
	var rows []T
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var row T
		if len(rows) >= maxDockerObjects || json.Unmarshal([]byte(line), &row) != nil {
			return nil, errDockerList
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func parseDockerNetworks(raw string) ([]DockerNetwork, error) {
	rows, err := decodeDockerList[DockerNetwork](raw)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if seen[row.ID] || !dockerNetworkID.MatchString(row.ID) || !dockerText(row.Name, 255) ||
			!dockerText(row.Driver, 128) || !dockerText(row.Scope, 32) {
			return nil, errDockerList
		}
		seen[row.ID] = true
	}
	return rows, nil
}

func parseDockerVolumes(raw string) ([]DockerVolume, error) {
	rows, err := decodeDockerList[DockerVolume](raw)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if seen[row.Name] || !dockerObjectName.MatchString(row.Name) || !dockerText(row.Driver, 128) ||
			!dockerText(row.Scope, 32) {
			return nil, errDockerList
		}
		seen[row.Name] = true
	}
	return rows, nil
}

func parseDockerImages(raw string) ([]DockerImage, error) {
	type referenceRow struct{ ID, Repository, Tag, Digest string }
	rows, err := decodeDockerList[referenceRow](raw)
	if err != nil {
		return nil, err
	}
	references := make(map[string][]string)
	for _, row := range rows {
		id := normalizeImageID(row.ID)
		if id == "" {
			return nil, errDockerList
		}
		names := references[id]
		if row.Repository != "<none>" {
			if !imageRepository.MatchString(row.Repository) {
				return nil, errDockerList
			}
			if row.Tag != "<none>" && row.Tag != "" {
				if !imageTag.MatchString(row.Tag) {
					return nil, errDockerList
				}
				names = append(names, row.Repository+":"+row.Tag)
			}
			if row.Digest != "<none>" && row.Digest != "" {
				if !strings.HasPrefix(row.Digest, "sha256:") || normalizeImageID(row.Digest) == "" {
					return nil, errDockerList
				}
				names = append(names, row.Repository+"@"+row.Digest)
			}
		}
		references[id] = names
	}
	images := make([]DockerImage, 0, len(references))
	for id, names := range references {
		slices.Sort(names)
		names = slices.Compact(names)
		if len(names) == 0 {
			names = []string{}
		}
		if len(strings.Join(names, "\n")) > 3000 || len(names) > 64 {
			return nil, errDockerList
		}
		images = append(images, DockerImage{ID: id, References: names})
	}
	slices.SortFunc(images, func(a, b DockerImage) int { return strings.Compare(a.ID, b.ID) })
	return images, nil
}

func dockerText(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsFunc(value, unicode.IsControl)
}

func normalizeImageID(raw string) string {
	id := strings.TrimPrefix(raw, "sha256:")
	if !imageDigest.MatchString(id) {
		return ""
	}
	return "sha256:" + id
}

func dockerRelationships(server, host string, obs Observation, put func(from, to, kind, source string) error) error {
	networks := make(map[string]string, len(obs.DockerNetworks))
	if obs.DockerNetworksOK {
		for _, network := range obs.DockerNetworks {
			id := resourceID(server, "docker_network", network.ID)
			networks[network.ID] = id
			if err := put(host, id, "has_docker_network", dockerNetworkSource); err != nil {
				return err
			}
		}
	}
	volumes := make(map[string]string, len(obs.DockerVolumes))
	if obs.DockerVolumesOK {
		for _, volume := range obs.DockerVolumes {
			id := resourceID(server, "docker_volume", volume.Name)
			volumes[volume.Name] = id
			if err := put(host, id, "has_docker_volume", dockerVolumeSource); err != nil {
				return err
			}
		}
	}
	images := make(map[string]string, len(obs.DockerImages))
	if obs.DockerImagesOK {
		for _, image := range obs.DockerImages {
			id := resourceID(server, "docker_image", image.ID)
			images[image.ID] = id
			if err := put(host, id, "has_docker_image", dockerImageSource); err != nil {
				return err
			}
		}
	}
	if !obs.DockerOK {
		return nil
	}
	for _, container := range obs.Containers {
		id := resourceID(server, "container", container.ID)
		if container.ComposeProject != "" {
			project := resourceID(server, "compose_project", container.ComposeProject)
			if err := put(id, project, "belongs_to_project", "docker"); err != nil {
				return err
			}
		}
		if image := images[container.ImageID]; image != "" {
			if err := put(id, image, "uses_image", "docker"); err != nil {
				return err
			}
		}
		for _, key := range container.networkIDs {
			if network := networks[key]; network != "" {
				if err := put(id, network, "attached_to_network", "docker"); err != nil {
					return err
				}
			}
		}
		for _, key := range container.volumeNames {
			if volume := volumes[key]; volume != "" {
				if err := put(id, volume, "mounts_volume", "docker"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
