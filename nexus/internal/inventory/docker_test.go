package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/testdocker"
	"github.com/xmahdi1/nexus/internal/testssh"
	"golang.org/x/crypto/ssh"
)

func TestDockerDiscoveryRelationshipsAndPartialCollection(t *testing.T) {
	service := fixture(t)
	obs := observation()
	containerID := obs.Containers[0].ID
	imageID := "sha256:" + strings.Repeat("b", 64)
	networkID := strings.Repeat("c", 64)
	raw := fmt.Sprintf(`{"id":%q,"name":"/db","image":"db:1","imageId":%q,"state":"running","health":"healthy",
		"composeProject":"demo","networks":[%q],"volumes":["db_data"],
		"env":["ignore-secret"],"labels":{"extra":"ignore-label"}}`, containerID, imageID, networkID)
	var err error
	obs.Containers, obs.Ports, err = parseDocker(strings.ReplaceAll(raw, "\n", ""))
	if err != nil {
		t.Fatal(err)
	}
	obs.DockerNetworks, err = parseDockerNetworks(fmt.Sprintf(`{"id":%q,"name":"demo_default","driver":"bridge","scope":"local"}`, networkID))
	if err != nil {
		t.Fatal(err)
	}
	obs.DockerVolumes, err = parseDockerVolumes(`{"name":"db_data","driver":"local","scope":"local","mountpoint":"ignore-path","options":"ignore-options"}`)
	if err != nil {
		t.Fatal(err)
	}
	obs.DockerImages, err = parseDockerImages(fmt.Sprintf("{\"id\":%q,\"repository\":\"db\",\"tag\":\"latest\",\"digest\":\"<none>\"}\n"+
		`{"id":%q,"repository":"db","tag":"1","digest":"<none>"}`, imageID, imageID))
	if err != nil || len(obs.DockerImages) != 1 || strings.Join(obs.DockerImages[0].References, ",") != "db:1,db:latest" {
		t.Fatal("image tags not normalized", obs.DockerImages, err)
	}
	service.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	actor := authorization.LegacyPrincipal
	scan := func(want string) {
		t.Helper()
		if run, err := service.Discover(context.Background(), actor, "dev"); err != nil || run.Status != want {
			t.Fatal(run, err)
		}
	}
	scan("succeeded")
	scan("succeeded")
	obs.DockerVolumesOK = false
	obs.DockerVolumes = nil
	obs.Containers[0].Health = "unhealthy"
	scan("partial")
	page, err := service.Relationships(actor, "dev", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]string{}
	for _, link := range page.Items {
		if link.SourceID == resourceID("dev", "container", containerID) {
			links[link.Kind] = link.DataState
		}
	}
	if links["mounts_volume"] != "stale" || links["attached_to_network"] != "fresh" ||
		links["uses_image"] != "fresh" || links["belongs_to_project"] != "fresh" {
		t.Fatal("Docker links lost their provenance", links)
	}
	snapshot, err := service.Read(actor, "dev")
	if err != nil {
		t.Fatal(err)
	}
	items := map[string]Item{}
	for _, item := range snapshot.Items {
		items[item.Kind] = item
	}
	if items["docker_volume"].DataState != "stale" || items["container"].Details.(Container).Health != "unhealthy" ||
		len(items["docker_image"].Details.(DockerImage).References) != 2 {
		t.Fatal("Docker resource facts were not persisted")
	}
	history, err := service.History(actor, "dev", items["container"].ID, "", 10)
	if err != nil || len(history.Items) != 2 || history.Items[0].Kind != "updated" {
		t.Fatal("missing health transition or duplicate changes", history, err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(data), "ignore-") {
		t.Fatal("unexpected Docker metadata in inventory", err)
	}
	obs.DockerVolumesOK = true
	scan("succeeded")
	snapshot, err = service.Read(actor, "dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range snapshot.Items {
		if item.Kind == "docker_volume" && item.DataState != "retired" {
			t.Fatal("successfully observed volume absence should retire the record", item)
		}
	}
}

func TestDisposableDockerInventoryCommands(t *testing.T) {
	lab := testdocker.New(t)
	lab.Write("ignore-secret", "alpine:3.21")
	recipe, err := os.ReadFile(lab.Recipe)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(recipe), "    network_mode: none\n",
		"    healthcheck:\n      test: [CMD, 'true']\n      interval: 1s\n", 1)
	if err := os.WriteFile(lab.Recipe, []byte(body+"networks:\n  default:\n    internal: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lab.Must("up", "-d", "--wait", "--wait-timeout", "20")
	id := strings.TrimSpace(lab.Must("ps", "-q", "stateful"))
	if len(id) != 64 || !containerID.MatchString(id) {
		t.Fatal("unexpected owned fixture ID")
	}
	filter := " --filter label=com.docker.compose.project=" + lab.Project
	allow := map[string]string{
		"command -v docker": "", dockerContainers: filter, dockerInspect + id: "",
		dockerNetworks: filter, dockerVolumes: filter, dockerImages: " --filter reference=alpine:3.21",
	}
	client := testssh.Client(t, func(channel ssh.Channel, command string) uint32 {
		suffix, ok := allow[command]
		if !ok {
			return 126
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", command+suffix)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "DOCKER_CONFIG=" + lab.Directory}
		var diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr = channel, io.MultiWriter(channel.Stderr(), &diagnostics)
		if err := cmd.Run(); err != nil {
			t.Logf("owned Docker fixture command failed: %v: %s", err, diagnostics.String())
			return 1
		}
		return 0
	})
	var obs Observation
	collectDocker(context.Background(), client, &obs)
	if !obs.DockerOK || !obs.DockerNetworksOK || !obs.DockerVolumesOK || !obs.DockerImagesOK ||
		len(obs.Containers) != 1 || len(obs.DockerNetworks) != 1 || len(obs.DockerVolumes) != 1 || len(obs.DockerImages) != 1 {
		t.Fatal("real Docker collection incomplete", obs)
	}
	container := obs.Containers[0]
	if container.ImageID != obs.DockerImages[0].ID || container.ComposeProject != lab.Project || container.Health != "healthy" ||
		len(container.networkIDs) != 1 || container.networkIDs[0] != obs.DockerNetworks[0].ID ||
		len(container.volumeNames) != 1 || container.volumeNames[0] != obs.DockerVolumes[0].Name {
		t.Fatal("real Docker references did not match", container)
	}
	data, err := json.Marshal(obs)
	if err != nil || strings.Contains(string(data), "ignore-secret") || strings.Contains(string(data), lab.Directory) {
		t.Fatal("real Docker projection included a secret or backing path", err)
	}
}
