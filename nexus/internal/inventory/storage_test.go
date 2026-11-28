package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/authorization"
)

func TestStorageAndResolverInventoryUsesOnlyNormalizedFields(t *testing.T) {
	service := fixture(t)
	obs := observation()
	var err error
	obs.BlockDevices, err = parseBlockDevices(`{"blockdevices":[{"kname":"vda1","maj:min":"254:1","type":"part","size":123456789,"ro":true,"serial":"ignore-device-serial"}]}`)
	if err != nil || len(obs.BlockDevices) != 1 || obs.BlockDevices[0].SizeBytes != 123456789 || !obs.BlockDevices[0].ReadOnly {
		t.Fatal("block device normalization failed", obs.BlockDevices, err)
	}
	obs.Mounts, err = parseMounts(`{"filesystems":[{"target":"/srv/test data","fstype":"ext4","maj:min":"254:1","options":"ignore-mount-options","source":"ignore-mount-source"}]}`)
	if err != nil || len(obs.Mounts) != 1 {
		t.Fatal("mount normalization failed", obs.Mounts, err)
	}
	obs.Resolvers, err = parseResolvers("127.0.0.53\n2001:0db8::53\n2001:db8::53\n")
	if err != nil || len(obs.Resolvers) != 2 || obs.Resolvers[1].Address != "2001:db8::53" || obs.Resolvers[1].Priority != 2 {
		t.Fatal("resolver order or normalization failed", obs.Resolvers, err)
	}
	service.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	actor := authorization.LegacyPrincipal
	if run, err := service.Discover(context.Background(), actor, "dev"); err != nil || run.Status != "succeeded" {
		t.Fatal(run, err)
	}
	obs.Mounts = nil
	obs.MountsOK = false
	if run, err := service.Discover(context.Background(), actor, "dev"); err != nil || run.Status != "partial" || !strings.Contains(run.Warning, mountsSource) {
		t.Fatal("unavailable mounts were not reported", run, err)
	}
	snapshot, err := service.Read(actor, "dev")
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, item := range snapshot.Items {
		states[item.Kind] = item.DataState
	}
	if states["mount"] != "stale" || states["block_device"] != "fresh" || states["resolver"] != "fresh" {
		t.Fatal("independent source freshness missing", states)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(raw), "ignore-") {
		t.Fatal("unexpected metadata retained", err)
	}
	links, err := service.Relationships(actor, "dev", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links.Items {
		if link.Kind == "uses_device" && link.SourceName == "/srv/test data" && link.TargetName == "vda1" && link.DataState == "stale" {
			return
		}
	}
	t.Fatal("missing device link with preserved freshness", links.Items)
}
