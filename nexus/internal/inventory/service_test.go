package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/db"
	"github.com/xmahdi1/nexus/internal/models"
	"path/filepath"
	"strings"
	"testing"
)

type adapterFunc func(context.Context, string) (Observation, error)

func (f adapterFunc) Collect(c context.Context, s string) (Observation, error) { return f(c, s) }
func fixture(t *testing.T) *Service {
	t.Helper()
	database, err := db.Init(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := database.DB()
	t.Cleanup(func() { conn.Close() })
	if err := database.Create(&models.Server{ID: "dev", Name: "Fixture", Host: "127.0.0.1", Port: 1, Username: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	return &Service{DB: database}
}
func observation() Observation {
	return Observation{Host: Host{Hostname: "fixture", OS: "Fixture Linux", Kernel: "6.fixture"}, HostOK: true, DockerOK: true, SocketsOK: true, ServicesOK: true, Containers: []Container{{ID: strings.Repeat("a", 64), Name: "db", Image: "db:1", State: "running"}}, Ports: []Port{{Protocol: "tcp", Address: "127.0.0.1", Port: 22, Exposure: "listener"}, {ContainerID: strings.Repeat("a", 64), Protocol: "tcp", Port: 3306, TargetPort: 3306, Exposure: "container_internal"}}}
}
func TestIdempotenceChangesProvenanceAndUnreachableStale(t *testing.T) {
	s := fixture(t)
	obs := observation()
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	for i := 0; i < 2; i++ {
		run, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
		if err != nil || run.Status != "succeeded" {
			t.Fatal(run, err)
		}
	}
	var changes int64
	s.DB.Model(&Change{}).Count(&changes)
	if changes != 4 {
		t.Fatal("spurious changes", changes)
	}
	snapshot, err := s.Read(authorization.LegacyPrincipal, "dev")
	if err != nil || len(snapshot.Items) != 4 {
		t.Fatal("normalization", len(snapshot.Items), err)
	}
	firstSeen := snapshot.Items[0].FirstSeenAt
	for _, item := range snapshot.Items {
		if item.Source == "" || item.DataState != "fresh" {
			t.Fatal("missing provenance")
		}
		if p, ok := item.Details.(Port); ok && p.Port == 3306 && (p.Exposure != "container_internal" || p.Address != "") {
			t.Fatal("internal port treated as public")
		}
	}
	obs.Containers[0].Image = "db:2"
	if _, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev"); err != nil {
		t.Fatal(err)
	}
	s.DB.Model(&Change{}).Count(&changes)
	if changes != 5 {
		t.Fatal("change not detected", changes)
	}
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) {
		return Observation{}, errors.New("NEVER-STORE-REMOTE-SECRET")
	})
	run, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
	if err != nil || run.Status != "failed" {
		t.Fatal(run, err)
	}
	snapshot, err = s.Read(authorization.LegacyPrincipal, "dev")
	if err != nil || len(snapshot.Items) != 4 {
		t.Fatal("unreachable host deleted inventory", err)
	}
	if !snapshot.Items[0].FirstSeenAt.Equal(firstSeen) {
		t.Fatal("first seen overwritten")
	}
	for _, item := range snapshot.Items {
		if item.DataState != "stale" {
			t.Fatal("failed observation remained fresh")
		}
	}
	raw, _ := json.Marshal(snapshot)
	if strings.Contains(string(raw), "NEVER-STORE") {
		t.Fatal("stored error/secret")
	}
}
func TestPartialCollectorPreservesAndFullAbsenceRetiresOnce(t *testing.T) {
	s := fixture(t)
	obs := observation()
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
	obs.DockerOK = false
	obs.Containers = nil
	obs.Ports = nil
	run, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
	if err != nil || run.Status != "partial" {
		t.Fatal(run, err)
	}
	snapshot, _ := s.Read(authorization.LegacyPrincipal, "dev")
	for _, item := range snapshot.Items {
		if item.Kind == "container" && item.DataState != "stale" {
			t.Fatal("partial collection retired container")
		}
	}
	obs.DockerOK = true
	for i := 0; i < 2; i++ {
		if _, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev"); err != nil {
			t.Fatal(err)
		}
	}
	var count int64
	s.DB.Model(&Change{}).Where("kind='retired'").Count(&count)
	if count != 3 {
		t.Fatal("retirement duplicated", count)
	}
}
func TestClaimsRecheckRevokedActorAndBoundReadPages(t *testing.T) {
	s := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) {
		close(entered)
		<-release
		return observation(), nil
	})
	go func() {
		_, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
		result <- err
	}()
	<-entered
	if _, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev"); !errors.Is(err, ErrBusy) {
		t.Fatal("overlap admitted", err)
	}
	if err := s.DB.Where("principal_id=? AND role_id='admin'", authorization.LegacyPrincipal).Delete(&authorization.Grant{}).Error; err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("revoked scan published", err)
	}
	var count int64
	s.DB.Model(&Resource{}).Count(&count)
	if count != 0 {
		t.Fatal("revoked scan wrote resources")
	}
	if _, err := s.Read("unknown", "dev"); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("unknown actor read inventory")
	}
	s = fixture(t)
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return observation(), nil })
	s.Discover(context.Background(), authorization.LegacyPrincipal, "dev")
	page, err := s.ReadPage(authorization.LegacyPrincipal, "dev", "", 2)
	if err != nil || len(page.Items) != 2 || page.Next == "" {
		t.Fatal("page unbounded", err)
	}
	second, err := s.ReadPage(authorization.LegacyPrincipal, "dev", page.Next, 2)
	if err != nil || len(second.Items) != 2 || page.Items[1].ID >= second.Items[0].ID {
		t.Fatal("pagination duplicate", err)
	}
}
func TestParsersDoNotCollectEnvironmentOrInferReachability(t *testing.T) {
	containers, ports, err := parseDocker(`{"id":"aaaaaaaaaaaa","name":"/db","image":"db:1","state":"running","exposed":{"3306/tcp":{}},"published":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]},"Env":["SECRET=NEVER-COLLECT"]}`)
	if err != nil || len(containers) != 1 || len(ports) != 2 {
		t.Fatal(err, ports)
	}
	data, _ := json.Marshal(struct {
		Containers []Container
		Ports      []Port
	}{containers, ports})
	if strings.Contains(string(data), "NEVER-COLLECT") || strings.Contains(string(data), "public") {
		t.Fatal("unsafe output")
	}
	listeners, err := parseSockets("tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\nudp UNCONN 0 0 [::]:53 [::]:*")
	if err != nil || len(listeners) != 2 || listeners[1].Address != "::" {
		t.Fatal("socket parsing", err, listeners)
	}
	if _, err := parseSockets("bad output"); err == nil {
		t.Fatal("unsupported format accepted as empty")
	}
	if _, _, err := parseDocker(`{"id":"$(bad)","name":"db"}`); err == nil {
		t.Fatal("command-like ID accepted")
	}
	output := &boundedOutput{}
	if _, err := output.Write(make([]byte, (1<<20)+1)); err == nil {
		t.Fatal("unbounded collector")
	}
}
