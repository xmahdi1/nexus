package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/authorization"
	"github.com/xmahdi1/nexus/internal/models"
)

func TestServicesRelationshipsAndBoundedChangeHistory(t *testing.T) {
	s := fixture(t)
	obs := observation()
	obs.Services = []ServiceUnit{{Unit: "ssh.service", Load: "loaded", Active: "active", Sub: "running"}}
	s.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	scan := func() {
		t.Helper()
		if _, err := s.Discover(context.Background(), authorization.LegacyPrincipal, "dev"); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	scan()
	links, err := s.Relationships(authorization.LegacyPrincipal, "dev", "", 200)
	if err != nil || len(links.Items) != 4 {
		t.Fatal("missing observed relationships", links, err)
	}
	for _, link := range links.Items {
		if link.SourceName == "" || link.TargetName == "" || link.DataState != "fresh" {
			t.Fatal("missing relationship provenance", link)
		}
	}
	id := resourceID("dev", "service", "ssh.service")
	obs.Services[0].Active = "failed"
	obs.Services[0].Sub = "failed"
	scan()
	history, err := s.History(authorization.LegacyPrincipal, "dev", id, "", 1)
	if err != nil || len(history.Items) != 1 || history.Next == "" || history.Items[0].Kind != "updated" {
		t.Fatal("history pagination", history, err)
	}
	var before, after struct {
		Details ServiceUnit `json:"details"`
	}
	if json.Unmarshal(history.Items[0].Before, &before) != nil || json.Unmarshal(history.Items[0].After, &after) != nil || before.Details.Active != "active" || after.Details.Active != "failed" {
		t.Fatal("before/after states missing")
	}
	older, err := s.History(authorization.LegacyPrincipal, "dev", id, history.Next, 1)
	if err != nil || len(older.Items) != 1 || older.Items[0].Kind != "observed" || older.Next != "" {
		t.Fatal("history duplicated", older, err)
	}
	obs.ServicesOK = false
	obs.Services = nil
	scan()
	page, err := s.Read(authorization.LegacyPrincipal, "dev")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range page.Items {
		if item.ID == id && item.DataState != "stale" {
			t.Fatal("unavailable collector retired service")
		}
	}
	links, err = s.Relationships(authorization.LegacyPrincipal, "dev", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links.Items {
		if link.Source == "systemd" && link.DataState != "stale" {
			t.Fatal("unavailable collector retired relationship")
		}
	}
	obs.ServicesOK = true
	scan()
	scan()
	history, err = s.History(authorization.LegacyPrincipal, "dev", id, "", 100)
	if err != nil || len(history.Items) != 3 || history.Items[0].Kind != "retired" || len(history.Items[0].After) != 0 {
		t.Fatal("service retirement duplicated", history, err)
	}
	links, err = s.Relationships(authorization.LegacyPrincipal, "dev", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range links.Items {
		if link.Source == "systemd" && link.DataState != "retired" {
			t.Fatal("confirmed absence did not retire relationship")
		}
	}
	if err := s.DB.Create(&models.Server{ID: "other", Name: "Other", Host: "192.0.2.2", Username: "fixture"}).Error; err != nil {
		t.Fatal(err)
	}
	other, err := s.History(authorization.LegacyPrincipal, "other", id, "", 100)
	if err != nil || len(other.Items) != 0 {
		t.Fatal("cross-server history", err)
	}
	if _, err := s.History("unknown", "dev", id, "", 100); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("history grant bypass", err)
	}
	if _, err := s.Relationships("unknown", "dev", "", 100); !errors.Is(err, authorization.ErrDenied) {
		t.Fatal("relationship grant bypass", err)
	}
	first, err := s.Relationships(authorization.LegacyPrincipal, "dev", "", 2)
	if err != nil || len(first.Items) != 2 || first.Next == "" {
		t.Fatal("relationship page unbounded", err)
	}
	second, err := s.Relationships(authorization.LegacyPrincipal, "dev", first.Next, 2)
	if err != nil || len(second.Items) != 2 || first.Items[1].ID >= second.Items[0].ID {
		t.Fatal("relationship cursor duplicate", err)
	}
}

func TestServiceCollectorAcceptsOnlyRuntimeProperties(t *testing.T) {
	valid := "SubState=running\nId=ssh.service\nActiveState=active\nLoadState=loaded\n"
	units, err := parseServices(valid)
	if err != nil || len(units) != 1 || units[0].Unit != "ssh.service" {
		t.Fatal("valid properties rejected", err)
	}
	for _, raw := range []string{"bad", valid + "Environment=SECRET", valid + "Id=second.service", strings.Replace(valid, "ssh.service", "$(bad).service", 1), strings.Replace(valid, "LoadState=loaded\n", "", 1), valid + "\n" + valid} {
		if _, err := parseServices(raw); err == nil {
			t.Fatal("malformed properties accepted")
		}
	}
	if units, err := parseServices(""); err != nil || len(units) != 0 {
		t.Fatal("empty complete collector rejected")
	}
	if strings.Contains(serviceCommand, "Environment") || !strings.Contains(serviceCommand, "--property=Id,LoadState,ActiveState,SubState") {
		t.Fatal("collector broadened")
	}
}
