package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xmahdi1/nexus/internal/authorization"
)

func TestNetworkInventoryKeepsHistoryAndIndependentRouteSources(t *testing.T) {
	service := fixture(t)
	obs := observation()
	var err error
	obs.Interfaces, obs.Addresses, err = parseAddresses(`[{"ifname":"eth0","mtu":1500,"operstate":"UP","address":"do-not-store","addr_info":[{"family":"inet6","local":"2001:0db8::0001","prefixlen":64,"scope":"global","valid_life_time":123}]}]`)
	if err != nil || len(obs.Addresses) != 1 || obs.Addresses[0].Address != "2001:db8::1" {
		t.Fatal("IPv6 address was not normalized", obs.Addresses, err)
	}
	v4, err := parseRoutes(`[{"dst":"default","metric":42,"nexthops":[{"gateway":"192.0.2.1","dev":"eth0","weight":1},{"gateway":"192.0.2.2","dev":"eth0","weight":2}]}]`, 4)
	if err != nil || len(v4) != 2 || v4[1].Weight != 2 {
		t.Fatal("missing IPv4 next hops", v4, err)
	}
	v6, err := parseRoutes(`[{"dst":"default","dev":"eth0","gateway":"fe80::1","metric":100}]`, 6)
	if err != nil || len(v6) != 1 || v6[0].Destination != "::/0" || v6[0].Gateway != "fe80::1" {
		t.Fatal("missing IPv6 route", v6, err)
	}
	obs.Routes = append(v4, v6...)
	service.Adapter = adapterFunc(func(context.Context, string) (Observation, error) { return obs, nil })
	actor := authorization.LegacyPrincipal
	scan := func(want string) {
		t.Helper()
		run, err := service.Discover(context.Background(), actor, "dev")
		if err != nil || run.Status != want {
			t.Fatal(run, err)
		}
		if want == "partial" && !strings.Contains(run.Warning, routes6Source) {
			t.Fatal("missing unavailable source", run.Warning)
		}
	}
	scan("succeeded")
	scan("succeeded")
	ifaceID := resourceID("dev", "interface", "eth0")
	v4ID := resourceID("dev", "route", v4[0].key())
	v6ID := resourceID("dev", "route", v6[0].key())
	obs.Interfaces[0].MTU = 1400
	obs.Routes = v4
	obs.Routes6OK = false
	scan("partial")
	snapshot, err := service.Read(actor, "dev")
	if err != nil {
		t.Fatal(err)
	}
	items := make(map[string]Item)
	for _, item := range snapshot.Items {
		items[item.ID] = item
	}
	if items[v4ID].DataState != "fresh" || items[v6ID].DataState != "stale" {
		t.Fatal("route sources were not tracked independently")
	}
	links, err := service.Relationships(actor, "dev", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, link := range links.Items {
		if link.Kind == "uses_interface" && link.TargetID == ifaceID {
			states[link.SourceID] = link.DataState
		}
	}
	if states[v6ID] != "stale" || states[v4ID] != "fresh" {
		t.Fatal("wrong route relationship state", states)
	}
	history, err := service.History(actor, "dev", ifaceID, "", 10)
	if err != nil || len(history.Items) != 2 || history.Items[0].Kind != "updated" ||
		!strings.Contains(string(history.Items[0].Before), `"mtu":1500`) ||
		!strings.Contains(string(history.Items[0].After), `"mtu":1400`) {
		t.Fatal("wrong interface change history", history, err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(raw), "do-not-store") || strings.Contains(string(raw), "valid_life_time") {
		t.Fatal("extra command output was retained", err)
	}
	obs.Routes6OK = true
	scan("succeeded")
	scan("succeeded")
	history, err = service.History(actor, "dev", v6ID, "", 10)
	if err != nil || len(history.Items) != 2 || history.Items[0].Kind != "retired" {
		t.Fatal("confirmed absence should retire the route once", history, err)
	}
}

func TestNetworkCollectorRejectsMalformedObservations(t *testing.T) {
	for _, raw := range []string{"null", "[", `[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.4","prefixlen":33}]}]`} {
		if _, _, err := parseAddresses(raw); err == nil {
			t.Fatalf("accepted invalid address inventory %q", raw)
		}
	}
	for _, raw := range []string{"null", `[{"dst":"2001:db8::/64"}]`, `[{"dst":"default","gateway":"not-an-ip"}]`} {
		if _, err := parseRoutes(raw, 4); err == nil {
			t.Fatalf("accepted invalid route inventory %q", raw)
		}
	}
}
