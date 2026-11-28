package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

const (
	addressCommand = "LC_ALL=C ip -j address show"
	routes4Command = "LC_ALL=C ip -j -4 route show table main"
	routes6Command = "LC_ALL=C ip -j -6 route show table main"
	addressSource  = "ip-address"
	routes4Source  = "ip-route-v4"
	routes6Source  = "ip-route-v6"
	maxInterfaces  = 512
	maxAddresses   = 4096
	maxRoutes      = 4096
)

var (
	networkName = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,15}$`)
	networkWord = regexp.MustCompile(`^[A-Za-z0-9_-]{0,32}$`)
	errNetwork  = errors.New("invalid or unsupported network observation")
)

type NetworkInterface struct {
	Name  string `json:"name"`
	MTU   int    `json:"mtu"`
	State string `json:"state"`
}

type NetworkAddress struct {
	InterfaceName string `json:"interfaceName"`
	Address       string `json:"address"`
	PrefixLength  int    `json:"prefixLength"`
	Scope         string `json:"scope"`
}

func (a NetworkAddress) cidr() string {
	return a.Address + "/" + strconv.Itoa(a.PrefixLength)
}

func (a NetworkAddress) key() string { return a.InterfaceName + " " + a.cidr() }

type NetworkRoute struct {
	Destination   string `json:"destination"`
	Gateway       string `json:"gateway"`
	InterfaceName string `json:"interfaceName"`
	Family        int    `json:"family"`
	Metric        uint32 `json:"metric"`
	Type          string `json:"type"`
	Weight        uint32 `json:"weight"`
	NextHopID     uint32 `json:"nextHopId"`
}

func (r NetworkRoute) source() string {
	if r.Family == 4 {
		return routes4Source
	}
	return routes6Source
}

func (r NetworkRoute) key() string {
	return fmt.Sprintf("%s %s %s %s %d %d", r.Destination, r.Type, r.InterfaceName, r.Gateway, r.Metric, r.NextHopID)
}

type interfaceRow struct {
	ResourceID string `gorm:"primaryKey"`
	NetworkInterface
}

func (interfaceRow) TableName() string { return "inventory_interfaces" }

type addressRow struct {
	ResourceID string `gorm:"primaryKey"`
	NetworkAddress
}

func (addressRow) TableName() string { return "inventory_addresses" }

type routeRow struct {
	ResourceID string `gorm:"primaryKey"`
	NetworkRoute
}

func (routeRow) TableName() string { return "inventory_routes" }

func parseAddresses(raw string) ([]NetworkInterface, []NetworkAddress, error) {
	var rows []struct {
		Name      string `json:"ifname"`
		MTU       int    `json:"mtu"`
		State     string `json:"operstate"`
		Addresses []struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Prefix *int   `json:"prefixlen"`
			Scope  string `json:"scope"`
		} `json:"addr_info"`
	}
	if !decodeInventoryJSON(raw, &rows) || rows == nil || len(rows) > maxInterfaces {
		return nil, nil, errNetwork
	}
	interfaces := make([]NetworkInterface, 0, len(rows))
	var addresses []NetworkAddress
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		if !networkName.MatchString(row.Name) || seen[row.Name] || row.MTU < 0 || row.MTU > 1<<31-1 || !networkWord.MatchString(row.State) {
			return nil, nil, errNetwork
		}
		seen[row.Name] = true
		interfaces = append(interfaces, NetworkInterface{Name: row.Name, MTU: row.MTU, State: row.State})
		for _, entry := range row.Addresses {
			if entry.Family != "inet" && entry.Family != "inet6" {
				continue
			}
			ip, err := netip.ParseAddr(entry.Local)
			if err != nil || ip.Zone() != "" || ip.Is4() != (entry.Family == "inet") || entry.Prefix == nil ||
				!netip.PrefixFrom(ip, *entry.Prefix).IsValid() || !networkWord.MatchString(entry.Scope) || len(addresses) >= maxAddresses {
				return nil, nil, errNetwork
			}
			addresses = append(addresses, NetworkAddress{InterfaceName: row.Name, Address: ip.String(), PrefixLength: *entry.Prefix, Scope: entry.Scope})
		}
	}
	return interfaces, addresses, nil
}

type routeHop struct {
	Gateway string
	Device  string `json:"dev"`
	Weight  uint32
	Via     struct {
		Host string
	}
}

func parseRoutes(raw string, family int) ([]NetworkRoute, error) {
	var rows []struct {
		routeHop
		Destination string `json:"dst"`
		Metric      uint32
		Type        string
		NextHopID   uint32     `json:"nhid"`
		Hops        []routeHop `json:"nexthops"`
	}
	if !decodeInventoryJSON(raw, &rows) || rows == nil || len(rows) > maxRoutes {
		return nil, errNetwork
	}
	var routes []NetworkRoute
	for _, row := range rows {
		dst, ok := routeDestination(row.Destination, family)
		if !ok || !networkWord.MatchString(row.Type) {
			return nil, errNetwork
		}
		if row.Type == "" {
			row.Type = "unicast"
		}
		hops := row.Hops
		if len(hops) == 0 {
			hops = []routeHop{row.routeHop}
		}
		for _, hop := range hops {
			if len(routes) >= maxRoutes || hop.Device != "" && !networkName.MatchString(hop.Device) {
				return nil, errNetwork
			}
			if hop.Gateway == "" {
				hop.Gateway = hop.Via.Host
			}
			if hop.Gateway != "" {
				gateway, err := netip.ParseAddr(hop.Gateway)
				if err != nil || gateway.Zone() != "" {
					return nil, errNetwork
				}
				hop.Gateway = gateway.String()
			}
			routes = append(routes, NetworkRoute{Destination: dst, Gateway: hop.Gateway, InterfaceName: hop.Device, Family: family, Metric: row.Metric, Type: row.Type, Weight: hop.Weight, NextHopID: row.NextHopID})
		}
	}
	return routes, nil
}

func routeDestination(value string, family int) (string, bool) {
	if value == "default" {
		value = "::/0"
		if family == 4 {
			value = "0.0.0.0/0"
		}
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" {
			return "", false
		}
		prefix = netip.PrefixFrom(ip, ip.BitLen())
	}
	if prefix.Addr().Is4() != (family == 4) {
		return "", false
	}
	return prefix.Masked().String(), true
}

func decodeInventoryJSON(raw string, target any) bool {
	return len(raw) <= 1<<20 && json.Unmarshal([]byte(raw), target) == nil
}
