package handlers

import "testing"

func TestFirewallRejectsInvalidNetworkInputs(t *testing.T) {
	for _, port := range []string{"0", "65536", "99999/tcp", "80:79/tcp", "80:99999/udp", "80:81", "443;true", "-1"} {
		if validPort(port) {
			t.Fatal("accepted invalid port", port)
		}
	}
	for _, port := range []string{"22", "65535/udp", "8000:8010/tcp"} {
		if !validPort(port) {
			t.Fatal("rejected valid port", port)
		}
	}
	for _, source := range []string{"...", "999.0.0.1", "10.0.0.0/99", "::1/129", "10.0.0.1;true"} {
		if validFrom(source) {
			t.Fatal("accepted invalid source", source)
		}
	}
	for _, source := range []string{"", "Anywhere", "127.0.0.1", "10.0.0.0/8", "::1", "2001:db8::/32"} {
		if !validFrom(source) {
			t.Fatal("rejected valid source", source)
		}
	}
}
