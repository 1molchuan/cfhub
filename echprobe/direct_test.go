package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestPickInterfaceSkipsTunnelsAndBridges(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	up := net.FlagUp | net.FlagBroadcast
	ifaces := []net.Interface{
		{Index: 1, Name: "lo0", Flags: net.FlagUp | net.FlagLoopback},
		{Index: 2, Name: "utun4", Flags: net.FlagUp | net.FlagPointToPoint},          // sing-box TUN
		{Index: 3, Name: "bridge100", Flags: up, HardwareAddr: mac},                  // VM bridge
		{Index: 4, Name: "en5", Flags: up, HardwareAddr: mac},                        // no global address
		{Index: 5, Name: "en0", Flags: up, HardwareAddr: mac},                        // the campus port
		{Index: 6, Name: "en1", Flags: up, HardwareAddr: mac},                        // Wi-Fi, later in order
		{Index: 7, Name: "wg0", Flags: up | net.FlagPointToPoint, HardwareAddr: mac}, // WireGuard
	}
	addrs := map[string][]net.Addr{
		"utun4":     {&net.IPNet{IP: net.ParseIP("10.255.0.1"), Mask: net.CIDRMask(30, 32)}},
		"bridge100": {&net.IPNet{IP: net.ParseIP("192.168.64.1"), Mask: net.CIDRMask(24, 32)}},
		"en5":       {&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}},
		"en0": {
			&net.IPNet{IP: net.ParseIP("111.186.1.20"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:da8:8000:e195::4bef"), Mask: net.CIDRMask(64, 128)},
		},
		"en1": {&net.IPNet{IP: net.ParseIP("10.180.3.4"), Mask: net.CIDRMask(16, 32)}},
	}
	lookup := func(i net.Interface) ([]net.Addr, error) { return addrs[i.Name], nil }
	for _, family := range []int{4, 6} {
		ifi, ips, err := pickInterface(ifaces, lookup, family)
		if err != nil || ifi.Name != "en0" || len(ips) != 1 {
			t.Fatalf("IPv%d: %v %v %v; want en0 with its one address", family, ifi, ips, err)
		}
	}
	if _, _, err := pickInterface(ifaces[:4], lookup, 4); err == nil {
		t.Fatal("picked a tunnel, bridge or address-less interface")
	}
}

// With CFPROBE_TEST_DIRECT=auto (or an interface name), print the public address seen with and
// without -direct: behind a TUN proxy the two must differ.
func TestDirectReachesTheInternetOutsideTheTunnel(t *testing.T) {
	name := os.Getenv("CFPROBE_TEST_DIRECT")
	if name == "" {
		t.Skip("set CFPROBE_TEST_DIRECT=auto on a machine behind a TUN proxy")
	}
	get := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, _ := httpRequest(ctx, "https://api.ipify.org")
		resp, err := hubClient.Do(req)
		if err != nil {
			return "error: " + err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	before := get()
	if err := setupDirect(name, 4); err != nil {
		t.Fatal(err)
	}
	after := get()
	t.Logf("public IPv4 without -direct: %s, with -direct: %s", before, after)
	if err := setupDirect(name, 6); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, _ := httpRequest(ctx, "https://api6.ipify.org")
		if resp, err := hubClient.Do(req); err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Logf("public IPv6 with -direct: %s", b)
		} else {
			t.Logf("IPv6 with -direct: %v", err)
		}
	}
}

func httpRequest(ctx context.Context, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
}
