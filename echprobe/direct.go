package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

// -direct: every connection (the handshakes measured, the DoH lookups, the hub API, self-updates)
// leaves through the machine's physical interface, bypassing a local proxy's TUN device (sing-box,
// Clash, WireGuard...). Otherwise such a machine measures the proxy's line: 2026-09-28, a campus Mac
// behind sing-box would have reported a foreign proxy exit instead of CERNET. The binding is the
// one proxies use for their own direct traffic (IP_BOUND_IF, SO_BINDTODEVICE, IP_UNICAST_IF).
// Names resolve through a public resolver over the same interface: a TUN's DNS may answer fake IPs.

// directDialer is nil unless -direct is set; dialer() hands out copies of it.
var directDialer *net.Dialer

const directDNS = "223.5.5.5:53"

// dialer returns a dialer with this timeout, bound to the -direct interface if one is set.
func dialer(timeout time.Duration) *net.Dialer {
	if directDialer == nil {
		return &net.Dialer{Timeout: timeout}
	}
	d := *directDialer
	d.Timeout = timeout
	return &d
}

// Interfaces never picked by -direct auto: bridges and links for VMs, containers and Apple services.
var virtualPrefixes = []string{"bridge", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "awdl", "llw", "anpi", "ap1", "utun", "tun", "tap", "wg", "tailscale", "zt"}

// isPPP reports a PPP link (pppoe-wan on OpenWrt, ppp0): point-to-point without a hardware address
// like a tunnel, but on a PPPoE router it carries the line's public address (2026-10-01).
func isPPP(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "ppp")
}

// pickInterface chooses the interface -direct auto binds to: up, with a hardware address, not a
// tunnel (point-to-point) or virtual bridge, with a global address of the family; the first in the
// system's order (the built-in port before later ones). PPP links count as physical.
func pickInterface(ifaces []net.Interface, addrs func(net.Interface) ([]net.Addr, error), family int) (*net.Interface, []net.IP, error) {
	for i := range ifaces {
		ifi := ifaces[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if !isPPP(ifi.Name) && (ifi.Flags&net.FlagPointToPoint != 0 || len(ifi.HardwareAddr) == 0) {
			continue
		}
		virtual := false
		for _, p := range virtualPrefixes {
			virtual = virtual || strings.HasPrefix(strings.ToLower(ifi.Name), p)
		}
		if virtual {
			continue
		}
		list, err := addrs(ifi)
		if err != nil {
			continue
		}
		var ips []net.IP
		for _, a := range list {
			ipn, ok := a.(*net.IPNet)
			if !ok || !ipn.IP.IsGlobalUnicast() || (ipn.IP.To4() != nil) != (family == 4) {
				continue
			}
			ips = append(ips, ipn.IP)
		}
		if len(ips) > 0 {
			return &ifi, ips, nil
		}
	}
	return nil, nil, fmt.Errorf("no physical interface with a global IPv%d address", family)
}

// setupDirect binds every connection of this run to the named interface ("auto": pickInterface).
func setupDirect(name string, family int) error {
	var ifi *net.Interface
	var ips []net.IP
	var err error
	if name == "auto" {
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		if ifi, ips, err = pickInterface(ifaces, func(i net.Interface) ([]net.Addr, error) { return i.Addrs() }, family); err != nil {
			return err
		}
	} else {
		if ifi, err = net.InterfaceByName(name); err != nil {
			return err
		}
		list, _ := ifi.Addrs()
		for _, a := range list {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() {
				ips = append(ips, ipn.IP)
			}
		}
	}
	control := func(network, _ string, c syscall.RawConn) error {
		var bindErr error
		if err := c.Control(func(fd uintptr) { bindErr = bindToInterface(fd, network, ifi) }); err != nil {
			return err
		}
		return bindErr
	}
	base := &net.Dialer{Control: control}
	base.Resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second, Control: control}).DialContext(ctx, network, directDNS)
	}}
	directDialer = base
	// Connections already open went through the tunnel: drop them so none is reused.
	dohTransport.DialContext = dialer(10 * time.Second).DialContext
	dohTransport.CloseIdleConnections()
	hubTransport := hubClient.Transport.(*http.Transport)
	hubTransport.CloseIdleConnections() // hubDial binds new ones through dialer()
	fmt.Fprintf(os.Stderr, "direct: every connection via %s %v, names via %s\n", ifi.Name, ips, directDNS)
	return nil
}
