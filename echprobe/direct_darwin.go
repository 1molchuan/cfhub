package main

import (
	"net"
	"strings"
	"syscall"
)

// macOS scoped routing: a socket bound with IP_BOUND_IF / IPV6_BOUND_IF uses that interface's own
// default route, not the TUN's.
const (
	ipBoundIf   = 25  // IP_BOUND_IF
	ipv6BoundIf = 125 // IPV6_BOUND_IF
)

func bindToInterface(fd uintptr, network string, ifi *net.Interface) error {
	if strings.HasSuffix(network, "6") {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6BoundIf, ifi.Index)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBoundIf, ifi.Index)
}
