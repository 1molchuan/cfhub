package main

import (
	"encoding/binary"
	"net"
	"strings"
	"syscall"
)

// IP_UNICAST_IF takes the interface index in network byte order for IPv4, host order for IPv6.
const ipUnicastIf = 31 // IP_UNICAST_IF and IPV6_UNICAST_IF

func bindToInterface(fd uintptr, network string, ifi *net.Interface) error {
	if strings.HasSuffix(network, "6") {
		return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, ipUnicastIf, ifi.Index)
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(ifi.Index))
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(binary.LittleEndian.Uint32(b[:])))
}
