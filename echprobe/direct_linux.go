package main

import (
	"net"
	"syscall"
)

// SO_BINDTODEVICE; unprivileged since Linux 5.7.
func bindToInterface(fd uintptr, _ string, ifi *net.Interface) error {
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifi.Name)
}
