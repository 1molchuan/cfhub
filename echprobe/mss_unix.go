//go:build linux || darwin

package main

import "syscall"

// clampMSS caps the TCP segment size of a socket before it connects (also what it advertises).
func clampMSS(fd uintptr, mss int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}
