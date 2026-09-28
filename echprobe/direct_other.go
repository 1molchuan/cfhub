//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"net"
)

func bindToInterface(uintptr, string, *net.Interface) error {
	return errors.New("-direct is not supported on this system")
}
