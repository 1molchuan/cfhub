//go:build !linux && !darwin

package main

// clampMSS is not available here (Windows has no TCP_MAXSEG option); connections keep the default.
func clampMSS(uintptr, int) error { return nil }
