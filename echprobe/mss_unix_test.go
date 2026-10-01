//go:build linux || darwin

package main

import (
	"context"
	"net"
	"syscall"
	"testing"
)

func TestHubDialClampsTheSegmentSize(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			defer c.Close()
			_, _ = c.Read(make([]byte, 1))
		}
	}()
	conn, err := hubDial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mss int
	var getErr error
	_ = raw.Control(func(fd uintptr) {
		mss, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	})
	if getErr != nil || mss <= 0 || mss > hubMSS {
		t.Fatalf("TCP_MAXSEG on a hub connection = %d (%v), want 1..%d", mss, getErr, hubMSS)
	}
	t.Logf("hub connection MSS %d", mss)
}
