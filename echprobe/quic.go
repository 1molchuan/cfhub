package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// handshakeQUIC mirrors handshake() over QUIC/UDP so TCP-level RSTs can be
// separated from path-level blocking. A successful handshake with ECHAccepted
// is the signal; no HTTP/3 request is made (h3 framing is not needed to answer
// "does this path work for QUIC+ECH?").
func handshakeQUIC(ip, sni string, ech []byte, timeout time.Duration) (a attempt) {
	start := time.Now()
	defer func() { a.Millis = time.Since(start).Milliseconds() }()

	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}
	if ech != nil {
		cfg.EncryptedClientHelloConfigList = ech
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, net.JoinHostPort(ip, "443"), cfg, &quic.Config{HandshakeIdleTimeout: timeout})
	if err != nil {
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) {
			a.Error = "quic: ECH rejected by server"
		} else {
			a.Error = "quic: " + err.Error()
		}
		return a
	}
	defer conn.CloseWithError(0, "done")
	cs := conn.ConnectionState()
	a.Handshake = true
	a.ECHAccepted = cs.TLS.ECHAccepted
	a.ALPN = cs.TLS.NegotiatedProtocol
	a.HTTPStatus = "(quic handshake only)"
	return a
}
