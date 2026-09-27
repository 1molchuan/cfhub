package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// metaCheck verifies the Meta ECHConfig the DoH server is currently handing out by doing a
// real ECH handshake against a Meta host with it. Outcomes reported to /admin/health:
//
//	accepted                          → "ok"
//	rejected, retry_configs recovered → "rotated" + the recovered ECHConfigList
//	rejected, nothing recovered       → "broken"
//	network failure                   → nothing reported (cannot distinguish from blocking)
func metaCheck(doh, host string, timeout time.Duration, adminURL, token, source string, ttl int) {
	ech, publicName, _, err := queryHTTPS(doh, host)
	if err != nil || len(ech) == 0 {
		fmt.Fprintf(os.Stderr, "meta-check: DoH returned no ECH for %s: %v\n", host, err)
		os.Exit(3)
	}
	ips, err := queryA(doh, host)
	if err != nil || len(ips) == 0 {
		fmt.Fprintf(os.Stderr, "meta-check: no A for %s: %v\n", host, err)
		os.Exit(3)
	}

	var verdict string
	var recovered []byte
	var reason string
	for _, ip := range ips {
		state, retry, herr := metaHandshake(ip, host, ech, timeout)
		switch state {
		case "accepted":
			verdict = "ok"
		case "rejected":
			if len(retry) > 0 && validEchList(retry) {
				verdict, recovered = "rotated", retry
				reason = fmt.Sprintf("seed rejected by %s; %d-byte retry_configs recovered", ip, len(retry))
			} else {
				verdict = "broken"
				reason = fmt.Sprintf("seed rejected by %s; no retry_configs", ip)
			}
		default:
			fmt.Fprintf(os.Stderr, "meta-check: %s: %v\n", ip, herr)
			continue
		}
		break
	}
	if verdict == "" {
		fmt.Fprintln(os.Stderr, "meta-check: every address failed at the network layer; not reporting")
		os.Exit(4)
	}
	fmt.Fprintf(os.Stderr, "meta-check: %s public_name=%s verdict=%s %s\n", host, publicName, verdict, reason)

	payload := map[string]any{"metaEch": verdict, "source": source, "ttl": ttl, "reason": reason}
	if recovered != nil {
		payload["echConfig"] = base64.StdEncoding.EncodeToString(recovered)
	}
	if verdict == "ok" {
		// Tell the server exactly which key was verified so it can keep a working learned key
		// rather than dropping back to a seed that may no longer be valid.
		payload["verified"] = base64.StdEncoding.EncodeToString(ech)
	}
	if adminURL == "" {
		out, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(out))
		return
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, adminURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad admin url:", err)
		os.Exit(2)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := dohClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report failed:", err)
		os.Exit(4)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("%d %s\n", resp.StatusCode, bytes.TrimSpace(out))
	if resp.StatusCode != http.StatusOK {
		os.Exit(4)
	}
}

// metaHandshake returns "accepted", "rejected" (with retry_configs), or "error".
func metaHandshake(ip, sni string, ech []byte, timeout time.Duration) (string, []byte, error) {
	raw, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return "error", nil, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	conn := tls.Client(raw, &tls.Config{
		ServerName:                     sni,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: ech,
		// On rejection the server presents the public_name certificate; we only need retry_configs,
		// so accept that outer certificate rather than fail before reading them.
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	})
	err = conn.Handshake()
	if err == nil {
		if conn.ConnectionState().ECHAccepted {
			return "accepted", nil, nil
		}
		return "error", nil, errors.New("handshake completed without ECH")
	}
	var rej *tls.ECHRejectionError
	if errors.As(err, &rej) {
		return "rejected", rej.RetryConfigList, nil
	}
	return "error", nil, err
}

func validEchList(b []byte) bool {
	if len(b) < 6 || len(b) > 16384 {
		return false
	}
	declared := int(b[0])<<8 | int(b[1])
	return declared == len(b)-2
}
