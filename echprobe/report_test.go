package main

import "testing"

func TestPeerIPsSkipsOwnReportAndJunk(t *testing.T) {
	state := []byte(`{"ok":true,"learned":{"ipv4":["1.1.1.1"],"sources":[
		{"source":"aliyun-shanghai","ipv4":["104.16.1.1","104.16.1.2"]},
		{"source":"tencent-beijing","ipv4":["172.64.1.1","not-an-ip","2606:4700::1"]}]}}`)
	got, err := peerIPs(state, "aliyun-shanghai")
	if err != nil || len(got) != 1 || got[0] != "172.64.1.1" {
		t.Fatalf("peerIPs = %v, %v; want only tencent's IPv4", got, err)
	}
	if got, err := peerIPs([]byte(`{"ok":true,"learned":null}`), "x"); err != nil || len(got) != 0 {
		t.Fatalf("no learned pool: got %v, %v", got, err)
	}
}

func TestPeerIPsFollowsTheFamily(t *testing.T) {
	defer func() { ipFamily = 4 }()
	ipFamily = 6
	state := []byte(`{"learned":{"sources":[
		{"source":"a-v6","ipv4":[],"ipv6":["2606:4700::6812:b76"]},
		{"source":"b","ipv4":["104.16.1.1"]}]}}`)
	got, err := peerIPs(state, "self")
	if err != nil || len(got) != 1 || got[0] != "2606:4700::6812:b76" {
		t.Fatalf("family 6 peers = %v, %v", got, err)
	}
	if isFamily("104.16.1.1") || !isFamily("2606:4700::1") || isFamily("cf.example") {
		t.Fatal("isFamily is wrong for family 6")
	}
}

func TestRoundOKRequiresA200FromTheZone(t *testing.T) {
	for _, c := range []struct {
		a    attempt
		want bool
	}{
		{attempt{Handshake: true, ECHAccepted: true, HTTPStatus: "HTTP/1.1 200 OK"}, true},
		// Enterprise-only edge IP: the ECH handshake succeeds, then Cloudflare refuses the zone.
		{attempt{Handshake: true, ECHAccepted: true, HTTPStatus: "HTTP/1.1 403 Forbidden"}, false},
		{attempt{Handshake: true, ECHAccepted: false, HTTPStatus: "HTTP/1.1 200 OK"}, false},
		{attempt{Handshake: false, Error: "tls: connection reset by peer"}, false},
		{attempt{Handshake: true, ECHAccepted: true, HTTPStatus: "(quic handshake only)"}, true},
	} {
		if got := roundOK(c.a); got != c.want {
			t.Errorf("roundOK(%+v) = %v, want %v", c.a, got, c.want)
		}
	}
}

func TestDropSlowKeepsOnlyUnthrottledIPs(t *testing.T) {
	// Medians measured from Aliyun Shanghai: two clean IPs, three that only complete after retransmits.
	ranked := []rankedIP{
		{IP: "104.16.242.120", Median: 1357},
		{IP: "172.64.154.211", Median: 246},
		{IP: "104.18.21.69", Median: 1251},
		{IP: "172.64.153.208", Median: 254},
		{IP: "104.17.105.37", Median: 606},
	}
	kept := dropSlow(ranked)
	var ips []string
	for _, r := range kept {
		ips = append(ips, r.IP)
	}
	// limit = max(2×246, 246+400) = 646ms; order is preserved.
	want := []string{"172.64.154.211", "172.64.153.208", "104.17.105.37"}
	if len(ips) != len(want) {
		t.Fatalf("kept %v, want %v", ips, want)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Fatalf("kept %v, want %v", ips, want)
		}
	}
}
