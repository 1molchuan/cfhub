package main

import (
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSampleIPv4StaysInRangeOnePer24(t *testing.T) {
	_, a, _ := net.ParseCIDR("104.16.0.0/13")
	_, b, _ := net.ParseCIDR("188.114.96.0/20")
	got, err := sampleIPv4([]string{"104.16.0.0/13", "188.114.96.0/20"}, 200, rand.New(rand.NewSource(1)))
	if err != nil || len(got) != 200 {
		t.Fatalf("got %d addresses, err %v", len(got), err)
	}
	prefixes := map[string]bool{}
	for _, s := range got {
		ip := net.ParseIP(s).To4()
		if ip == nil || !(a.Contains(ip) || b.Contains(ip)) {
			t.Fatalf("%s is outside the ranges", s)
		}
		if ip[3] == 0 || ip[3] == 255 {
			t.Fatalf("%s is a .0/.255 address", s)
		}
		p := s[:strings.LastIndex(s, ".")]
		if prefixes[p] {
			t.Fatalf("two addresses in %s.0/24", p)
		}
		prefixes[p] = true
	}
}

func TestSampleIPv4StopsWhenRangesRunOut(t *testing.T) {
	got, err := sampleIPv4([]string{"198.51.100.0/24", "203.0.113.0/23"}, 10, rand.New(rand.NewSource(1)))
	if err != nil || len(got) != 3 {
		t.Fatalf("three /24s hold at most three picks, got %v (err %v)", got, err)
	}
}

func TestSampleIPv4RejectsIPv6AndHugeRanges(t *testing.T) {
	for _, bad := range []string{"2606:4700::/32", "0.0.0.0/0", "not-a-cidr"} {
		if _, err := sampleIPv4([]string{bad}, 1, rand.New(rand.NewSource(1))); err == nil {
			t.Errorf("%s should be rejected", bad)
		}
	}
}

// testAll must test IPs concurrently, but one IP's rounds strictly one after another.
func TestTestAllIsParallelAcrossIPsSequentialWithinOne(t *testing.T) {
	defer func(h func(string, string, []byte, time.Duration) attempt, p int) { handshake, rankParallel = h, p }(handshake, rankParallel)
	rankParallel = 4
	var inFlight, peak atomic.Int32
	var mu sync.Mutex
	perIP := map[string]int{}
	busy := map[string]bool{}
	handshake = func(ip, sni string, _ []byte, _ time.Duration) attempt {
		mu.Lock()
		if busy[ip] {
			mu.Unlock()
			t.Errorf("two rounds for %s at once", ip)
			return attempt{}
		}
		busy[ip] = true
		perIP[ip]++
		mu.Unlock()
		n := inFlight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		inFlight.Add(-1)
		mu.Lock()
		busy[ip] = false
		mu.Unlock()
		if ip == "192.0.2.9" {
			return attempt{Error: "tcp: timeout"}
		}
		return attempt{Handshake: true, ECHAccepted: true, HTTPStatus: "HTTP/1.1 200 OK", Millis: 50}
	}
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.9"}
	stats := testAll(ips, []string{"x.com", "linux.do"}, []byte{1}, 6, time.Second, true)
	if len(stats) != len(ips) {
		t.Fatalf("stats for %d of %d IPs", len(stats), len(ips))
	}
	if peak.Load() < 2 || peak.Load() > 4 {
		t.Fatalf("peak concurrency %d, want 2..4", peak.Load())
	}
	if st := stats["192.0.2.1"]; st.OK != 6 || st.Rounds != 6 || st.Rate != 1 || st.MedianMs != 50 {
		t.Fatalf("good IP: %+v", st)
	}
	if st := stats["192.0.2.9"]; st.Rounds != 1 || st.OK != 0 || perIP["192.0.2.9"] != 1 {
		t.Fatalf("a failing IP must stop after its first round with stopOnFail: %+v", st)
	}
}
