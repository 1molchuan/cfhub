package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type rankedIP struct {
	IP      string
	Rate    float64 // this run
	History float64 // across retained runs (equals Rate without history)
	Runs    int
	Median  int64
	Rounds  int // this run's handshakes (all succeeded: only perfect IPs are eligible)
}

// loadKnown opens the history file (if any) and lists the IPs that have been reliable so far. They are
// re-tested every run, so the chosen pool keeps being verified even when this run's random per-domain
// sample misses them.
func loadKnown(historyPath string) (probeHistory, map[string]bool) {
	known := map[string]bool{}
	if historyPath == "" {
		return nil, known
	}
	hist := loadHistory(historyPath)
	hist.prune(time.Now())
	for ip := range hist {
		if rate, _ := hist.rate(ip); rate >= historyMinRate {
			known[ip] = true
		}
	}
	return hist, known
}

// maxKnown (set by -max-known) caps how many history IPs one run re-tests. Every IP that kept 90%
// over the last six hours counts as known, so the set only grows with each run's new candidates:
// Tencent reached 933 and its runs stopped finishing at the evening peak (2026-09-26).
var maxKnown = 300

// retestOrder lists what to re-test ahead of this run's fresh candidates, so a -budget cut drops
// fresh candidates first: the best maxKnown history IPs (success rate, then latest median), then the
// peers' IPs not among them. fromHistory is how many came from the history.
func retestOrder(hist probeHistory, known map[string]bool, peers []string) (order []string, fromHistory int) {
	type entry struct {
		ip     string
		rate   float64
		median int64
	}
	var entries []entry
	for ip := range known {
		rate, _ := hist.rate(ip)
		var median int64
		if runs := hist[ip]; len(runs) > 0 {
			median = runs[len(runs)-1].Median
		}
		entries = append(entries, entry{ip, rate, median})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].rate != entries[j].rate {
			return entries[i].rate > entries[j].rate
		}
		if entries[i].median != entries[j].median {
			return entries[i].median < entries[j].median
		}
		return entries[i].ip < entries[j].ip
	})
	seen := map[string]bool{}
	for _, e := range entries {
		if len(order) >= maxKnown {
			break
		}
		order = append(order, e.ip)
		seen[e.ip] = true
	}
	fromHistory = len(order)
	for _, ip := range peers {
		if !seen[ip] {
			order = append(order, ip)
			seen[ip] = true
		}
	}
	return order, fromHistory
}

// eligibleIPs records this run in the history and returns the IPs fit to report, best first. An IP is
// eligible only with a perfect ECH success rate in this run and, when a history file is kept, at least
// historyMinRate across recent runs; far-slower-than-fastest IPs are dropped (dropSlow); the rest rank
// by historical rate, then how many runs back it up, then median latency.
func eligibleIPs(stats []domStat, hist probeHistory, historyPath string) []rankedIP {
	// An IP listed under several candidate domains is tested once (collectRank) and shows up under
	// each of them with the same result; count it once.
	type agg struct {
		ok, rounds int
		median     int64
	}
	current := map[string]*agg{}
	for _, ds := range stats {
		for _, ip := range ds.IPs {
			if current[ip.IP] == nil {
				current[ip.IP] = &agg{ok: ip.OK, rounds: ip.Rounds, median: ip.MedianMs}
			}
		}
	}

	if hist != nil {
		now := time.Now()
		for ip, a := range current {
			if a.rounds > 0 {
				hist.record(ip, runRecord{At: now.Unix(), OK: a.ok, Rounds: a.rounds, Median: a.median})
			}
		}
		hist.prune(now)
		if err := saveHistory(historyPath, hist); err != nil {
			fmt.Fprintln(os.Stderr, "history save failed:", err)
		}
	}

	var ranked []rankedIP
	for ip, a := range current {
		if a.rounds == 0 || a.ok != a.rounds || a.median <= 0 {
			continue
		}
		r := rankedIP{IP: ip, Rate: 1, History: 1, Runs: 1, Median: a.median, Rounds: a.rounds}
		if hist != nil {
			r.History, r.Runs = hist.rate(ip)
			if r.Runs >= 2 && r.History < historyMinRate {
				continue
			}
		}
		ranked = append(ranked, r)
	}
	ranked = dropSlow(ranked)
	// Proven-over-time beats lucky-once: history rate, then how many runs back it up (capped, so once
	// an IP is proven, latency decides rather than seniority), then latency.
	const provenRuns = 3
	proven := func(runs int) int { return min(runs, provenRuns) }
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].History != ranked[j].History {
			return ranked[i].History > ranked[j].History
		}
		if pi, pj := proven(ranked[i].Runs), proven(ranked[j].Runs); pi != pj {
			return pi > pj
		}
		return ranked[i].Median < ranked[j].Median
	})
	return ranked
}

// reportRun ranks candidates like rankRun, then pushes the best IPs to the DoH
// server's /admin/preferred so the default pool tracks what actually works from
// this vantage point (see eligibleIPs). Nothing is posted if fewer than `minIPs`
// qualify, so a bad probe run cannot shrink the pool.
func reportRun(doh, resolver, candidates, target string, rounds int, timeout time.Duration, adminURL, token, source, scope string, topN, minIPs int, ttl int, historyPath string) {
	hist, known := loadKnown(historyPath)
	// Cross-test the other probers' latest reports. The server keeps only IPs every prober vouches
	// for, and each prober samples candidate domains at random, so without this most of one
	// prober's good IPs were never tried by the other and could not reach the pool at all.
	var peers []string
	if scope == "default" {
		ips, err := fetchPeerIPs(adminURL, token, source)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read other probers' reports (continuing without):", err)
		}
		peers = ips
	}
	retest, fromHistory := retestOrder(hist, known, peers)
	fmt.Fprintf(os.Stderr, "re-testing %d known IPs (%d of %d from history, %d only from other probers)\n", len(retest), fromHistory, len(known), len(retest)-fromHistory)
	stats := collectRank(doh, resolver, strings.Join(append(retest, candidates), ","), target, rounds, timeout, true)
	ranked := eligibleIPs(stats, hist, historyPath)
	var chosen []string
	for _, r := range ranked {
		chosen = append(chosen, r.IP)
		if len(chosen) >= topN {
			break
		}
	}
	fmt.Fprintf(os.Stderr, "eligible=%d chosen=%v\n", len(ranked), chosen)
	for i, r := range ranked {
		if i >= topN {
			break
		}
		fmt.Fprintf(os.Stderr, "  %-16s history=%3.0f%% over %d run(s)  median=%dms\n", r.IP, r.History*100, r.Runs, r.Median)
	}
	if len(chosen) < minIPs {
		fmt.Fprintf(os.Stderr, "only %d eligible IPs (< %d); not reporting\n", len(chosen), minIPs)
		os.Exit(3)
	}
	// One family per report: a family-6 prober uses its own source name, so its report never replaces
	// an IPv4 list, and the server combines each family over the sources that report it.
	field := "ipv4"
	if ipFamily == 6 {
		field = "ipv6"
	}
	body, _ := json.Marshal(map[string]any{field: chosen, "ttl": ttl, "source": source, "scope": scope})
	// Posting the same pool twice is harmless, so retry once on a fresh connection.
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		if attempt > 1 {
			fmt.Fprintln(os.Stderr, "report failed, retrying:", err)
			time.Sleep(2 * time.Second)
		}
		dohTransport.CloseIdleConnections()
		var status int
		if status, err = postReport(adminURL, token, body); err == nil {
			if status != http.StatusOK {
				os.Exit(4)
			}
			return
		}
	}
	fmt.Fprintln(os.Stderr, "report failed:", err)
	os.Exit(4)
}

// dropSlow removes IPs whose median handshake is far slower than the fastest eligible one. On a
// throttled path the handshake still completes, but only after retransmits (seen as 1.2–1.5s
// medians against ~250ms), and the same IPs then fail outright a fraction of the time.
func dropSlow(ranked []rankedIP) []rankedIP {
	if len(ranked) == 0 {
		return ranked
	}
	fastest := ranked[0].Median
	for _, r := range ranked {
		fastest = min(fastest, r.Median)
	}
	limit := max(2*fastest, fastest+400)
	kept := ranked[:0]
	for _, r := range ranked {
		if r.Median <= limit {
			kept = append(kept, r)
		} else {
			fmt.Fprintf(os.Stderr, "  drop %-16s median=%dms > %dms (fastest %dms)\n", r.IP, r.Median, limit, fastest)
		}
	}
	return kept
}

// fetchPeerIPs reads the server's learned-pool state (GET on the same /admin/preferred URL) and
// returns the addresses of the current family reported by default-scope sources other than self.
func fetchPeerIPs(adminURL, token, self string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, adminURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return peerIPs(body, self)
}

func peerIPs(state []byte, self string) ([]string, error) {
	var s struct {
		Learned *struct {
			Sources []struct {
				Source string   `json:"source"`
				IPv4   []string `json:"ipv4"`
				IPv6   []string `json:"ipv6"`
			} `json:"sources"`
		} `json:"learned"`
	}
	if err := json.Unmarshal(state, &s); err != nil {
		return nil, err
	}
	var out []string
	if s.Learned == nil {
		return out, nil
	}
	for _, src := range s.Learned.Sources {
		if src.Source == self {
			continue
		}
		for _, ip := range append(src.IPv4, src.IPv6...) {
			if isFamily(ip) {
				out = append(out, ip)
			}
		}
	}
	return out, nil
}

func postReport(adminURL, token string, body []byte) (int, error) {
	req, err := http.NewRequest(http.MethodPost, adminURL, bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad admin url:", err)
		os.Exit(2)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := dohClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	fmt.Printf("%d %s\n", resp.StatusCode, bytes.TrimSpace(out))
	return resp.StatusCode, nil
}
