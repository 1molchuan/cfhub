package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// rankRun benchmarks candidate preferred-domains: each is resolved through the
// DoH server (mirroring the server-side ?cf= rewrite), then every resolved IP
// is dialed `rounds` times with a real ECH handshake using `target` as SNI.
// Candidates are ranked by ECH success rate, then median latency.
type ipStat struct {
	IP        string  `json:"ip"`
	OK        int     `json:"ok"`
	Rounds    int     `json:"rounds"`
	MedianMs  int64   `json:"median_ms"`
	LastError string  `json:"last_error,omitempty"`
	Rate      float64 `json:"rate"`
}

type domStat struct {
	Domain   string   `json:"domain"`
	IPs      []ipStat `json:"ips"`
	BestRate float64  `json:"best_rate"`
	BestMs   int64    `json:"best_median_ms"`
	BestIP   string   `json:"best_ip"`
	Error    string   `json:"error,omitempty"`
}

func rankRun(doh, candidates, target string, rounds int, timeout time.Duration) {
	results := collectRank(doh, doh, candidates, target, rounds, timeout, false)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(results)
}

// roundOK: ECH accepted and, over TCP, the site's /cdn-cgi/trace answered 200. The status matters:
// a Cloudflare edge IP that does not serve the zone still completes the ECH handshake, then answers
// 403 (error 1034). QUIC rounds make no HTTP request, so the handshake alone decides.
func roundOK(a attempt) bool {
	if !a.Handshake || !a.ECHAccepted {
		return false
	}
	if strings.HasPrefix(a.HTTPStatus, "(quic") {
		return true
	}
	fields := strings.Fields(a.HTTPStatus)
	return len(fields) >= 2 && fields[1] == "200"
}

// ipsPerDomain (set by -per-domain) caps handshakes per candidate domain per run. Domains can return
// dozens of IPs; a random sample each run, combined with -history, covers the whole set over runs.
var ipsPerDomain = 4

// rankParallel (set by -parallel) is how many IPs collectRank tests at once. One IP's rounds stay
// back to back on one worker: running them in a row is what exposes IPs that fail intermittently.
// Sequential testing took 20-25 min per run for ~150 IPs, and Tencent's runs hit their 25 min limit.
var rankParallel = 8

// rankDeadline (set by -budget) is when testAll stops starting new IPs; the IPs already tested are
// still reported. Without it a slow run (evening peak: more timeouts) was killed by its unit's
// TimeoutStartSec before reporting anything — Tencent lost every run for two hours on 2026-09-26,
// and its lapsed source left the nationwide pool with three IPs. Zero means no limit.
var rankDeadline time.Time

// ipFamily (set by -family) selects the address family rank and report modes work on: candidate
// domains are resolved to A (4) or AAAA (6) records, and IP literals of the other family are skipped.
var ipFamily = 4

func isFamily(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return (parsed.To4() != nil) == (ipFamily == 4)
}

func resolveFamily(resolver, domain string) ([]string, error) {
	if ipFamily == 6 {
		return queryAAAA(resolver, domain)
	}
	return queryA(resolver, domain)
}

// collectRank fetches the ECH config from doh (which injects it) but resolves candidate domains
// through resolver. The resolver must not be our own DoH: that rewrites Cloudflare answers to the
// current learned pool, so the prober would only ever re-test its own previous choice.
// With stopOnFail an IP stops being dialed at its first failure (Rounds then counts the attempts
// made): report mode requires a perfect run anyway, and failures cost up to `timeout` each.
//
// target is a comma-separated list of hostnames; rounds cycle through them. The pool serves every
// Cloudflare site, so it must be checked against more than one kind: some Cloudflare edge IPs
// (e.g. 198.41.209.206) serve only Enterprise zones and answer everything else with error 1034, so
// an IP that is perfect for x.com can break linux.do's images. A round counts only if the server
// answers /cdn-cgi/trace with 200 (see roundOK).
func collectRank(doh, resolver, candidates, target string, rounds int, timeout time.Duration, stopOnFail bool) []domStat {
	targets := splitList(target)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no rank target")
		os.Exit(2)
	}
	ech, _, _, err := queryHTTPS(doh, targets[0])
	if err != nil || len(ech) == 0 {
		fmt.Fprintf(os.Stderr, "cannot get ECH config for %s: %v\n", targets[0], err)
		os.Exit(1)
	}

	// Resolve every candidate first, then test each distinct IP once (an IP can come from several
	// domains, and from the known/peer lists as a literal) on a pool of workers.
	var results []domStat
	var domIPs [][]string
	var unique []string
	seen := map[string]bool{}
	for _, d := range strings.Split(candidates, ",") {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		ds := domStat{Domain: d}
		var ips []string
		var err error
		if net.ParseIP(d) != nil {
			if !isFamily(d) {
				continue
			}
			ips = []string{d}
		} else {
			ips, err = resolveFamily(resolver, d)
		}
		if err == nil && len(ips) == 0 {
			err = errors.New("no A records")
		}
		if err != nil {
			ds.Error = err.Error()
			results = append(results, ds)
			domIPs = append(domIPs, nil)
			continue
		}
		if len(ips) > ipsPerDomain {
			rand.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
			ips = ips[:ipsPerDomain]
		}
		for _, ip := range ips {
			if !seen[ip] {
				seen[ip] = true
				unique = append(unique, ip)
			}
		}
		results = append(results, ds)
		domIPs = append(domIPs, ips)
	}

	stats := testAll(unique, targets, ech, rounds, timeout, stopOnFail)
	for i := range results {
		ds := &results[i]
		for _, ip := range domIPs[i] {
			st, ok := stats[ip]
			if !ok {
				continue // not reached before the -budget deadline
			}
			ds.IPs = append(ds.IPs, st)
			if st.Rate > ds.BestRate || (st.Rate == ds.BestRate && st.MedianMs > 0 && (ds.BestMs == 0 || st.MedianMs < ds.BestMs)) {
				ds.BestRate, ds.BestMs, ds.BestIP = st.Rate, st.MedianMs, st.IP
			}
		}
		if ds.Error == "" && net.ParseIP(ds.Domain) == nil {
			fmt.Fprintf(os.Stderr, "%-32s best %.0f%% %4dms via %s\n", ds.Domain, ds.BestRate*100, ds.BestMs, ds.BestIP)
		}
	}
	fmt.Fprintf(os.Stderr, "tested %d of %d distinct IPs, %d at a time\n", len(stats), len(unique), max(1, rankParallel))

	sort.SliceStable(results, func(i, j int) bool {
		if results[i].BestRate != results[j].BestRate {
			return results[i].BestRate > results[j].BestRate
		}
		return results[i].BestMs < results[j].BestMs
	})
	return results
}

// testAll runs testIP for every IP, rankParallel at a time, in the given order (callers put the IPs
// that matter most first). Past rankDeadline no new IP is started; the missing ones are left out.
func testAll(ips, targets []string, ech []byte, rounds int, timeout time.Duration, stopOnFail bool) map[string]ipStat {
	stats := make(map[string]ipStat, len(ips))
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for w := 0; w < max(1, rankParallel); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				st := testIP(ip, targets, ech, rounds, timeout, stopOnFail)
				mu.Lock()
				stats[ip] = st
				mu.Unlock()
			}
		}()
	}
	for i, ip := range ips {
		if !rankDeadline.IsZero() && time.Now().After(rankDeadline) {
			fmt.Fprintf(os.Stderr, "-budget reached: %d of %d IPs left untested\n", len(ips)-i, len(ips))
			break
		}
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	return stats
}

// testIP makes `rounds` handshakes to ip in a row, cycling through targets; with stopOnFail it stops
// at the first failure (Rounds then counts the attempts made).
func testIP(ip string, targets []string, ech []byte, rounds int, timeout time.Duration, stopOnFail bool) ipStat {
	st := ipStat{IP: ip}
	var lat []int64
	for i := 0; i < rounds; i++ {
		st.Rounds++
		host := targets[i%len(targets)]
		a := handshake(ip, host, ech, timeout)
		if roundOK(a) {
			st.OK++
			lat = append(lat, a.Millis)
			continue
		}
		switch {
		case a.Error != "":
			st.LastError = host + ": " + a.Error
		case a.Handshake:
			st.LastError = host + ": " + a.HTTPStatus
		}
		if stopOnFail {
			break
		}
	}
	st.Rate = float64(st.OK) / float64(st.Rounds)
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		st.MedianMs = lat[len(lat)/2]
	}
	return st
}
