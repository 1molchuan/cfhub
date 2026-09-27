package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Site check (-sitecheck): the preferred pool is ranked by ECH handshakes and /cdn-cgi/trace, both
// answered by the Cloudflare edge itself. A site can still hang when the colo a line lands on cannot
// reach that site's origin: on 2026-09-26 every linux.do request that needed its origin hung through
// Singapore (where CERNET and Tencent Beijing land for 172.64.x) while Frankfurt answered in 300 ms,
// and the handshake-based pool kept serving Singapore IPs. This mode fetches real pages through the
// general pool; when too many hang it looks for IPs whose colo does reach the origin, verifies them
// end to end, and reports them to /admin/site. Every run reports, so a recovered site loses its
// override at once. Only a hang or a connection failure counts against an IP: a fast 403 is the
// edge's bot challenge (datacenter lines get it for most requests), not an unreachable origin.

const (
	siteFailShare   = 5 // a set of IPs is degraded when more than 1 in siteFailShare requests fail
	siteMaxTraced   = 120
	siteMaxVerified = 40 // candidates fetched end to end before giving up
	siteMinPool     = 2
	sitePoolSize    = 6 // the DoH's LEARNED_POOL_SIZE: more is never served
	siteBodyLimit   = 1 << 20
)

// siteAddr and siteRoots are swapped by tests (fake IPs → local servers, a private CA).
var (
	siteAddr  = func(ip string) string { return net.JoinHostPort(ip, "443") }
	siteRoots *x509.CertPool
)

type siteProbe struct {
	IP     string
	Colo   string
	OK     int
	Fail   int
	Millis int64 // /cdn-cgi/trace round trip, including the handshake
	Err    string
}

// fetchSite opens one ECH connection to ip (reused for every request, like a browser's h2
// connection), reads /cdn-cgi/trace for the colo, then fetches each path. A request passes when its
// whole response arrives within timeout, whatever the status. A failed trace fails every path: the IP
// is unusable from this line.
func fetchSite(ip, host string, ech []byte, paths []string, timeout time.Duration) siteProbe {
	p := siteProbe{IP: ip}
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", siteAddr(ip))
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, &tls.Config{
				ServerName:                     host,
				MinVersion:                     tls.VersionTLS13,
				NextProtos:                     []string{"h2", "http/1.1"},
				EncryptedClientHelloConfigList: ech,
				RootCAs:                        siteRoots,
				// One-segment ClientHello (see dohTransport): the post-quantum share stalls some paths.
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			})
			if err := c.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			if !c.ConnectionState().ECHAccepted {
				c.Close()
				return nil, errors.New("ECH not accepted")
			}
			return c, nil
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string) ([]byte, error) {
		req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0")
		req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(io.LimitReader(resp.Body, siteBodyLimit))
	}
	start := time.Now()
	trace, err := get("/cdn-cgi/trace")
	if err != nil {
		p.Fail, p.Err = len(paths), "trace: "+err.Error()
		return p
	}
	p.Millis = time.Since(start).Milliseconds()
	for _, line := range strings.Split(string(trace), "\n") {
		if colo, ok := strings.CutPrefix(line, "colo="); ok {
			p.Colo = strings.TrimSpace(colo)
		}
	}
	for _, path := range paths {
		if _, err := get(path); err != nil {
			p.Fail++
			p.Err = path + ": " + err.Error()
		} else {
			p.OK++
		}
	}
	return p
}

// probeAll runs fetchSite on every IP, rankParallel at a time, stopping at rankDeadline.
func probeAll(ips []string, host string, ech []byte, paths []string, timeout time.Duration) []siteProbe {
	out := make([]siteProbe, len(ips))
	done := make([]bool, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, rankParallel))
	for i, ip := range ips {
		if !rankDeadline.IsZero() && time.Now().After(rankDeadline) {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i], done[i] = fetchSite(ip, host, ech, paths, timeout), true
		}()
	}
	wg.Wait()
	var tested []siteProbe
	for i := range out {
		if done[i] {
			tested = append(tested, out[i])
		}
	}
	return tested
}

func degraded(ok, fail int) bool {
	return fail > 0 && fail*siteFailShare > ok+fail
}

// checkSite decides whether host needs its own pool and, if so, finds one. The general pool is
// degraded when more than 1 in siteFailShare of its requests fail. Its colos with that failure rate
// are then avoided: candidates are traced (one cheap edge request each) to learn their colo and
// latency, and the fastest ones in other colos are verified end to end, at most two per /24. A colo
// that fails two candidates is abandoned too. Fewer than siteMinPool verified IPs: nil (no override
// beats an override nobody verified).
func checkSite(host string, ech []byte, paths []string, pool, candidates []string, timeout time.Duration) (bool, []string) {
	general := probeAll(pool, host, ech, paths, timeout)
	ok, fail := 0, 0
	colos := map[string][2]int{}
	for _, p := range general {
		ok += p.OK
		fail += p.Fail
		c := colos[p.Colo]
		colos[p.Colo] = [2]int{c[0] + p.OK, c[1] + p.Fail}
		fmt.Fprintf(os.Stderr, "  pool %-16s colo=%-4s ok=%d fail=%d %s\n", p.IP, p.Colo, p.OK, p.Fail, p.Err)
	}
	if !degraded(ok, fail) {
		fmt.Fprintf(os.Stderr, "%s: general pool fine (%d/%d requests ok)\n", host, ok, ok+fail)
		return false, nil
	}
	bad := map[string]bool{}
	for colo, c := range colos {
		if colo != "" && degraded(c[0], c[1]) {
			bad[colo] = true
		}
	}
	fmt.Fprintf(os.Stderr, "%s: general pool DEGRADED (%d of %d requests failed); avoiding colos %v\n", host, fail, ok+fail, keys(bad))

	inPool := map[string]bool{}
	for _, ip := range pool {
		inPool[ip] = true
	}
	var fresh []string
	for _, ip := range candidates {
		if !inPool[ip] && len(fresh) < siteMaxTraced {
			fresh = append(fresh, ip)
			inPool[ip] = true
		}
	}
	traced := probeAll(fresh, host, ech, nil, timeout)
	var usable []siteProbe
	for _, p := range traced {
		if p.Fail == 0 && p.Colo != "" && !bad[p.Colo] {
			usable = append(usable, p)
		}
	}
	sort.SliceStable(usable, func(i, j int) bool { return usable[i].Millis < usable[j].Millis })
	fmt.Fprintf(os.Stderr, "%s: traced %d candidates, %d outside the avoided colos\n", host, len(traced), len(usable))

	var chosen []string
	perBlock := map[string]int{}
	coloFails := map[string]int{}
	verified := 0
	for len(usable) > 0 && len(chosen) < sitePoolSize && verified < siteMaxVerified {
		if !rankDeadline.IsZero() && time.Now().After(rankDeadline) {
			fmt.Fprintln(os.Stderr, "-budget reached while verifying candidates")
			break
		}
		// The next batch: skip colos found broken meanwhile and /24s already represented twice.
		var batch []string
		var rest []siteProbe
		for _, p := range usable {
			switch {
			case bad[p.Colo] || perBlock[ipBlock(p.IP)] >= 2:
			case len(batch) < max(1, rankParallel):
				batch = append(batch, p.IP)
			default:
				rest = append(rest, p)
			}
		}
		usable = rest
		if len(batch) == 0 {
			break
		}
		verified += len(batch)
		results := probeAll(batch, host, ech, paths, timeout)
		sort.SliceStable(results, func(i, j int) bool { return results[i].Millis < results[j].Millis })
		for _, p := range results {
			fmt.Fprintf(os.Stderr, "  alt  %-16s colo=%-4s ok=%d fail=%d %dms %s\n", p.IP, p.Colo, p.OK, p.Fail, p.Millis, p.Err)
			if p.Fail > 0 {
				if coloFails[p.Colo]++; coloFails[p.Colo] >= 2 {
					bad[p.Colo] = true
				}
				continue
			}
			if len(chosen) < sitePoolSize && perBlock[ipBlock(p.IP)] < 2 {
				chosen = append(chosen, p.IP)
				perBlock[ipBlock(p.IP)]++
			}
		}
	}
	if len(chosen) < siteMinPool {
		fmt.Fprintf(os.Stderr, "%s: only %d verified alternatives (< %d); no override\n", host, len(chosen), siteMinPool)
		return true, nil
	}
	fmt.Fprintf(os.Stderr, "%s: override %v\n", host, chosen)
	return true, chosen
}

func ipBlock(ip string) string {
	if i := strings.LastIndexByte(ip, '.'); i > 0 {
		return ip[:i]
	}
	return ip
}

// generalPool reads the nationwide pool the DoH serves (GET /admin/preferred on the DoH's host) and
// every default-scope source's IPv4 list, which are good alternative candidates.
func generalPool(doh, token string) (pool, sources []string, err error) {
	u, err := url.Parse(doh)
	if err != nil {
		return nil, nil, err
	}
	u.Path, u.RawQuery = "/admin/preferred", ""
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var s struct {
		Learned *struct {
			IPv4    []string `json:"ipv4"`
			Sources []struct {
				IPv4 []string `json:"ipv4"`
			} `json:"sources"`
		} `json:"learned"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, nil, err
	}
	if s.Learned == nil || len(s.Learned.IPv4) == 0 {
		return nil, nil, errors.New("the DoH has no learned IPv4 pool")
	}
	for _, src := range s.Learned.Sources {
		sources = append(sources, src.IPv4...)
	}
	return s.Learned.IPv4, sources, nil
}

// siteCheckRun checks every host named in urls (grouped by host, paths in order) and reports the
// overrides; the report always goes out, so an empty one withdraws this source's earlier overrides.
func siteCheckRun(doh string, urls []string, timeout time.Duration, reportURL, token, source string, ttl int, historyPath string, sampled []string) {
	var hosts []string
	paths := map[string][]string{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			fmt.Fprintf(os.Stderr, "bad -sitecheck URL %q (want https://host/path)\n", raw)
			os.Exit(2)
		}
		host := strings.ToLower(u.Hostname())
		if paths[host] == nil {
			hosts = append(hosts, host)
		}
		paths[host] = append(paths[host], u.RequestURI())
	}
	pool, peers, err := generalPool(doh, token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read the general pool:", err)
		os.Exit(1)
	}
	hist, known := loadKnown(historyPath)
	retest, _ := retestOrder(hist, known, peers)
	candidates := append(retest, sampled...)

	overrides := map[string][]string{}
	for _, host := range hosts {
		ech, _, _, err := queryHTTPS(doh, host)
		if err != nil || len(ech) == 0 {
			fmt.Fprintf(os.Stderr, "%s: no ECH config from the DoH (%v); skipped\n", host, err)
			continue
		}
		if _, alt := checkSite(host, ech, paths[host], pool, candidates, timeout); alt != nil {
			overrides[host] = alt
		}
	}
	if reportURL == "" {
		fmt.Printf("overrides: %v (not reported: no -site-report)\n", overrides)
		return
	}
	body, _ := json.Marshal(map[string]any{"source": source, "ttl": ttl, "hosts": overrides})
	dohTransport.CloseIdleConnections()
	if status, err := postReport(reportURL, token, body); err != nil || status != http.StatusOK {
		fmt.Fprintln(os.Stderr, "site report failed:", err, status)
		os.Exit(4)
	}
}
