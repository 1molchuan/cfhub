package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func newIndentEncoder() *json.Encoder {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc
}

// postGithub reports the per-host pools to /admin/github.
func postGithub(adminURL, token, source string, ttl int, hosts map[string][]string) {
	body, _ := json.Marshal(map[string]any{"source": source, "ttl": ttl, "hosts": hosts})
	var err error
	for attempt := 1; attempt <= 2; attempt++ {
		if attempt > 1 {
			fmt.Fprintln(os.Stderr, "github report failed, retrying:", err)
			time.Sleep(2 * time.Second)
		}
		dohTransport.CloseIdleConnections()
		req, e := http.NewRequest(http.MethodPost, adminURL, bytes.NewReader(body))
		if e != nil {
			fmt.Fprintln(os.Stderr, "bad admin url:", e)
			os.Exit(2)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		var resp *http.Response
		if resp, err = dohClient.Do(req); err == nil {
			out, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			fmt.Printf("%d %s\n", resp.StatusCode, bytes.TrimSpace(out))
			if resp.StatusCode != http.StatusOK {
				os.Exit(4)
			}
			return
		}
	}
	fmt.Fprintln(os.Stderr, "github report failed:", err)
	os.Exit(4)
}

// githubRun optimizes GitHub-family hosts. GitHub publishes no ECH, and its China pain is IP
// reachability (blackholed IPs, and on some lines a forged cert for a host's SNI), not a uniform SNI
// block — so the right lever is a per-host preferred-IP pool, like the Cloudflare one. Candidates come
// from community hosts sources (the maintainers already scan for good IPs); this keeps only the ones
// that work from THIS line. A candidate passes when a cert-validated TLS 1.3 handshake to the IP with
// the host's real SNI completes and the host answers HTTP — that rejects both blackholes (timeout) and
// forged-cert interference (the cert fails to verify). The per-host results are POSTed to /admin/github.
// shareFamilies are registrable domains whose hosts sit on shared anycast with a wildcard cert (all
// *.githubusercontent.com on the 185.199.108-111.x Fastly addresses; likewise github.io Pages and the
// githubassets.com static host). Within a family an IP good for one host is good for all, so their
// candidates are pooled and each unique IP is tested only once — which rescues a host whose own listed
// IPs are blocked (raw's IP was blackholed while a sibling's worked), and keeps the probe from bursting
// GitHub with per-host duplicate handshakes (a burst got the whole line throttled in testing).
var shareFamilies = map[string]bool{"githubusercontent.com": true, "github.io": true, "githubassets.com": true}

func githubRun(doh string, sources, hostFilter []string, rounds int, timeout time.Duration, adminURL, token, source string, ttl int, share bool, resolver string) {
	candidates := fetchGithubCandidates(sources, hostFilter, resolver)
	if len(candidates) == 0 {
		fmt.Fprintln(os.Stderr, "no GitHub candidates fetched (sources unreachable?)")
		os.Exit(3)
	}
	hosts := make([]string, 0, len(candidates))
	for h := range candidates {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	// A test group is a shared-cert family (tested once with a representative host's SNI) or a single
	// standalone host. Pool a family's candidate IPs across its member hosts.
	type group struct {
		rep     string   // SNI used to test (a member host)
		members []string // hosts that get this group's result
		ips     []string
	}
	groups := map[string]*group{}
	for _, host := range hosts {
		key := host
		rd := registrableDomain(host)
		if share && shareFamilies[rd] {
			key = "family:" + rd
		}
		g := groups[key]
		if g == nil {
			g = &group{rep: host}
			groups[key] = g
		}
		g.members = append(g.members, host)
		g.ips = appendUnique(g.ips, candidates[host]...)
	}

	report := map[string][]string{}
	var mu sync.Mutex
	for _, g := range groups {
		good := testGroupIPs(g.ips, g.rep, rounds, timeout)
		fmt.Fprintf(os.Stderr, "%-34s %d/%d IPs ok (rep %s)\n", strings.Join(g.members, ","), len(good), len(g.ips), g.rep)
		if len(good) == 0 {
			continue
		}
		mu.Lock()
		for _, host := range g.members {
			report[host] = good
		}
		mu.Unlock()
	}

	if len(report) == 0 {
		fmt.Fprintln(os.Stderr, "no GitHub host had a working IP; not reporting")
		os.Exit(3)
	}
	if adminURL == "" {
		enc := newIndentEncoder()
		_ = enc.Encode(report)
		return
	}
	postGithub(adminURL, token, source, ttl, report)
}

// testGroupIPs checks each IP against sni (rounds back to back, parallel across IPs) and returns the
// ones that pass every round, fastest first.
func testGroupIPs(ips []string, sni string, rounds int, timeout time.Duration) []string {
	type res struct {
		ip string
		ms int64
		ok bool
	}
	out := make([]res, len(ips))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, rankParallel))
	for i, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			var ms int64
			for r := 0; r < rounds; r++ {
				good, d, _ := githubCheck(ip, sni, timeout)
				if !good {
					return
				}
				if d > ms {
					ms = d
				}
			}
			out[i] = res{ip, ms, true}
		}(i, ip)
	}
	wg.Wait()
	var passed []res
	for _, r := range out {
		if r.ok {
			passed = append(passed, r)
		}
	}
	sort.Slice(passed, func(a, b int) bool { return passed[a].ms < passed[b].ms })
	good := make([]string, 0, len(passed))
	for _, r := range passed {
		good = append(good, r.ip)
	}
	return good
}

func appendUnique(dst []string, items ...string) []string {
	for _, it := range items {
		found := false
		for _, x := range dst {
			if x == it {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, it)
		}
	}
	return dst
}

// githubCheck does one cert-validated TLS 1.3 handshake to ip with host's SNI (no ECH) and one HTTP
// request. good is true when the cert verifies for host and the server returns an HTTP status line.
func githubCheck(ip, host string, timeout time.Duration) (good bool, ms int64, errStr string) {
	start := time.Now()
	raw, err := dialer(timeout).Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, 0, "tcp: " + err.Error()
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	// ServerName set and InsecureSkipVerify false: the cert must be valid for host, so a forged cert
	// injected for this SNI (seen on some lines) fails here.
	conn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if err := conn.Handshake(); err != nil {
		return false, 0, "tls: " + err.Error()
	}
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: echprobe\r\nConnection: close\r\n\r\n", host)
	if _, err := io.WriteString(conn, req); err != nil {
		return false, 0, "http write: " + err.Error()
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false, 0, "http read: " + err.Error()
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return false, 0, "not http: " + strings.TrimSpace(line)
	}
	return true, time.Since(start).Milliseconds(), ""
}

// fetchGithubCandidates downloads hosts-file sources and returns {host: [ipv4]} for hosts matching the
// filter (exact names or .suffix). Sources are tried in order; all reachable ones are unioned.
func fetchGithubCandidates(sources, filter []string, resolver string) map[string][]string {
	out := map[string]map[string]bool{}
	client := &http.Client{Timeout: 15 * time.Second}
	// Some probers (Aliyun) have an unreliable system resolver; -github-resolver dials a fixed DNS
	// server (e.g. 223.5.5.5:53) for the source hostnames instead.
	if resolver != "" {
		res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "udp", resolver)
		}}
		client.Transport = &http.Transport{DialContext: (&net.Dialer{Timeout: 10 * time.Second, Resolver: res}).DialContext}
	}
	for _, url := range sources {
		// A source without a scheme is a local hosts file (deploy/prober/github-extra-hosts).
		if !strings.Contains(url, "://") {
			body, err := os.ReadFile(url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "source %s: %v\n", url, err)
				continue
			}
			parseHostsFile(string(body), filter, out)
			continue
		}
		resp, err := client.Get(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "source %s: %v\n", url, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "source %s: HTTP %d\n", url, resp.StatusCode)
			continue
		}
		parseHostsFile(string(body), filter, out)
	}
	result := map[string][]string{}
	for host, set := range out {
		for ip := range set {
			result[host] = append(result[host], ip)
		}
		sort.Strings(result[host])
	}
	return result
}

// parseHostsFile adds "IP host" lines (matching the filter) to out. IPv4 only.
func parseHostsFile(body string, filter []string, out map[string]map[string]bool) {
	for _, line := range strings.Split(body, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if p := net.ParseIP(ip); p == nil || p.To4() == nil {
			continue
		}
		for _, host := range fields[1:] {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if !githubHostMatch(host, filter) {
				continue
			}
			if out[host] == nil {
				out[host] = map[string]bool{}
			}
			out[host][ip] = true
		}
	}
}

// registrableDomain returns the last two dotted labels (github.com, githubusercontent.com, github.io).
func registrableDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// githubHostMatch reports whether host matches one of filter's exact names or ".suffix" entries.
func githubHostMatch(host string, filter []string) bool {
	for _, f := range filter {
		if strings.HasPrefix(f, ".") {
			if host == f[1:] || strings.HasSuffix(host, f) {
				return true
			}
		} else if host == f {
			return true
		}
	}
	return false
}
