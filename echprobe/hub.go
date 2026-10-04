package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// Volunteer mode (-hub): the same measurement as report mode, but reporting to cfhub
// (work/cfhub) with a personal token instead of to the DoH with the admin token. The hub tags
// the report with this line's operator and votes a pool per operator; nothing here can touch the
// DoH directly. Built-in defaults below, so volunteers need only the hub URL and their token.

// Candidate "preferred domains" and Cloudflare ranges, the same the core probers use
// (deploy/prober/windows/run.cmd).
const (
	defaultHubCandidates  = "cf.090227.xyz,cmcc.090227.xyz,cu.090227.xyz,ct.090227.xyz,skk.moe,yx.cloudflare.182682.xyz,cfip.xxxxxxxx.tk,www.visa.com.hk,openai.com,cloudflare-ip.mofashi.ltd,saas.sin.fan,cf.877774.xyz,cf.0sm.com,cf.130519.xyz,ip.164746.xyz,www.visa.com.sg,www.visa.com.tw,icook.tw,icook.hk,japan.com,www.digitalocean.com,www.shopify.com,www.udemy.com,www.hugedomains.com,www.ipget.net,www.gov.ua"
	defaultHubSampleCIDRs = "104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,162.158.0.0/15,188.114.96.0/20,190.93.240.0/20"
	defaultHubResolver    = "https://223.5.5.5/dns-query"
	// Every IP that passed (a run tests about 150): the hub reads an IP missing from a report as one
	// that failed, so a top-64 cut made near-tied IPs lose votes at random (release 9). The hub
	// accepts 256; hubs before 2026-10-01 accepted 64.
	hubMaxIPs       = 256
	legacyHubMaxIPs = 64
	hubMinIPs       = 2 // a pool needs two agreed IPs; fewer is not worth sending
)

// hubClient offers classical key exchange only, like dohTransport: Go's default post-quantum key
// share splits the ClientHello over two TCP segments, and from Tencent Cloud Beijing that handshake
// to the hub timed out on every report (2026-09-26) while one-segment handshakes went through.
var hubClient = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	DialContext:         hubDial,
	ForceAttemptHTTP2:   true,
	TLSHandshakeTimeout: 15 * time.Second,
	IdleConnTimeout:     30 * time.Second,
	TLSClientConfig:     &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}},
}}

// hubMSS caps the TCP segments sent to the hub. A report is a few KB; a line that drops full-size
// upstream packets while blocking the ICMP that would shrink them (a PMTU black hole) lets the small
// candidates request through and stalls every report (2026-09-29, Shanghai Mobile: reports up to
// ~1.4 KB went through, larger ones hung on both routes). The hub origin clamps its side too, but
// the edge route's CDN does not. Linux and macOS only: Windows has no such socket option.
const hubMSS = 1200

// hubDial dials the hub: bound to the -direct interface when set (see dialer), segments capped at hubMSS.
func hubDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := dialer(15 * time.Second)
	bind := d.Control
	d.Control = func(network, address string, c syscall.RawConn) error {
		if bind != nil {
			if err := bind(network, address, c); err != nil {
				return err
			}
		}
		// Best effort: an unclamped connection still works on most lines.
		return c.Control(func(fd uintptr) { _ = clampMSS(fd, hubMSS) })
	}
	return d.DialContext(ctx, network, addr)
}

type hubCandidates struct {
	ISP  string   `json:"isp"`
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

// apiBases lists where to reach the probe API: the signed manifest's routes (https only), then the
// hub itself.
func apiBases(m releaseManifest, hub string) []string {
	var out []string
	for _, base := range m.API {
		if base = strings.TrimRight(base, "/"); strings.HasPrefix(base, "https://") && base != hub {
			out = append(out, base)
		}
	}
	return append(out, hub)
}

// hubRoute is one way to reach the probe API: a base URL and the client that carries the request.
type hubRoute struct {
	base   string
	via    string // the address a pinned route dials, for the log
	client *http.Client
}

func (r hubRoute) String() string {
	if r.via == "" {
		return r.base
	}
	return r.base + " [" + r.via + "]"
}

// plainRoutes reaches each base through hubClient: names resolved as usual, so over IPv4 for the hub
// and the CDN route, which have no IPv6 address.
func plainRoutes(bases []string) []hubRoute {
	out := make([]hubRoute, 0, len(bases))
	for _, base := range bases {
		out = append(out, hubRoute{base: base, client: hubClient})
	}
	return out
}

// maxPinnedIPv6 bounds the Cloudflare addresses tried per IPv6 route before falling back to the others.
const maxPinnedIPv6 = 2

// ipv6Routes reaches the manifest's api6 bases (Cloudflare) over IPv6, so the request leaves from
// this line's IPv6 address and Cloudflare passes that address to the hub: the hub then files an IPv6
// report under the line's IPv6 prefix and operator, not its IPv4 ones. Each base is dialed at the
// given Cloudflare addresses, best first (any Cloudflare address serves any Cloudflare site, and these
// are the ones this line reaches); with none, the base's own name is resolved and dialed over IPv6.
// No proxy: one would hide the address.
func ipv6Routes(bases, candidates []string) []hubRoute {
	var ips []string
	for _, ip := range candidates {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil && len(ips) < maxPinnedIPv6 {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		ips = []string{""}
	}
	var out []hubRoute
	for _, base := range bases {
		for _, ip := range ips {
			transport := hubClient.Transport.(*http.Transport).Clone()
			transport.Proxy = nil
			transport.DialContext = pinnedDial(ip)
			out = append(out, hubRoute{base: base, via: ip, client: &http.Client{Timeout: 20 * time.Second, Transport: transport}})
		}
	}
	return out
}

// pinnedDial dials over IPv6 only: to ip on the requested port when set, else to the requested address.
func pinnedDial(ip string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		if ip != "" {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addr = net.JoinHostPort(ip, port)
		}
		return hubDial(ctx, "tcp6", addr)
	}
}

// callHubAPI sends one request to the first route that answers: a transport failure (timeout,
// reset) moves on to the next route, while any HTTP response, even an error, is final.
func callHubAPI(routes []hubRoute, method, path, token string, body []byte) (*http.Response, error) {
	var lastErr error
	for _, route := range routes {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, route.base+path, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := route.client.Do(req)
		if err == nil {
			fmt.Fprintf(os.Stderr, "%s %s via %s: HTTP %d\n", method, strings.SplitN(path, "?", 2)[0], route, resp.StatusCode)
			return resp, nil
		}
		fmt.Fprintf(os.Stderr, "%s unreachable (%v), trying the next route\n", route, err)
		lastErr = err
	}
	return nil, lastErr
}

// fetchHubCandidates asks the hub what to re-test: this operator's current pool and the top of
// other volunteers' recent reports on it, so independent probers converge on common IPs.
func fetchHubCandidates(apis []hubRoute, token string, family int) (hubCandidates, error) {
	var out hubCandidates
	resp, err := callHubAPI(apis, http.MethodGet, fmt.Sprintf("/api/v1/probe/candidates?family=%d", family), token, nil)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("HTTP %d %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return out, json.Unmarshal(body, &out)
}

type hubReportIP struct {
	IP       string `json:"ip"`
	MedianMS int64  `json:"median_ms"`
	OK       int    `json:"ok"`
	Rounds   int    `json:"rounds"`
}

func hubReportBody(ranked []rankedIP, family int) []byte {
	ips := make([]hubReportIP, 0, len(ranked))
	for _, r := range ranked {
		ips = append(ips, hubReportIP{IP: r.IP, MedianMS: r.Median, OK: r.Rounds, Rounds: r.Rounds})
	}
	body, _ := json.Marshal(map[string]any{"family": family, "ips": ips, "version": probeVersion})
	return body
}

// reportBackoff is the wait before each retry of a report that reached no route. Right after a run a
// line can refuse new connections for a minute or two: its NAT (home router, or carrier-grade NAT)
// is full of the run's hundreds of handshakes. 2026-09-28, Shanghai Mobile: candidates fetched before
// the run went through, the report after it failed on both routes, retried 3 s apart, and nothing
// reached the hub. At most about 7 minutes in all, so the IPv6 run still fits the unit's timeout.
var reportBackoff = []time.Duration{20 * time.Second, time.Minute, 2 * time.Minute}

// sendHubReport posts the report, retrying after reportBackoff while no route answers at all.
func sendHubReport(apis []hubRoute, token string, body []byte) (int, string, error) {
	for attempt := 0; ; attempt++ {
		status, reply, err := postHubReport(apis, token, body)
		if err == nil || attempt == len(reportBackoff) {
			return status, reply, err
		}
		fmt.Fprintf(os.Stderr, "report reached no route (%v); retrying in %s\n", err, reportBackoff[attempt])
		time.Sleep(reportBackoff[attempt])
	}
}

// postHubReport sends the report; the status code is returned so the caller can tell a refusal
// (bad token, too soon) from a transport failure on every route (err != nil, worth a retry).
func postHubReport(apis []hubRoute, token string, body []byte) (int, string, error) {
	resp, err := callHubAPI(apis, http.MethodPost, "/api/v1/probe/report", token, body)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	reply, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(bytes.TrimSpace(reply)), nil
}

func hubRun(doh, resolver, candidates, target string, rounds int, timeout time.Duration, hub, token, historyPath string, update bool) {
	hub = strings.TrimRight(hub, "/")
	local := func(u *url.URL) bool { return u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" }
	if u, err := url.Parse(hub); err != nil || (u.Scheme != "https" && !local(u)) {
		fmt.Fprintln(os.Stderr, "-hub must be an https URL") // the token must never travel in clear text
		os.Exit(2)
	}
	fmt.Fprintf(os.Stderr, "%s\n", probeVersion)
	// The signed manifest names the release and any faster routes to the hub's probe API.
	apis := []string{hub}
	var api6 []string
	if m, err := loadManifest(hub); err != nil {
		fmt.Fprintln(os.Stderr, "release manifest unavailable (reporting to the hub directly):", err)
	} else {
		apis = apiBases(m, hub)
		if ipFamily == 6 {
			api6 = m.API6
		}
		if update {
			cleanupOldExecutable()
			if seq, err := selfUpdate(hub, m); err != nil {
				fmt.Fprintln(os.Stderr, "self-update skipped:", err)
			} else if seq > 0 {
				fmt.Fprintf(os.Stderr, "updated to signed release %d; it runs from the next run on\n", seq)
			}
		}
	}
	hist, known := loadKnown(historyPath)
	// An IPv6 run goes over IPv6 first (see ipv6Routes): before the run at the addresses that did best
	// in earlier runs, for the report at this run's best.
	routes := func(best []string) []hubRoute { return append(ipv6Routes(api6, best), plainRoutes(apis)...) }
	previousBest, _ := retestOrder(hist, known, nil)
	var peers []string
	if hubPeers, err := fetchHubCandidates(routes(previousBest), token, ipFamily); err != nil {
		fmt.Fprintln(os.Stderr, "hub candidates unavailable (continuing without):", err)
		if directDialer != nil {
			// 2026-10-01: OpenClash on the router redirected the prober's own connections; bound to the
			// WAN they could only time out.
			fmt.Fprintln(os.Stderr, "hint: with -direct, a transparent proxy on this machine (OpenClash, PassWall...) can still catch the prober's traffic in its firewall rules; exempt user cfprobe in it")
		}
	} else {
		fmt.Fprintf(os.Stderr, "hub: this line is %s (%s); %d candidates from the hub\n", hubPeers.Name, hubPeers.ISP, len(hubPeers.IPs))
		for _, ip := range hubPeers.IPs {
			if isFamily(ip) {
				peers = append(peers, ip)
			}
		}
	}
	retest, _ := retestOrder(hist, known, peers)
	stats := collectRank(doh, resolver, strings.Join(append(retest, candidates), ","), target, rounds, timeout, true)
	ranked := eligibleIPs(stats, hist, historyPath)
	if len(ranked) > hubMaxIPs {
		ranked = ranked[:hubMaxIPs]
	}
	fmt.Fprintf(os.Stderr, "eligible=%d\n", len(ranked))
	for i, r := range ranked {
		if i >= 12 {
			break
		}
		fmt.Fprintf(os.Stderr, "  %-16s history=%3.0f%% over %d run(s)  median=%dms\n", r.IP, r.History*100, r.Runs, r.Median)
	}
	if len(ranked) < hubMinIPs {
		fmt.Fprintf(os.Stderr, "only %d eligible IPs (< %d); not reporting\n", len(ranked), hubMinIPs)
		os.Exit(3)
	}
	best := make([]string, 0, maxPinnedIPv6)
	for _, r := range ranked {
		if len(best) < maxPinnedIPv6 {
			best = append(best, r.IP)
		}
	}
	reportRoutes := routes(best)
	status, reply, err := sendHubReport(reportRoutes, token, hubReportBody(ranked, ipFamily))
	if err == nil && status == http.StatusBadRequest && strings.Contains(reply, "at most") && len(ranked) > legacyHubMaxIPs {
		// A hub from before 2026-10-01 (or a self-hosted one) takes 64: send the best 64 instead.
		fmt.Fprintf(os.Stderr, "hub takes fewer IPs (%s); sending the best %d\n", reply, legacyHubMaxIPs)
		status, reply, err = sendHubReport(reportRoutes, token, hubReportBody(ranked[:legacyHubMaxIPs], ipFamily))
	}
	switch {
	case err != nil:
		fmt.Fprintln(os.Stderr, "report failed:", err)
		os.Exit(4)
	case status == http.StatusOK:
		fmt.Println("reported:", reply)
	case status == http.StatusTooManyRequests:
		fmt.Println("hub: reported recently, this run skipped") // not an error: the timer just fired early
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		fmt.Fprintf(os.Stderr, "hub refused the token (%d %s): get a new one at %s/join\n", status, reply, hub)
		os.Exit(4)
	default:
		fmt.Fprintf(os.Stderr, "hub: HTTP %d %s\n", status, reply)
		os.Exit(4)
	}
}
