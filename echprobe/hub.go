package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	hubMaxIPs             = 64 // the hub accepts at most this many per report
	hubMinIPs             = 2  // a pool needs two agreed IPs; fewer is not worth sending
)

// hubClient offers classical key exchange only, like dohTransport: Go's default post-quantum key
// share splits the ClientHello over two TCP segments, and from Tencent Cloud Beijing that handshake
// to the hub timed out on every report (2026-09-26) while one-segment handshakes went through.
var hubClient = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
	Proxy:               http.ProxyFromEnvironment,
	ForceAttemptHTTP2:   true,
	TLSHandshakeTimeout: 15 * time.Second,
	IdleConnTimeout:     30 * time.Second,
	TLSClientConfig:     &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}},
}}

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

// callHubAPI sends one request to the first route that answers: a transport failure (timeout,
// reset) moves on to the next route, while any HTTP response, even an error, is final.
func callHubAPI(apis []string, method, path, token string, body []byte) (*http.Response, error) {
	var lastErr error
	for _, base := range apis {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequest(method, base+path, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := hubClient.Do(req)
		if err == nil {
			fmt.Fprintf(os.Stderr, "%s %s via %s: HTTP %d\n", method, strings.SplitN(path, "?", 2)[0], base, resp.StatusCode)
			return resp, nil
		}
		fmt.Fprintf(os.Stderr, "%s unreachable (%v), trying the next route\n", base, err)
		lastErr = err
	}
	return nil, lastErr
}

// fetchHubCandidates asks the hub what to re-test: this operator's current pool and the top of
// other volunteers' recent reports on it, so independent probers converge on common IPs.
func fetchHubCandidates(apis []string, token string, family int) (hubCandidates, error) {
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

// postHubReport sends the report; the status code is returned so the caller can tell a refusal
// (bad token, too soon) from a transport failure on every route (err != nil, worth one retry).
func postHubReport(apis []string, token string, body []byte) (int, string, error) {
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
	if m, err := loadManifest(hub); err != nil {
		fmt.Fprintln(os.Stderr, "release manifest unavailable (reporting to the hub directly):", err)
	} else {
		apis = apiBases(m, hub)
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
	var peers []string
	if hubPeers, err := fetchHubCandidates(apis, token, ipFamily); err != nil {
		fmt.Fprintln(os.Stderr, "hub candidates unavailable (continuing without):", err)
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
	body := hubReportBody(ranked, ipFamily)
	var (
		status int
		reply  string
		err    error
	)
	// Each route once, then all of them again: a transport failure moves on, any HTTP answer is final.
	for attempt := 1; attempt <= 2; attempt++ {
		if status, reply, err = postHubReport(apis, token, body); err == nil {
			break
		}
		fmt.Fprintln(os.Stderr, "report failed, retrying:", err)
		time.Sleep(3 * time.Second)
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
