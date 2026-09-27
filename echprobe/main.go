// echprobe: end-to-end ECH verification against a DoH server.
//
// For each target host it (1) queries the DoH server for HTTPS + A records,
// (2) pulls the ECHConfigList out of the HTTPS record, (3) performs a real TLS
// handshake to the resolved IP with ECH enabled and reports ECHAccepted, and
// (4) as a control repeats the handshake without ECH so the difference is
// attributable to ECH rather than to the network path.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	// A run lasts minutes; NATs on some networks silently drop a connection idle that long, and
	// reusing it hangs until the client timeout. Never reuse a connection idle past 30s.
	// Classical key exchange only: the post-quantum key share makes the ClientHello span two TCP
	// segments, and on some paths (Tencent Cloud Beijing → the DoH edge) that handshake stalls
	// most of the time while a single-segment ClientHello always gets through.
	dohTransport = &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
		TLSClientConfig:     &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}},
	}
	dohClient = &http.Client{Timeout: 10 * time.Second, Transport: dohTransport}
)

type result struct {
	Host           string   `json:"host"`
	IPs            []string `json:"ips"`
	DialIP         string   `json:"dial_ip"`
	EchConfigBytes int      `json:"ech_config_bytes"`
	EchPublicName  string   `json:"ech_public_name,omitempty"`
	WithECH        attempt  `json:"with_ech"`
	WithoutECH     attempt  `json:"without_ech"`
}

type attempt struct {
	Handshake   bool   `json:"handshake_ok"`
	ECHAccepted bool   `json:"ech_accepted"`
	ALPN        string `json:"alpn,omitempty"`
	HTTPStatus  string `json:"http_status,omitempty"`
	Error       string `json:"error,omitempty"`
	Millis      int64  `json:"ms"`
}

func main() {
	doh := flag.String("doh", "https://edge.1molchuan.top/dns-query", "DoH endpoint")
	hosts := flag.String("hosts", "linux.do,x.com,www.instagram.com", "comma-separated hosts")
	ipOverride := flag.String("ip", "", "dial this IP for every host instead of the resolved one")
	timeout := flag.Duration("timeout", 8*time.Second, "per-connection timeout")
	rank := flag.String("rank", "", "comma-separated candidate preferred-domains to benchmark (rank mode)")
	rankTarget := flag.String("rank-target", "x.com,linux.do", "comma-separated hosts used in turn for rank-mode handshakes; mix Enterprise and non-Enterprise Cloudflare zones")
	rounds := flag.Int("rounds", 5, "handshakes per IP in rank mode")
	useQUIC := flag.Bool("quic", false, "handshake over QUIC/UDP instead of TCP")
	report := flag.String("report", "", "POST the best -rank IPs to this /admin/preferred URL")
	adminToken := flag.String("admin-token", os.Getenv("ECHPROBE_ADMIN_TOKEN"), "bearer token for -report (or ECHPROBE_ADMIN_TOKEN)")
	reportSource := flag.String("report-source", "echprobe", "source label sent with -report")
	reportTop := flag.Int("report-top", 6, "how many best IPs to report")
	reportMin := flag.Int("report-min", 3, "minimum eligible IPs required before reporting")
	reportTTL := flag.Int("report-ttl", 3600, "seconds the reported pool stays active server-side")
	metaHost := flag.String("meta-check", "", "verify the Meta ECH key served by -doh via a real handshake to this host (e.g. www.instagram.com)")
	healthURL := flag.String("health", "", "POST the -meta-check verdict to this /admin/health URL (omit to print only)")
	metaTTL := flag.Int("meta-ttl", 86400, "seconds a rotated/broken Meta verdict stays active server-side")
	dohIP := flag.String("doh-ip", "", "dial the DoH host at this IP (keeps SNI/Host); for boxes with broken system DNS")
	reportScope := flag.String("report-scope", "default", `"default" serves everyone; "client" serves only clients in this prober's own /24`)
	tokenFile := flag.String("admin-token-file", "", "read the admin token from this file (keeps it off the command line)")
	logFile := flag.String("log", "", "append stdout/stderr to this file (for windowless scheduled runs)")
	historyPath := flag.String("history", "", "keep per-IP results across -report runs in this file and require them to be stable")
	resolveDoh := flag.String("resolve-doh", "", "plain DoH used to resolve -rank candidate domains (default: -doh). Must not rewrite answers")
	selfcheckHosts := flag.String("selfcheck", "", "comma-separated hosts: check the DoH answers let Chromium use ECH (see selfcheck.go)")
	selfcheckNoH3 := flag.String("selfcheck-no-h3", "x.com,twimg.com,t.co,twitter.com,instagram.com,cdninstagram.com,facebook.com,fbcdn.net", "domain suffixes that must not advertise h3 (QUIC+ECH fails there)")
	selfcheckReport := flag.String("selfcheck-report", "", "POST the -selfcheck verdict to this /admin/selfcheck URL")
	h3Hosts := flag.String("h3check", "", "comma-separated hosts: measure QUIC+ECH against the DoH's answers (-rounds handshakes each)")
	h3Report := flag.String("h3-report", "", "POST the -h3check verdicts to this /admin/h3 URL")
	h3TTL := flag.Int("h3-ttl", 5400, "seconds the -h3check verdicts stay active server-side")
	h3History := flag.String("h3-history", "", "keep per-host -h3check run results here; h3 is reported only after consecutive passes")
	family := flag.Int("family", 4, "address family for -rank/-report: 4 (A records, reported as ipv4) or 6 (AAAA, reported as ipv6)")
	perDomain := flag.Int("per-domain", 4, "IPs drawn at random from each -rank candidate domain per run")
	parallel := flag.Int("parallel", 8, "IPs tested at once in -rank/-report mode (one IP's rounds stay back to back)")
	sampleCIDRs := flag.String("sample-cidrs", "", "comma-separated IPv4 ranges (e.g. Cloudflare's) to draw extra -rank candidates from")
	sampleN := flag.Int("sample-n", 0, "addresses drawn from -sample-cidrs per run, at most one per /24")
	githubSources := flag.String("github", "", "comma-separated community hosts-file URLs; GitHub-mode: verify each host's candidate IPs from this line and report per-host pools")
	githubHosts := flag.String("github-hosts", "github.com,gist.github.com,api.github.com,codeload.github.com,raw.githubusercontent.com,objects.githubusercontent.com,avatars.githubusercontent.com,camo.githubusercontent.com,media.githubusercontent.com,user-images.githubusercontent.com,private-user-images.githubusercontent.com,cloud.githubusercontent.com,desktop.githubusercontent.com,favicons.githubusercontent.com,github.githubassets.com", "GitHub host names/.suffixes to keep from the hosts sources (Azure-hosted *.githubusercontent.com like pipelines.actions are left out)")
	githubReport := flag.String("github-report", "", "POST the -github per-host pools to this /admin/github URL")
	githubTTL := flag.Int("github-ttl", 4200, "seconds the reported GitHub pools stay active server-side")
	githubShare := flag.Bool("github-share", true, "pool candidate IPs within each registrable domain (siblings share anycast + a wildcard cert)")
	githubResolver := flag.String("github-resolver", "", "DNS server (host:port, e.g. 223.5.5.5:53) to resolve -github source URLs; for probers with an unreliable system resolver")
	hub := flag.String("hub", "", "volunteer mode: report to this cfhub (e.g. https://cfhub.1molchuan.top) with a personal token; -rank, -resolve-doh, -sample-* and the pacing flags default to built-in values")
	hubTokenFile := flag.String("token-file", "", "read the cfhub volunteer token from this file (or set CFHUB_TOKEN)")
	noUpdate := flag.Bool("no-update", false, "-hub mode: do not install newer signed releases (see selfupdate.go)")
	budget := flag.Duration("budget", 0, "rank/report/hub/sitecheck: stop starting new tests after this long and report what was measured (keep it a few minutes under the unit's timeout); 0 = no limit")
	maxKnownFlag := flag.Int("max-known", 300, "re-test at most this many IPs from -history per run, best first")
	siteURLs := flag.String("sitecheck", "", "comma-separated URLs (e.g. https://linux.do/srv/status): fetch them through the general pool over ECH; report sites whose origin hangs, with IPs verified end to end")
	siteReport := flag.String("site-report", "", "POST the -sitecheck result to this /admin/site URL (omit to print only)")
	siteTTL := flag.Int("site-ttl", 2700, "seconds a -sitecheck override stays active server-side")
	flag.Parse()
	if *hub != "" {
		// Volunteer defaults: lighter than the core probers (a few MB per run), explicit flags still win.
		set := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
		defaults := map[string]func(){
			"rank":         func() { *rank = defaultHubCandidates },
			"resolve-doh":  func() { *resolveDoh = defaultHubResolver },
			"sample-cidrs": func() { *sampleCIDRs = defaultHubSampleCIDRs },
			"sample-n":     func() { *sampleN = 30 },
			"rounds":       func() { *rounds = 6 },
			"timeout":      func() { *timeout = 6 * time.Second },
			"per-domain":   func() { *perDomain = 6 },
			"parallel":     func() { *parallel = 6 },
			// The installers run IPv4 then IPv6 under one 20 min limit.
			"budget":    func() { *budget = 8 * time.Minute },
			"max-known": func() { *maxKnownFlag = 150 },
		}
		for name, apply := range defaults {
			if !set[name] {
				apply()
			}
		}
	}
	ipsPerDomain = max(1, *perDomain)
	rankParallel = max(1, *parallel)
	maxKnown = max(0, *maxKnownFlag)
	if *budget > 0 {
		rankDeadline = time.Now().Add(*budget)
	}
	if *family != 4 && *family != 6 {
		fmt.Fprintln(os.Stderr, "-family must be 4 or 6")
		os.Exit(2)
	}
	ipFamily = *family
	if *logFile != "" {
		if info, err := os.Stat(*logFile); err == nil && info.Size() > 1<<20 {
			_ = os.Rename(*logFile, *logFile+".1")
		}
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(5)
		}
		fmt.Fprintf(f, "--- %s ---\n", time.Now().Format(time.RFC3339))
		os.Stdout, os.Stderr = f, f
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read -admin-token-file:", err)
			os.Exit(2)
		}
		*adminToken = strings.TrimSpace(string(b))
	}
	if *reportScope != "default" && *reportScope != "client" {
		fmt.Fprintln(os.Stderr, `-report-scope must be "default" or "client"`)
		os.Exit(2)
	}
	if *useQUIC {
		handshake = handshakeQUIC
	}
	if *dohIP != "" {
		u, err := url.Parse(*doh)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad -doh:", err)
			os.Exit(2)
		}
		host := u.Hostname()
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		dohTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if h, p, err := net.SplitHostPort(addr); err == nil && h == host {
				addr = net.JoinHostPort(*dohIP, p)
			}
			return dialer.DialContext(ctx, network, addr)
		}
	}

	if *rank != "" && *sampleN > 0 && *sampleCIDRs != "" && ipFamily == 4 {
		drawn, err := sampleIPv4(splitList(*sampleCIDRs), *sampleN, mrand.New(mrand.NewSource(time.Now().UnixNano())))
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad -sample-cidrs:", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "drew %d random candidates from %s\n", len(drawn), *sampleCIDRs)
		*rank += "," + strings.Join(drawn, ",")
	}

	if *hub != "" {
		token := strings.TrimSpace(os.Getenv("CFHUB_TOKEN"))
		if *hubTokenFile != "" {
			b, err := os.ReadFile(*hubTokenFile)
			if err != nil {
				fmt.Fprintln(os.Stderr, "cannot read -token-file:", err)
				os.Exit(2)
			}
			token = strings.TrimSpace(string(b))
		}
		if token == "" {
			fmt.Fprintln(os.Stderr, "-hub needs a token: -token-file or CFHUB_TOKEN (get one at "+strings.TrimRight(*hub, "/")+"/join)")
			os.Exit(2)
		}
		hubRun(*doh, *resolveDoh, *rank, *rankTarget, *rounds, *timeout, *hub, token, *historyPath, !*noUpdate)
		return
	}

	if *siteURLs != "" {
		if *adminToken == "" || ipFamily != 4 {
			fmt.Fprintln(os.Stderr, "-sitecheck needs -admin-token (it reads the general pool from the DoH) and works on IPv4")
			os.Exit(2)
		}
		var sampled []string
		if *sampleN > 0 && *sampleCIDRs != "" {
			drawn, err := sampleIPv4(splitList(*sampleCIDRs), *sampleN, mrand.New(mrand.NewSource(time.Now().UnixNano())))
			if err != nil {
				fmt.Fprintln(os.Stderr, "bad -sample-cidrs:", err)
				os.Exit(2)
			}
			sampled = drawn
		}
		siteCheckRun(*doh, splitList(*siteURLs), *timeout, *siteReport, *adminToken, *reportSource, *siteTTL, *historyPath, sampled)
		return
	}

	if *githubSources != "" {
		if *githubReport != "" && *adminToken == "" {
			fmt.Fprintln(os.Stderr, "-github-report requires -admin-token")
			os.Exit(2)
		}
		githubRun(*doh, splitList(*githubSources), splitList(*githubHosts), *rounds, *timeout, *githubReport, *adminToken, *reportSource, *githubTTL, *githubShare, *githubResolver)
		return
	}

	if *h3Hosts != "" {
		if *h3Report != "" && *adminToken == "" {
			fmt.Fprintln(os.Stderr, "-h3-report requires -admin-token")
			os.Exit(2)
		}
		h3Check(*doh, splitList(*h3Hosts), *rounds, *timeout, *h3Report, *adminToken, *reportSource, *h3TTL, *h3History)
		return
	}
	if *selfcheckHosts != "" {
		if *selfcheckReport != "" && *adminToken == "" {
			fmt.Fprintln(os.Stderr, "-selfcheck-report requires -admin-token")
			os.Exit(2)
		}
		selfCheck(*doh, splitList(*selfcheckHosts), splitList(*selfcheckNoH3), *selfcheckReport, *adminToken, *reportSource)
		return
	}
	if *metaHost != "" {
		if *healthURL != "" && *adminToken == "" {
			fmt.Fprintln(os.Stderr, "-health requires -admin-token")
			os.Exit(2)
		}
		metaCheck(*doh, *metaHost, *timeout, *healthURL, *adminToken, *reportSource, *metaTTL)
		return
	}
	if *report != "" {
		if *rank == "" || *adminToken == "" {
			fmt.Fprintln(os.Stderr, "-report requires -rank candidates and -admin-token")
			os.Exit(2)
		}
		resolver := *resolveDoh
		if resolver == "" {
			resolver = *doh
		}
		reportRun(*doh, resolver, *rank, *rankTarget, *rounds, *timeout, *report, *adminToken, *reportSource, *reportScope, *reportTop, *reportMin, *reportTTL, *historyPath)
		return
	}
	if *rank != "" {
		rankRun(*doh, *rank, *rankTarget, *rounds, *timeout)
		return
	}

	var out []result
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		out = append(out, probe(*doh, h, *ipOverride, *timeout))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func probe(doh, host, ipOverride string, timeout time.Duration) result {
	r := result{Host: host}

	ech, publicName, hints, err := queryHTTPS(doh, host)
	if err != nil {
		r.WithECH.Error = "doh HTTPS query: " + err.Error()
		return r
	}
	r.EchConfigBytes = len(ech)
	r.EchPublicName = publicName

	ips, err := queryA(doh, host)
	if err != nil {
		r.WithECH.Error = "doh A query: " + err.Error()
		return r
	}
	if len(ips) == 0 {
		ips = hints
	}
	r.IPs = ips

	switch {
	case ipOverride != "":
		r.DialIP = ipOverride
	case len(ips) > 0:
		r.DialIP = ips[0]
	default:
		r.WithECH.Error = "no address to dial"
		return r
	}

	if len(ech) == 0 {
		r.WithECH.Error = "DoH response carried no ECH config"
	} else {
		r.WithECH = handshake(r.DialIP, host, ech, timeout)
	}
	r.WithoutECH = handshake(r.DialIP, host, nil, timeout)
	return r
}

// handshake is the transport used by probe/rank; swapped to handshakeQUIC by -quic.
var handshake = handshakeTCP

func handshakeTCP(ip, sni string, ech []byte, timeout time.Duration) (a attempt) {
	start := time.Now()
	defer func() { a.Millis = time.Since(start).Milliseconds() }()

	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	if ech != nil {
		cfg.EncryptedClientHelloConfigList = ech
	}

	raw, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		a.Error = "tcp: " + err.Error()
		return a
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		var rej *tls.ECHRejectionError
		if errors.As(err, &rej) {
			a.Error = fmt.Sprintf("tls: ECH rejected by server (retry config %d bytes)", len(rej.RetryConfigList))
		} else {
			a.Error = "tls: " + err.Error()
		}
		return a
	}
	cs := conn.ConnectionState()
	a.Handshake = true
	a.ECHAccepted = cs.ECHAccepted
	a.ALPN = cs.NegotiatedProtocol

	// /cdn-cgi/trace: answered by every Cloudflare zone without bot challenges, so a non-200 means the
	// edge refused the zone (e.g. error 1034 on Enterprise-only IPs), not that the site dislikes us.
	req := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\r\nHost: %s\r\nUser-Agent: echprobe\r\nConnection: close\r\n\r\n", sni)
	if _, err := io.WriteString(conn, req); err != nil {
		a.Error = "http write: " + err.Error()
		return a
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		a.Error = "http read: " + err.Error()
		return a
	}
	a.HTTPStatus = strings.TrimSpace(line)
	return a
}

func dohRoundTrip(doh string, name string, t dnsmessage.Type) (*dnsmessage.Message, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: binary.BigEndian.Uint16(idb[:]), RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	wire, err := b.Finish()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, doh, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var m dnsmessage.Message
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	return &m, nil
}

func queryA(doh, host string) ([]string, error) {
	m, err := dohRoundTrip(doh, host, dnsmessage.TypeA)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			ips = append(ips, net.IP(a.A[:]).String())
		}
	}
	return ips, nil
}

func queryAAAA(doh, host string) ([]string, error) {
	m, err := dohRoundTrip(doh, host, dnsmessage.TypeAAAA)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AAAAResource); ok {
			ips = append(ips, net.IP(a.AAAA[:]).String())
		}
	}
	return ips, nil
}

// queryHTTPS returns the ECHConfigList (SvcParam key 5), the ECH public name
// parsed from it, and any ipv4hint addresses (key 4).
func queryHTTPS(doh, host string) (ech []byte, publicName string, hints []string, err error) {
	m, err := dohRoundTrip(doh, host, dnsmessage.Type(65))
	if err != nil {
		return nil, "", nil, err
	}
	for _, rr := range m.Answers {
		h, ok := rr.Body.(*dnsmessage.HTTPSResource)
		if !ok {
			continue
		}
		if v, ok := h.GetParam(dnsmessage.SVCParamECH); ok && len(v) > 0 {
			ech = append([]byte(nil), v...)
			publicName = echPublicName(ech)
		}
		if v, ok := h.GetParam(dnsmessage.SVCParamIPv4Hint); ok {
			for i := 0; i+4 <= len(v); i += 4 {
				hints = append(hints, net.IP(v[i:i+4]).String())
			}
		}
	}
	return ech, publicName, hints, nil
}

// echPublicName extracts public_name from the first ECHConfig in a list
// (draft-ietf-tls-esni, version 0xfe0d). Best-effort, for display only.
func echPublicName(list []byte) string {
	if len(list) < 2 {
		return ""
	}
	p := list[2:]
	if len(p) < 4 {
		return ""
	}
	if binary.BigEndian.Uint16(p) != 0xfe0d {
		return ""
	}
	p = p[4:] // version + length
	if len(p) < 1 {
		return ""
	}
	p = p[1:] // config_id
	if len(p) < 2 {
		return ""
	}
	p = p[2:] // kem_id
	if len(p) < 2 {
		return ""
	}
	pkLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < pkLen+2 {
		return ""
	}
	p = p[pkLen:]
	csLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < csLen+1 {
		return ""
	}
	p = p[csLen:]
	p = p[1:] // maximum_name_length
	if len(p) < 1 {
		return ""
	}
	nl := int(p[0])
	p = p[1:]
	if len(p) < nl {
		return ""
	}
	return string(p[:nl])
}
