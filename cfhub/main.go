// cfhub: crowdsourced Cloudflare preferred IPs, per network operator.
//
// linux.do users sign in, get a personal token, and run a prober (work/echprobe -hub) on their own
// line. cfhub tags each report with the reporter's operator (from the connecting address, which only
// our Caddy may vouch for), votes a pool per operator, and pushes it to the edge DoH, which then
// answers each client with its own operator's pool. It also serves a public dashboard and API and an
// allowlisted admin page. Everything degrades to the DoH's nationwide pool if cfhub is down.
package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	texttemplate "text/template"
	"time"
)

type Config struct {
	Listen    string
	DataDir   string
	DistDir   string
	PublicURL string

	ClientID, ClientSecret          string
	AuthorizeURL, TokenURL, UserURL string
	SessionKey                      []byte
	Admins                          map[int64]bool
	MinTrust                        int

	DoHURL   string
	HubToken string

	Quorum, PoolSize, PushTTL                 int
	ReportTTL, ReportInterval, AggregateEvery time.Duration

	ISPBase string
	CFURLs  []string
	// DLMirrors are base URLs serving the same files as /dl (e.g. a CDN path in front of this host),
	// tried by the installers before /dl itself. They need no trust: every file's sha256 is pinned.
	DLMirrors []string
	// RegionBase serves ip2region_v4.xdb (provinces for the volunteer map).
	RegionBase string
	// ExtraCandidates are sent to every prober to re-test besides the pools, e.g. another pool to
	// compare against on every line (CFHUB_EXTRA_CANDIDATES, comma-separated IPs).
	ExtraCandidates []netip.Addr
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envInt(name string, fallback, lo, hi int) int {
	v, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return fallback
	}
	return max(lo, min(hi, v))
}

func envDuration(name string, fallback time.Duration) time.Duration {
	v, err := time.ParseDuration(os.Getenv(name))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func loadConfig() (Config, error) {
	c := Config{
		Listen:         env("CFHUB_LISTEN", "127.0.0.1:8790"),
		DataDir:        env("CFHUB_DATA_DIR", "/var/lib/cfhub"),
		PublicURL:      strings.TrimRight(env("CFHUB_PUBLIC_URL", ""), "/"),
		ClientID:       env("LINUXDO_CLIENT_ID", ""),
		ClientSecret:   env("LINUXDO_CLIENT_SECRET", ""),
		AuthorizeURL:   env("LINUXDO_AUTHORIZE_URL", "https://connect.linux.do/oauth2/authorize"),
		TokenURL:       env("LINUXDO_TOKEN_URL", "https://connect.linux.do/oauth2/token"),
		UserURL:        env("LINUXDO_USER_URL", "https://connect.linux.do/api/user"),
		SessionKey:     []byte(env("CFHUB_SESSION_KEY", "")),
		Admins:         map[int64]bool{},
		MinTrust:       envInt("CFHUB_MIN_TRUST", 1, 0, 4),
		DoHURL:         env("CFHUB_DOH_URL", "http://127.0.0.1:8787/admin/preferred"),
		HubToken:       env("HUB_TOKEN", ""),
		Quorum:         envInt("CFHUB_QUORUM", 2, 1, 50),
		PoolSize:       envInt("CFHUB_POOL_SIZE", 6, 1, 16),
		PushTTL:        envInt("CFHUB_PUSH_TTL", 1800, 600, 86400),
		ReportTTL:      envDuration("CFHUB_REPORT_TTL", 150*time.Minute),
		ReportInterval: envDuration("CFHUB_REPORT_INTERVAL", 20*time.Minute),
		AggregateEvery: envDuration("CFHUB_AGGREGATE_EVERY", 5*time.Minute),
		ISPBase:        env("CFHUB_ISP_BASE", "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists"),
		CFURLs:         strings.Split(env("CFHUB_CF_URLS", "https://www.cloudflare.com/ips-v4/,https://www.cloudflare.com/ips-v6/"), ","),
		RegionBase:     env("CFHUB_IP2REGION_BASE", "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data"),
	}
	c.DistDir = env("CFHUB_DIST_DIR", filepath.Join(c.DataDir, "dist"))
	for _, raw := range strings.Split(os.Getenv("CFHUB_DL_MIRRORS"), ",") {
		if mirror := strings.TrimRight(strings.TrimSpace(raw), "/"); strings.HasPrefix(mirror, "https://") {
			c.DLMirrors = append(c.DLMirrors, mirror)
		}
	}
	for _, raw := range strings.Split(os.Getenv("CFHUB_EXTRA_CANDIDATES"), ",") {
		if addr, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
			c.ExtraCandidates = append(c.ExtraCandidates, addr)
		}
	}
	for _, raw := range strings.Split(os.Getenv("CFHUB_ADMINS"), ",") {
		if id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); err == nil && id > 0 {
			c.Admins[id] = true
		}
	}
	if c.PublicURL == "" {
		return c, errors.New("CFHUB_PUBLIC_URL is required")
	}
	if len(c.SessionKey) < 32 {
		return c, errors.New("CFHUB_SESSION_KEY must be at least 32 characters")
	}
	return c, nil
}

type Hub struct {
	cfg         Config
	store       *Store
	net         *netData
	region      *regionDB
	client      *http.Client // DoH push
	oauthClient *http.Client
	pages       map[string]*template.Template
	scripts     *texttemplate.Template

	mu           sync.RWMutex
	pools        map[poolKey]*Pool
	regions      RegionSnapshot
	leaders      []Leader
	aggregatedAt int64
	aggMu        sync.Mutex // one aggregation at a time

	distMu    sync.Mutex
	distCache map[string]distEntry
}

func newHub(cfg Config, store *Store, nd *netData) *Hub {
	return &Hub{
		cfg: cfg, store: store, net: nd,
		region:      newRegionDB(cfg.DataDir, cfg.RegionBase),
		client:      &http.Client{Timeout: 10 * time.Second},
		oauthClient: &http.Client{Timeout: 15 * time.Second},
		pages:       loadPages(),
		scripts:     loadScripts(),
		pools:       map[poolKey]*Pool{},
		distCache:   map[string]distEntry{},
	}
}

// every runs fn now (after an initial delay) and then on each tick until ctx ends.
func every(ctx context.Context, initial, interval time.Duration, fn func(context.Context)) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(initial):
	}
	fn(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}

func main() {
	log.SetFlags(0) // journald adds timestamps
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	for _, dir := range []string{cfg.DataDir, cfg.DistDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			log.Fatalf("data dir: %v", err)
		}
	}
	store, err := OpenStore(filepath.Join(cfg.DataDir, "hub.db"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer store.Close()
	nd := newNetData(cfg.DataDir, cfg.ISPBase, cfg.CFURLs)
	nd.Load()
	hub := newHub(cfg, store, nd)
	if err := hub.region.Load(); err != nil {
		log.Printf("ip2region: %v", err)
	}
	if len(cfg.Admins) == 0 {
		log.Print("warning: CFHUB_ADMINS is empty, nobody can open /admin")
	}
	if cfg.HubToken == "" {
		log.Print("warning: HUB_TOKEN is empty, pools are computed but not pushed to the DoH")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go every(ctx, 0, 24*time.Hour, func(ctx context.Context) {
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := nd.Refresh(c); err != nil {
			log.Printf("netdata refresh (keeping the previous copy): %v", err)
		}
	})
	go every(ctx, 5*time.Second, 24*time.Hour, func(ctx context.Context) {
		c, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if err := hub.region.Refresh(c); err != nil {
			log.Printf("region refresh (keeping the previous copy): %v", err)
		}
	})
	go every(ctx, 15*time.Second, cfg.AggregateEvery, hub.runAggregation)
	go every(ctx, time.Minute, time.Hour, func(context.Context) {
		now := time.Now()
		if err := store.Prune(now.Add(-7*24*time.Hour).Unix(), now.Add(-30*24*time.Hour).Unix()); err != nil {
			log.Printf("prune: %v", err)
		}
	})

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           hub.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("cfhub listening on %s (public %s, quorum %d)", cfg.Listen, cfg.PublicURL, cfg.Quorum)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
