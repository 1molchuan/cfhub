package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// carriers are the operators whose ranges come from github.com/gaoyifan/china-operator-ip.
var carriers = []string{"chinanet", "unicom", "cmcc", "cernet"}

// operators are the categories with their own pool, in display order: the carriers, then domestic
// cloud providers taken together ("cloud"; volunteers often run the prober on a cloud server, and
// datacenter lines reach Cloudflare differently from home lines). Everything else (other networks,
// overseas) reports as "other": shown on the dashboard, never published as a pool.
var operators = append(slices.Clone(carriers), "cloud")

var operatorNames = map[string]string{
	"chinanet": "电信",
	"unicom":   "联通",
	"cmcc":     "移动",
	"cernet":   "教育网",
	"cloud":    "国内云厂商",
	"other":    "其他",
	"national": "全国", // the nationwide pool (aggregate.go), not a line
}

// cloudProviders are the domestic clouds counted as "cloud", by the ASNs of their mainland regions
// (their overseas ASNs — Alibaba 45102, Tencent 132203, Huawei 136907 — reach Cloudflare like any
// foreign datacenter and stay "other"). Ranges come from RIPEstat's announced prefixes, daily.
var cloudProviders = []struct {
	Key, Name string
	ASNs      []int
}{
	{"aliyun", "阿里云", []int{37963}},
	{"tencent", "腾讯云", []int{45090}},
	{"huawei", "华为云", []int{55990}},
	{"baidu", "百度智能云", []int{55967, 38365}},
	{"volcengine", "火山引擎", []int{137718}},
	{"jdcloud", "京东云", []int{131486}},
	{"ksyun", "金山云", []int{59019}},
}

// providerName is the display name of a cloud provider key, or "" if unknown.
func providerName(key string) string {
	for _, p := range cloudProviders {
		if p.Key == key {
			return p.Name
		}
	}
	return ""
}

// minEntries guards a refresh against a truncated download: a list this short is not believable.
var minEntries = map[string]int{"chinanet": 500, "unicom": 300, "cmcc": 200, "cernet": 20}

const defaultASNURL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%d&sourceapp=cfhub"

// netData holds the operator table (carriers from github.com/gaoyifan/china-operator-ip plus the
// cloud providers' ranges; served to the DoH as "<isp> <cidr>" lines) and Cloudflare's published
// ranges. All refresh daily and are kept on disk, so a restart never depends on GitHub, RIPEstat or
// cloudflare.com being reachable.
type netData struct {
	mu          sync.RWMutex
	carrierText string                  // "<carrier> <cidr>" lines
	cloudText   string                  // "<provider> <cidr>" lines
	ispText     string                  // served: cloud ranges as "cloud <cidr>", then the carriers'
	isp         map[netip.Prefix]string // carrier name, or "cloud/<provider>"
	bits4       []int                   // prefix lengths present, longest first
	bits6       []int
	cf          []netip.Prefix

	dir     string
	ispBase string
	cfURLs  []string
	asnURL  string // fmt pattern taking the AS number
	client  *http.Client
}

func newNetData(dir, ispBase string, cfURLs []string) *netData {
	return &netData{dir: dir, ispBase: strings.TrimRight(ispBase, "/"), cfURLs: cfURLs, asnURL: defaultASNURL, client: &http.Client{Timeout: 30 * time.Second}}
}

func (d *netData) ispFile() string   { return filepath.Join(d.dir, "isp-table.txt") }
func (d *netData) cloudFile() string { return filepath.Join(d.dir, "cloud-table.txt") }
func (d *netData) cfFile() string    { return filepath.Join(d.dir, "cloudflare-ranges.txt") }

// classify returns the table entry for addr ("chinanet", "cloud/aliyun", ...), or "". Most specific
// prefix wins.
func (d *netData) classify(addr netip.Addr) string {
	addr = addr.Unmap()
	d.mu.RLock()
	defer d.mu.RUnlock()
	bits := d.bits6
	if addr.Is4() {
		bits = d.bits4
	}
	for _, b := range bits {
		prefix, err := addr.Prefix(b)
		if err != nil {
			continue
		}
		if name, ok := d.isp[prefix]; ok {
			return name
		}
	}
	return ""
}

// ISPOf names the operator category of addr ("chinanet", ..., "cloud"), or "" when it is in none.
func (d *netData) ISPOf(addr netip.Addr) string {
	isp, _, _ := strings.Cut(d.classify(addr), "/")
	return isp
}

// ProviderOf names the cloud provider of addr ("aliyun", ...), or "" when it is not a cloud address.
func (d *netData) ProviderOf(addr netip.Addr) string {
	_, provider, _ := strings.Cut(d.classify(addr), "/")
	return provider
}

// IsCloudflare reports whether addr is inside Cloudflare's published ranges.
func (d *netData) IsCloudflare(addr netip.Addr) bool {
	addr = addr.Unmap()
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, prefix := range d.cf {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (d *netData) ISPTableText() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ispText
}

func (d *netData) Ready() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.carrierText != "" && len(d.isp) > 0 && len(d.cf) > 0
}

// buildISPTable merges the cloud providers' ranges ("<provider> <cidr>") and the carriers'
// ("<carrier> <cidr>") into one lookup table and the text served to the DoH. Cloud lines come first
// and a prefix listed twice keeps its first entry, so the hub and the DoH (most specific range wins,
// see src/isp.ts) classify every address the same way.
func buildISPTable(carrierText, cloudText string) (map[netip.Prefix]string, string, []int, []int, error) {
	table := map[netip.Prefix]string{}
	seen4, seen6 := map[int]bool{}, map[int]bool{}
	var served strings.Builder
	served.WriteString("# client IP -> operator (cloud = domestic cloud providers); served by cfhub\n")
	add := func(text string, cloud bool) {
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 2 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			prefix, err := netip.ParsePrefix(fields[1])
			if err != nil {
				continue
			}
			prefix = prefix.Masked()
			if _, dup := table[prefix]; dup {
				continue
			}
			name := fields[0]
			if cloud {
				table[prefix] = "cloud/" + name
				name = "cloud"
			} else {
				table[prefix] = name
			}
			fmt.Fprintf(&served, "%s %s\n", name, prefix)
			if prefix.Addr().Is4() {
				seen4[prefix.Bits()] = true
			} else {
				seen6[prefix.Bits()] = true
			}
		}
	}
	add(cloudText, true)
	add(carrierText, false)
	if len(table) == 0 {
		return nil, "", nil, nil, errors.New("operator table is empty")
	}
	return table, served.String(), sortedDesc(seen4), sortedDesc(seen6), nil
}

func sortedDesc(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for b := range set {
		out = append(out, b)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func parseCIDRs(text string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, field := range strings.Fields(text) {
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", field, err)
		}
		out = append(out, prefix.Masked())
	}
	if len(out) == 0 {
		return nil, errors.New("no CIDRs")
	}
	return out, nil
}

// setISP replaces the carrier lines, setCloud the cloud provider lines; either rebuilds the table.
func (d *netData) setISP(text string) error   { return d.setTables(&text, nil) }
func (d *netData) setCloud(text string) error { return d.setTables(nil, &text) }

func (d *netData) setTables(carrierText, cloudText *string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	carrier, cloud := d.carrierText, d.cloudText
	if carrierText != nil {
		carrier = *carrierText
	}
	if cloudText != nil {
		cloud = *cloudText
	}
	table, served, bits4, bits6, err := buildISPTable(carrier, cloud)
	if err != nil {
		return err
	}
	d.carrierText, d.cloudText, d.ispText, d.isp, d.bits4, d.bits6 = carrier, cloud, served, table, bits4, bits6
	return nil
}

func (d *netData) setCF(text string) error {
	prefixes, err := parseCIDRs(text)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.cf = prefixes
	d.mu.Unlock()
	return nil
}

// Load reads the last good copies from disk (no network).
func (d *netData) Load() {
	if raw, err := os.ReadFile(d.ispFile()); err == nil {
		if err := d.setISP(string(raw)); err != nil {
			log.Printf("netdata: cached operator table unusable: %v", err)
		}
	}
	if raw, err := os.ReadFile(d.cloudFile()); err == nil {
		if err := d.setCloud(string(raw)); err != nil {
			log.Printf("netdata: cached cloud table unusable: %v", err)
		}
	}
	if raw, err := os.ReadFile(d.cfFile()); err == nil {
		if err := d.setCF(string(raw)); err != nil {
			log.Printf("netdata: cached Cloudflare ranges unusable: %v", err)
		}
	}
}

func (d *netData) fetch(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return string(body), err
}

// Refresh downloads every dataset; each is replaced only if the new copy is complete and valid.
func (d *netData) Refresh(ctx context.Context) error {
	var errs []error
	if err := d.refreshISP(ctx); err != nil {
		errs = append(errs, fmt.Errorf("operator table: %w", err))
	}
	if err := d.refreshCloud(ctx); err != nil {
		errs = append(errs, fmt.Errorf("cloud table: %w", err))
	}
	if err := d.refreshCF(ctx); err != nil {
		errs = append(errs, fmt.Errorf("cloudflare ranges: %w", err))
	}
	return errors.Join(errs...)
}

// refreshCloud rebuilds the cloud table from RIPEstat's announced prefixes of each provider's ASNs.
// Any failed or empty ASN keeps the whole previous table: a partial one would move that provider's
// probers to "other".
func (d *netData) refreshCloud(ctx context.Context) error {
	var b strings.Builder
	b.WriteString("# domestic cloud provider -> announced prefixes (RIPEstat); served by cfhub as \"cloud\"\n")
	for _, p := range cloudProviders {
		for _, asn := range p.ASNs {
			text, err := d.fetch(ctx, fmt.Sprintf(d.asnURL, asn))
			if err != nil {
				return err
			}
			var body struct {
				Data struct {
					Prefixes []struct {
						Prefix string `json:"prefix"`
					} `json:"prefixes"`
				} `json:"data"`
			}
			if err := json.Unmarshal([]byte(text), &body); err != nil {
				return fmt.Errorf("AS%d: %w", asn, err)
			}
			count := 0
			for _, entry := range body.Data.Prefixes {
				if _, err := netip.ParsePrefix(entry.Prefix); err != nil {
					continue
				}
				fmt.Fprintf(&b, "%s %s\n", p.Key, entry.Prefix)
				count++
			}
			if count == 0 {
				return fmt.Errorf("AS%d (%s) announces no prefixes; keeping the previous table", asn, p.Key)
			}
		}
	}
	text := b.String()
	if err := d.setCloud(text); err != nil {
		return err
	}
	return writeFileAtomic(d.cloudFile(), []byte(text))
}

func (d *netData) refreshISP(ctx context.Context) error {
	var b strings.Builder
	b.WriteString("# client IP -> operator, from github.com/gaoyifan/china-operator-ip\n")
	for _, name := range carriers {
		count := 0
		for _, suffix := range []string{"", "6"} {
			text, err := d.fetch(ctx, fmt.Sprintf("%s/%s%s.txt", d.ispBase, name, suffix))
			if err != nil {
				return err
			}
			for _, field := range strings.Fields(text) {
				if _, err := netip.ParsePrefix(field); err != nil {
					continue
				}
				fmt.Fprintf(&b, "%s %s\n", name, field)
				if suffix == "" {
					count++
				}
			}
		}
		if count < minEntries[name] {
			return fmt.Errorf("%s has only %d IPv4 prefixes (want >= %d); keeping the previous table", name, count, minEntries[name])
		}
	}
	text := b.String()
	if err := d.setISP(text); err != nil {
		return err
	}
	return writeFileAtomic(d.ispFile(), []byte(text))
}

func (d *netData) refreshCF(ctx context.Context) error {
	var parts []string
	for _, url := range d.cfURLs {
		text, err := d.fetch(ctx, url)
		if err != nil {
			return err
		}
		if _, err := parseCIDRs(text); err != nil {
			return err
		}
		parts = append(parts, strings.TrimSpace(text))
	}
	text := strings.Join(parts, "\n") + "\n"
	if err := d.setCF(text); err != nil {
		return err
	}
	return writeFileAtomic(d.cfFile(), []byte(text))
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
