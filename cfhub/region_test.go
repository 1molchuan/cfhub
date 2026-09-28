package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMapHasEveryProvinceAndNamesMatchIP2Region(t *testing.T) {
	names := map[string]bool{}
	mainland := 0
	for _, p := range chinaMap.Provinces {
		name := shortProvince(p.Name)
		if names[name] || p.D == "" {
			t.Fatalf("province %q duplicated or without a shape", p.Name)
		}
		names[name] = true
		if !outsideMainland[name] {
			mainland++
		}
	}
	if len(names) != 34 || mainland != 31 {
		t.Fatalf("%d regions, %d mainland; want 34 and 31", len(names), mainland)
	}
	for _, name := range []string{"台湾", "香港", "澳门"} {
		if !names[name] {
			t.Errorf("%s missing from the map", name)
		}
	}
	if chinaMap.Inset.NineDash == "" || len(chinaMap.Inset.Paths) == 0 {
		t.Fatal("the South China Sea inset (islands and nine-dash line) is missing")
	}
	// The forms ip2region uses must land on a map region.
	for _, raw := range []string{"广东省", "上海市", "北京市", "内蒙古", "广西", "新疆", "西藏", "宁夏", "内蒙古自治区", "广西壮族自治区", "新疆维吾尔自治区", "宁夏回族自治区", "香港特别行政区", "澳门特别行政区", "台湾省", "黑龙江省"} {
		if !names[shortProvince(raw)] {
			t.Errorf("ip2region name %q -> %q is not on the map", raw, shortProvince(raw))
		}
	}
}

func TestRegionStatsCountMainlandProbersOnce(t *testing.T) {
	where := map[string]string{
		"58.247.1.0/24": "上海", "58.247.2.0/24": "上海", "120.192.1.0/24": "广东",
		"203.0.113.0/24": "香港", "198.51.100.0/24": "",
	}
	r := func(user int64, prefix, isp string, family int, at int64) Report {
		return Report{UserID: user, Prefix: prefix, ISP: isp, Family: family, At: at}
	}
	snap := regionStats([]Report{ // newest first
		r(1, "58.247.1.0/24", "chinanet", 4, 300),
		r(1, "58.247.1.0/24", "chinanet", 4, 200), // same prober again
		r(1, "2408:1::/48", "chinanet", 6, 200),   // its IPv6 side: not a second machine
		r(2, "58.247.2.0/24", "unicom", 4, 250),
		r(1, "120.192.1.0/24", "cmcc", 4, 100),
		r(3, "203.0.113.0/24", "other", 4, 100),
		r(4, "198.51.100.0/24", "other", 4, 100),
	}, func(prefix string) string { return where[prefix] })
	sh, gd := snap.Provinces["上海"], snap.Provinces["广东"]
	if sh == nil || sh.Users != 2 || sh.Probers != 2 || sh.ISPs["chinanet"] != 1 || sh.ISPs["unicom"] != 1 || sh.LastAt != 300 {
		t.Fatalf("上海 %+v; want 2 users, 2 probers (telecom 1, unicom 1), last 300", sh)
	}
	if gd == nil || gd.Users != 1 || gd.Probers != 1 {
		t.Fatalf("广东 %+v", gd)
	}
	if snap.Users != 2 || snap.Probers != 3 || snap.Elsewhere != 2 || snap.Provinces["香港"] != nil {
		t.Fatalf("totals %+v; want 2 users, 3 mainland probers, 2 elsewhere (Hong Kong, unknown)", snap)
	}
	if got := ispSummary(sh.ISPs); got != "电信 1 · 联通 1" {
		t.Fatalf("summary %q", got)
	}
	v := buildMapView(snap)
	classes := map[string]string{}
	for i, p := range chinaMap.Provinces {
		classes[shortProvince(p.Name)] = v.Shapes[i].Class
	}
	if classes["上海"] != "lv2" || classes["广东"] != "lv1" || classes["西藏"] != "lv0" || classes["香港"] != "out" || classes["台湾"] != "out" {
		t.Fatalf("classes %v", classes)
	}
}

func TestUptimeCountsHoursPerProberAndSkipsBannedUsers(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, u := range []User{{ID: 1, Username: "alice"}, {ID: 2, Username: "bob"}, {ID: 3, Username: "mallory"}} {
		if _, err := store.UpsertUser(u, 0); err != nil {
			t.Fatal(err)
		}
	}
	const h = 3600
	now := int64(1000 * h)
	add := func(user int64, prefix string, family int, at int64) {
		if err := store.InsertReport(Report{UserID: user, Prefix: prefix, ISP: "chinanet", Family: family, At: at}); err != nil {
			t.Fatal(err)
		}
	}
	// Alice: one prober, three distinct hours (two reports in hour 990), plus IPv6 reports that do not count.
	add(1, "58.247.1.0/24", 4, 990*h+10)
	add(1, "58.247.1.0/24", 4, 990*h+2000)
	add(1, "58.247.1.0/24", 4, 991*h)
	add(1, "58.247.1.0/24", 4, 999*h)
	add(1, "2408:1::/48", 6, 999*h)
	// Bob: two probers, 2 hours each, one of them online now.
	add(2, "58.247.2.0/24", 4, 900*h)
	add(2, "58.247.2.0/24", 4, 901*h)
	add(2, "58.247.3.0/24", 4, 998*h)
	add(2, "58.247.3.0/24", 4, 1000*h)
	add(3, "58.247.4.0/24", 4, 999*h)
	_ = store.SetBanned(3, true, "")

	leaders, err := store.Leaders(now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaders) != 2 {
		t.Fatalf("leaders %+v; the banned user must not be listed", leaders)
	}
	if l := leaders[0]; l.Username != "bob" || l.Hours != 4 || l.Probers != 2 || l.Online != 1 || l.Since != 900*h {
		t.Fatalf("first %+v; want bob 4h, 2 probers, 1 online, since hour 900", l)
	}
	if l := leaders[1]; l.Username != "alice" || l.Hours != 3 || l.Probers != 1 || l.Online != 1 {
		t.Fatalf("second %+v; want alice 3h over 1 prober", l)
	}
}

func TestUptimeBackfillsFromExistingReportsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.UpsertUser(User{ID: 1, Username: "alice"}, 0)
	// Reports stored by a build without uptime tracking.
	for _, at := range []int64{3600, 7200, 7300, 10800} {
		if _, err := store.db.Exec(`INSERT INTO reports (user_id, at, prefix, isp, family, ips, dropped, version) VALUES (1, ?, '58.247.1.0/24', 'chinanet', 4, '[]', 0, '')`, at); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = store.db.Exec(`DELETE FROM prober_uptime`)
	_ = store.SetSetting("uptime_backfilled", "0")
	store.Close()
	for range 2 { // reopening must not count them again
		if store, err = OpenStore(path); err != nil {
			t.Fatal(err)
		}
		leaders, _ := store.Leaders(10800, 10)
		if len(leaders) != 1 || leaders[0].Hours != 3 || leaders[0].Since != 3600 {
			t.Fatalf("after backfill %+v; want 3 hours since 3600", leaders)
		}
		store.Close()
	}
}

func TestDashboardShowsMapAndThanksList(t *testing.T) {
	te := newTestEnv(t, "")
	alice := te.user(t, 30, "alice")
	te.do(t, "POST", "/api/v1/probe/report", alice, "58.247.1.9", report("104.16.1.1"))
	te.hub.runAggregation(context.Background())
	te.hub.mu.Lock()
	te.hub.regions = regionStats([]Report{{UserID: 30, Prefix: "58.247.1.0/24", ISP: "chinanet", Family: 4, At: unixNow()}}, func(string) string { return "上海" })
	te.hub.mu.Unlock()

	resp := te.do(t, "GET", "/", "", "", nil)
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	for _, want := range []string{"<svg viewBox=\"0 0 1000", "统计范围：中国大陆", "上海：1 人 · 1 台", "香港：不在统计范围", "南海诸岛", "DataV.GeoAtlas", "感谢榜", "https://linux.do/u/alice", "1 小时"} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if strings.Contains(page, "style=") {
		t.Error("inline styles are blocked by the CSP (style-src 'self'); use classes")
	}

	resp = te.do(t, "GET", "/api/v1/regions", "", "", nil)
	var got struct {
		Scope     string        `json:"scope"`
		Probers   int           `json:"probers"`
		Provinces []*RegionStat `json:"provinces"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.Scope != "中国大陆" || got.Probers != 1 || len(got.Provinces) != 1 || got.Provinces[0].Name != "上海" {
		t.Fatalf("regions API %+v", got)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("regions API without CORS")
	}
}

func TestFmtHours(t *testing.T) {
	for hours, want := range map[int]string{0: "0 小时", 5: "5 小时", 24: "1 天", 50: "2 天 2 小时"} {
		if got := fmtHours(hours); got != want {
			t.Errorf("fmtHours(%d) = %q, want %q", hours, got, want)
		}
	}
}

func TestRegionDownloadVerifiesAndKeepsTheGoodCopy(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not an xdb file")
	}))
	defer srv.Close()
	db := newRegionDB(dir, srv.URL)
	if err := db.Refresh(context.Background()); err == nil {
		t.Fatal("a corrupt database was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, regionFile)); err == nil || db.Ready() {
		t.Fatal("a corrupt download replaced the database")
	}
	if db.Province("58.247.1.0/24") != "" {
		t.Fatal("lookup without a database must be empty")
	}
}

// With a real ip2region_v4.xdb (CFHUB_TEST_XDB=path), check a few known networks.
func TestRegionLookupWithRealDatabase(t *testing.T) {
	src := os.Getenv("CFHUB_TEST_XDB")
	if src == "" {
		t.Skip("set CFHUB_TEST_XDB to an ip2region_v4.xdb")
	}
	dir := t.TempDir()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, regionFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	db := newRegionDB(dir, "")
	if err := db.Load(); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Refresh(context.Background()); err != nil { // fresh file: no download
		t.Fatal(err)
	}
	for prefix, want := range map[string]string{
		"202.120.2.0/24": "上海", "123.125.114.0/24": "北京", "1.1.1.0/24": "", "2001:db8::/48": "",
	} {
		if got := db.Province(prefix); got != want {
			t.Errorf("%s: %q, want %q", prefix, got, want)
		}
	}
	start := time.Now()
	for range 1000 {
		db.Province("202.120.2.0/24")
	}
	if time.Since(start) > time.Second {
		t.Error("cached lookups are slow")
	}
}
