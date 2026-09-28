package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/service"
	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

// The volunteer map: each prober's province, from its reporter prefix, counted over the last day.
// Provinces come from ip2region (github.com/lionsoul2014/ip2region, Apache-2.0/MIT), refreshed weekly
// and kept on disk. Only counts are published, never who is where.

const regionWindow = 24 * time.Hour

// outsideMainland: drawn on the map (it is a map of China) but not counted: the statistics cover
// mainland China only.
var outsideMainland = map[string]bool{"台湾": true, "香港": true, "澳门": true}

// shortProvince turns "广西壮族自治区", "广西", "上海市", "香港特别行政区" into "广西", "上海", "香港".
func shortProvince(name string) string {
	for _, suffix := range []string{"特别行政区", "维吾尔自治区", "壮族自治区", "回族自治区", "自治区", "省", "市"} {
		if s, ok := strings.CutSuffix(name, suffix); ok && s != "" {
			return s
		}
	}
	return name
}

type regionDB struct {
	dir, base string
	client    *http.Client

	mu    sync.RWMutex
	svc   *service.Ip2Region
	cache map[string]string // prefix -> short province ("" = not in China or unknown)
}

func newRegionDB(dir, base string) *regionDB {
	return &regionDB{dir: dir, base: strings.TrimRight(base, "/"), client: &http.Client{Timeout: 10 * time.Minute}, cache: map[string]string{}}
}

// Only the IPv4 database: the map counts machines by their IPv4 prefix.
const regionFile = "ip2region_v4.xdb"

func (r *regionDB) file() string { return filepath.Join(r.dir, regionFile) }

// Load opens the copy on disk (no network). A missing file leaves lookups empty until Refresh.
func (r *regionDB) Load() error {
	if _, err := os.Stat(r.file()); err != nil {
		return nil
	}
	v4, err := service.NewV4Config(service.VIndexCache, r.file(), 2)
	if err != nil {
		return err
	}
	svc, err := service.NewIp2Region(v4, nil)
	if err != nil {
		return err
	}
	r.mu.Lock()
	old := r.svc
	r.svc, r.cache = svc, map[string]string{}
	r.mu.Unlock()
	if old != nil {
		old.CloseTimeout(5 * time.Second)
	}
	return nil
}

// Refresh downloads the database when it is missing or a week old, verifies it and reloads.
func (r *regionDB) Refresh(ctx context.Context) error {
	if info, err := os.Stat(r.file()); err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
		return nil
	}
	if err := r.download(ctx); err != nil {
		return fmt.Errorf("ip2region: %w", err)
	}
	return r.Load()
}

func (r *regionDB) download(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.base+"/"+regionFile, nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := r.file() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, io.LimitReader(resp.Body, 256<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = xdb.VerifyFromFile(tmp) // a truncated or wrong file must not replace a good one
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, r.file())
}

func (r *regionDB) Close() {
	r.mu.Lock()
	svc := r.svc
	r.svc = nil
	r.mu.Unlock()
	if svc != nil {
		svc.Close()
	}
}

func (r *regionDB) Ready() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.svc != nil
}

// Province returns the short province name ("广东", "香港", ...) of a reporter prefix, or "" when it
// is outside China or unknown.
func (r *regionDB) Province(prefix string) string {
	r.mu.RLock()
	name, ok := r.cache[prefix]
	svc := r.svc
	r.mu.RUnlock()
	if ok || svc == nil {
		return name
	}
	if p, err := netip.ParsePrefix(prefix); err == nil {
		// "中国|广东省|广州市|电信|CN"
		if region, err := svc.Search(p.Addr().String()); err == nil {
			if f := strings.Split(region, "|"); len(f) >= 2 && f[0] == "中国" && f[1] != "0" {
				name = shortProvince(f[1])
			}
		}
	}
	r.mu.Lock()
	r.cache[prefix] = name
	r.mu.Unlock()
	return name
}

// RegionStat is one province's volunteers over the last day. Probers are counted by IPv4 prefix, so a
// dual-stack machine counts once.
type RegionStat struct {
	Name    string         `json:"name"`
	Users   int            `json:"users"`
	Probers int            `json:"probers"`
	ISPs    map[string]int `json:"isps"` // category -> probers
	LastAt  int64          `json:"last_at"`
}

type RegionSnapshot struct {
	Provinces map[string]*RegionStat `json:"provinces"` // mainland only, by short name
	Users     int                    `json:"users"`     // mainland
	Probers   int                    `json:"probers"`   // mainland
	Elsewhere int                    `json:"elsewhere"` // probers outside mainland China (or unknown)
}

// regionStats counts IPv4 probers per mainland province from reports (newest first).
func regionStats(reports []Report, province func(prefix string) string) RegionSnapshot {
	snap := RegionSnapshot{Provinces: map[string]*RegionStat{}}
	seen := map[string]bool{}
	users := map[string]map[int64]bool{}
	allUsers := map[int64]bool{}
	for _, r := range reports {
		if r.Family != 4 || seen[r.Prefix] {
			continue
		}
		seen[r.Prefix] = true
		name := province(r.Prefix)
		if name == "" || outsideMainland[name] {
			snap.Elsewhere++
			continue
		}
		st := snap.Provinces[name]
		if st == nil {
			st = &RegionStat{Name: name, ISPs: map[string]int{}}
			snap.Provinces[name] = st
			users[name] = map[int64]bool{}
		}
		st.Probers++
		st.ISPs[r.ISP]++
		st.LastAt = max(st.LastAt, r.At)
		users[name][r.UserID] = true
		allUsers[r.UserID] = true
		snap.Probers++
	}
	for name, st := range snap.Provinces {
		st.Users = len(users[name])
	}
	snap.Users = len(allUsers)
	return snap
}

//go:embed geo/china.json
var chinaMapJSON []byte

type geoProvince struct {
	Adcode string  `json:"adcode"`
	Name   string  `json:"name"`
	D      string  `json:"d"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
}

type geoMap struct {
	Width, Height float64
	Provinces     []geoProvince
	Inset         struct {
		X, Y, W, H float64
		Paths      map[string]string `json:"paths"`
		NineDash   string            `json:"nine_dash"`
	}
}

var chinaMap = func() geoMap {
	var m geoMap
	if err := json.Unmarshal(chinaMapJSON, &m); err != nil {
		log.Fatalf("geo/china.json: %v", err)
	}
	return m
}()

// Labels of these regions would sit on top of their neighbours'; their shapes still carry a tooltip.
var noLabel = map[string]bool{"天津": true, "香港": true, "澳门": true}

type mapShape struct {
	D, Class, Tip, Label string
	X, Y                 float64
}

type mapView struct {
	Width, Height float64
	Shapes        []mapShape
	InsetX        float64
	InsetY        float64
	InsetW        float64
	InsetH        float64
	Inset         []mapShape
	NineDash      string
}

// level is the colour step of a province with n probers (classes lv0..lv4 in app.css).
func level(n int) string {
	switch {
	case n == 0:
		return "lv0"
	case n == 1:
		return "lv1"
	case n <= 3:
		return "lv2"
	case n <= 9:
		return "lv3"
	}
	return "lv4"
}

func regionTip(name string, st *RegionStat) string {
	if outsideMainland[name] {
		return name + "：不在统计范围（统计仅含中国大陆）"
	}
	if st == nil {
		return name + "：暂无探针"
	}
	return fmt.Sprintf("%s：%d 人 · %d 台\n%s\n最近上报 %s", name, st.Users, st.Probers, ispSummary(st.ISPs), time.Unix(st.LastAt, 0).In(cst).Format("01-02 15:04"))
}

// ispSummary lists a province's probers by line category, largest first: "电信 2 · 移动 1".
func ispSummary(isps map[string]int) string {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range isps {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	parts := make([]string, len(list))
	for i, e := range list {
		name := operatorNames[e.k]
		if name == "" {
			name = e.k
		}
		parts[i] = fmt.Sprintf("%s %d", name, e.v)
	}
	return strings.Join(parts, " · ")
}

func buildMapView(snap RegionSnapshot) mapView {
	m := chinaMap
	v := mapView{Width: m.Width, Height: m.Height, InsetX: m.Inset.X, InsetY: m.Inset.Y, InsetW: m.Inset.W, InsetH: m.Inset.H, NineDash: m.Inset.NineDash}
	class := func(name string) string {
		if outsideMainland[name] {
			return "out"
		}
		if st := snap.Provinces[name]; st != nil {
			return level(st.Probers)
		}
		return "lv0"
	}
	for _, p := range m.Provinces {
		name := shortProvince(p.Name)
		s := mapShape{D: p.D, Class: class(name), Tip: regionTip(name, snap.Provinces[name]), X: p.X, Y: p.Y}
		if !noLabel[name] {
			s.Label = name
		}
		v.Shapes = append(v.Shapes, s)
		if d := m.Inset.Paths[p.Adcode]; d != "" {
			v.Inset = append(v.Inset, mapShape{D: d, Class: s.Class, Tip: s.Tip})
		}
	}
	return v
}

func (h *Hub) regionSnapshot() (RegionSnapshot, []Leader) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.regions, h.leaders
}

// sorted lists the provinces with probers, most probers first.
func (snap RegionSnapshot) sorted() []*RegionStat {
	list := make([]*RegionStat, 0, len(snap.Provinces))
	for _, st := range snap.Provinces {
		list = append(list, st)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Probers != list[j].Probers {
			return list[i].Probers > list[j].Probers
		}
		return list[i].Name < list[j].Name
	})
	return list
}

// GET /api/v1/regions — volunteers per mainland province over the last day (counts only).
func (h *Hub) handleAPIRegions(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	snap, _ := h.regionSnapshot()
	_, at := h.snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"updated_at": at, "scope": "中国大陆", "window_hours": int(regionWindow.Hours()),
		"users": snap.Users, "probers": snap.Probers, "elsewhere": snap.Elsewhere, "provinces": snap.sorted(),
	})
}
