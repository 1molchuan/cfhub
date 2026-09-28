package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed scripts/install.sh.tmpl scripts/install.ps1.tmpl
var scriptFS embed.FS

var cst = time.FixedZone("CST", 8*3600)

// cssVersion goes into the stylesheet URL, so a deploy is not rendered with an hour-old cached app.css.
var cssVersion = func() string {
	raw, _ := staticFS.ReadFile("static/app.css")
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:4])
}()

var templateFuncs = template.FuncMap{
	"fmtTime": func(ts int64) string { return time.Unix(ts, 0).In(cst).Format("01-02 15:04") },
	"ispName": func(isp string) string {
		if name, ok := operatorNames[isp]; ok {
			return name
		}
		if isp == "" {
			return "—"
		}
		return isp
	},
	"fmtDate":    func(ts int64) string { return time.Unix(ts, 0).In(cst).Format("2006-01-02") },
	"fmtHours":   fmtHours,
	"ispSummary": ispSummary,
	"inc":        func(i int) int { return i + 1 },
}

// fmtHours writes an uptime as "3 天 4 小时".
func fmtHours(hours int) string {
	switch {
	case hours < 24:
		return fmt.Sprintf("%d 小时", hours)
	case hours%24 == 0:
		return fmt.Sprintf("%d 天", hours/24)
	}
	return fmt.Sprintf("%d 天 %d 小时", hours/24, hours%24)
}

// distFiles are the only files /dl serves, keyed by the checksum name the installers use.
var distFiles = map[string]string{
	"amd64":   "cfprobe-linux-amd64",
	"arm64":   "cfprobe-linux-arm64",
	"windows": "cfprobe-windows-amd64.exe",
}

func loadPages() map[string]*template.Template {
	pages := map[string]*template.Template{}
	for _, name := range []string{"index", "join", "me", "admin", "message"} {
		files := []string{"templates/layout.html", "templates/" + name + ".html"}
		if name == "index" {
			files = append(files, "templates/map.html")
		}
		pages[name] = template.Must(template.New("").Funcs(templateFuncs).ParseFS(templateFS, files...))
	}
	return pages
}

func loadScripts() *texttemplate.Template {
	return texttemplate.Must(texttemplate.ParseFS(scriptFS, "scripts/*.tmpl"))
}

func (h *Hub) render(w http.ResponseWriter, r *http.Request, status int, page, title string, data map[string]any) {
	s, _ := h.currentSession(r)
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	data["Session"] = s
	data["CSRF"] = h.csrfToken(s)
	data["PublicURL"] = strings.TrimRight(h.cfg.PublicURL, "/")
	data["MinTrust"] = h.cfg.MinTrust
	data["Quorum"] = h.cfg.Quorum
	data["CSSVersion"] = cssVersion
	var buf bytes.Buffer
	if err := h.pages[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		log.Printf("render %s: %v", page, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (h *Hub) renderMessage(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	h.render(w, r, status, "message", heading, map[string]any{"Heading": heading, "Message": message})
}

// sparkline turns history medians into SVG polyline points (160x36 box), plus how often the IP set changed.
func sparkline(history []HistoryRow) (string, int) {
	if len(history) < 2 {
		return "", 0
	}
	peak, changes := 1, 0
	for i, row := range history {
		peak = max(peak, row.MedianMS)
		if i > 0 && !slices.Equal(row.IPs, history[i-1].IPs) {
			changes++
		}
	}
	var b strings.Builder
	for i, row := range history {
		x := float64(i) * 160 / float64(len(history)-1)
		y := 34 - float64(row.MedianMS)/float64(peak)*32
		fmt.Fprintf(&b, "%.1f,%.1f ", x, y)
	}
	return strings.TrimSpace(b.String()), changes
}

// GET /
func (h *Hub) handleIndex(w http.ResponseWriter, r *http.Request) {
	pools, at := h.snapshot()
	since := time.Now().Add(-48 * time.Hour).Unix()
	var cards []map[string]any
	for _, p := range pools {
		card := map[string]any{"Pool": p}
		if p.ISP != "other" {
			if history, err := h.store.History(p.ISP, p.Family, since); err == nil {
				card["Spark"], card["Changes"] = sparkline(history)
			}
		}
		cards = append(cards, card)
	}
	regions, leaders := h.regionSnapshot()
	h.render(w, r, http.StatusOK, "index", "看板", map[string]any{
		"Pools": cards, "UpdatedAt": at,
		"Map": buildMapView(regions), "Regions": regions, "RegionRows": regions.sorted(), "RegionReady": h.region.Ready(),
		"Leaders": leaders, "Now": time.Now().Unix(),
	})
}

// GET /join
func (h *Hub) handleJoin(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if s, ok := h.currentSession(r); ok {
		prefix, created, used, _ := h.store.TokenInfo(s.User.ID)
		data["TokenPrefix"], data["TokenCreated"], data["TokenUsed"] = prefix, created, used
	}
	h.render(w, r, http.StatusOK, "join", "加入", data)
}

// POST /me/token — create or replace the caller's token and show it once.
func (h *Hub) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	s, ok := h.checkPost(w, r)
	if !ok {
		return
	}
	if s.User.Banned {
		h.renderMessage(w, r, http.StatusForbidden, "无法生成 token", "你的账号已被管理员停用上报。")
		return
	}
	token, err := h.store.RotateToken(s.User.ID, unixNow())
	if err != nil {
		log.Printf("rotate token: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	h.render(w, r, http.StatusOK, "join", "你的 token", map[string]any{"NewToken": token})
}

// GET /me
func (h *Hub) handleMe(w http.ResponseWriter, r *http.Request) {
	s, ok := h.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/join", http.StatusSeeOther)
		return
	}
	reports, _ := h.store.UserReports(s.User.ID, 50)
	rows := make([]map[string]any, 0, len(reports))
	for _, report := range reports {
		rows = append(rows, map[string]any{"Report": report, "Line": h.lineName(report)})
	}
	prefix, _, _, _ := h.store.TokenInfo(s.User.ID)
	h.render(w, r, http.StatusOK, "me", "我的探针", map[string]any{"Reports": rows, "TokenPrefix": prefix})
}

// lineName labels a report's line: the operator, plus the provider for a cloud server.
func (h *Hub) lineName(report Report) string {
	name := templateFuncs["ispName"].(func(string) string)(report.ISP)
	if report.ISP == "cloud" {
		if prefix, err := netip.ParsePrefix(report.Prefix); err == nil {
			if provider := providerName(h.net.ProviderOf(prefix.Addr())); provider != "" {
				name += " · " + provider
			}
		}
	}
	return name
}

func (h *Hub) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s, ok := h.currentSession(r); ok && s.Admin {
		return true
	}
	http.NotFound(w, r) // do not advertise the admin area
	return false
}

// GET /admin
func (h *Hub) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	users, err := h.store.ListUsers(time.Now().Add(-24 * time.Hour).Unix())
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	names := map[int64]string{}
	for _, u := range users {
		names[u.ID] = u.Username
	}
	pools, _ := h.snapshot()
	published := map[poolKey]map[string]bool{}
	var poolViews []map[string]any
	for _, p := range pools {
		set := map[string]bool{}
		var voters []map[string]any
		for _, ip := range p.IPs {
			set[ip.IP] = true
			// One tag per user, with how many of their servers vouch for the IP.
			count := map[int64]int{}
			var order []int64
			for _, id := range ip.voters {
				if count[id] == 0 {
					order = append(order, id)
				}
				count[id]++
			}
			var who []string
			for _, id := range order {
				if count[id] > 1 {
					who = append(who, fmt.Sprintf("%s ×%d", names[id], count[id]))
				} else {
					who = append(who, names[id])
				}
			}
			voters = append(voters, map[string]any{"IP": ip.IP, "MedianMS": ip.MedianMS, "Users": who})
		}
		if p.Published {
			published[poolKey{p.ISP, p.Family}] = set
		}
		poolViews = append(poolViews, map[string]any{"Pool": p, "Voters": voters, "Suspended": h.store.Setting("suspended:"+p.ISP) == "1"})
	}
	// Agreement: share of the user's latest top-6 that made it into the published pool.
	agreement := map[int64]string{}
	if reports, err := h.store.ActiveReports(time.Now().Add(-h.cfg.ReportTTL).Unix()); err == nil {
		for _, report := range reports {
			if _, done := agreement[report.UserID]; done {
				continue
			}
			set, ok := published[poolKey{report.ISP, report.Family}]
			if !ok {
				agreement[report.UserID] = "—"
				continue
			}
			top, hit := min(6, len(report.IPs)), 0
			for _, ip := range report.IPs[:top] {
				if set[ip.IP] {
					hit++
				}
			}
			agreement[report.UserID] = fmt.Sprintf("%d%%", hit*100/max(top, 1))
		}
	}
	var rows []map[string]any
	for _, u := range users {
		a := agreement[u.ID]
		if a == "" {
			a = "—"
		}
		rows = append(rows, map[string]any{
			"ID": u.ID, "Username": u.Username, "TrustLevel": u.TrustLevel, "TokenPrefix": u.TokenPrefix,
			"Reports24h": u.Reports24h, "LastReport": u.LastReport, "LastISP": u.LastISP, "Agreement": a,
			"Banned": u.Banned, "BanReason": u.BanReason,
		})
	}
	h.render(w, r, http.StatusOK, "admin", "管理", map[string]any{"Pools": poolViews, "Users": rows})
}

// POST /admin/user/{id}/{action}  action = ban | unban | revoke
func (h *Hub) handleAdminUser(w http.ResponseWriter, r *http.Request) {
	s, ok := h.checkPost(w, r)
	if !ok || !s.Admin {
		if ok {
			http.NotFound(w, r)
		}
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad user id", http.StatusBadRequest)
		return
	}
	switch r.PathValue("action") {
	case "ban":
		reason := strings.TrimSpace(r.PostFormValue("reason"))
		if len(reason) > 200 {
			reason = reason[:200]
		}
		err = h.store.SetBanned(id, true, reason)
		if err == nil {
			err = h.store.RevokeTokens(id)
		}
	case "unban":
		err = h.store.SetBanned(id, false, "")
	case "revoke":
		err = h.store.RevokeTokens(id)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	log.Printf("admin %d: %s user %d", s.User.ID, r.PathValue("action"), id)
	go h.runAggregation(context.Background()) // a ban takes the user's votes out right away
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// POST /admin/isp/{isp}/{action}  action = suspend | resume
func (h *Hub) handleAdminISP(w http.ResponseWriter, r *http.Request) {
	s, ok := h.checkPost(w, r)
	if !ok || !s.Admin {
		if ok {
			http.NotFound(w, r)
		}
		return
	}
	isp, action := r.PathValue("isp"), r.PathValue("action")
	if !slices.Contains(operators, isp) || (action != "suspend" && action != "resume") {
		http.NotFound(w, r)
		return
	}
	value := "0"
	if action == "suspend" {
		value = "1"
	}
	if err := h.store.SetSetting("suspended:"+isp, value); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	log.Printf("admin %d: %s %s", s.User.ID, action, isp)
	go h.runAggregation(context.Background())
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func allowCORS(w http.ResponseWriter) { w.Header().Set("Access-Control-Allow-Origin", "*") }

// GET /api/v1/pools
func (h *Hub) handleAPIPools(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	pools, at := h.snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"updated_at": at, "quorum": h.cfg.Quorum, "pools": pools})
}

// GET /api/v1/history?isp=chinanet&family=4&hours=48
func (h *Hub) handleAPIHistory(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	q := r.URL.Query()
	isp := q.Get("isp")
	if !slices.Contains(operators, isp) {
		http.Error(w, "isp must be one of "+strings.Join(operators, ", "), http.StatusBadRequest)
		return
	}
	family := 4
	if q.Get("family") == "6" {
		family = 6
	}
	hours, err := strconv.Atoi(q.Get("hours"))
	if err != nil || hours < 1 {
		hours = 48
	}
	hours = min(hours, 30*24)
	rows, err := h.store.History(isp, family, time.Now().Add(-time.Duration(hours)*time.Hour).Unix())
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"isp": isp, "family": family, "history": rows})
}

// GET /api/v1/summary
func (h *Hub) handleAPISummary(w http.ResponseWriter, r *http.Request) {
	allowCORS(w)
	pools, at := h.snapshot()
	probers := map[string]int{}
	for _, p := range pools {
		probers[p.ISP] = max(probers[p.ISP], p.Probers)
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated_at": at, "quorum": h.cfg.Quorum, "active_probers": probers})
}

// GET /internal/isp-table — for the DoH on this host only. Caddy sets X-Real-IP on everything it
// proxies, so a request without it that comes from loopback did not come through the public site.
func (h *Hub) handleISPTable(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, err := netip.ParseAddr(host)
	if err != nil || !peer.Unmap().IsLoopback() || r.Header.Get("X-Real-IP") != "" {
		http.NotFound(w, r)
		return
	}
	text := h.net.ISPTableText()
	if text == "" {
		http.Error(w, "operator table not loaded yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, text)
}

type distEntry struct {
	modTime time.Time
	size    int64
	sum     string
}

// distSum returns the sha256 of a distributed binary, cached until the file changes.
func (h *Hub) distSum(name string) (string, error) {
	path := filepath.Join(h.cfg.DistDir, name)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	h.distMu.Lock()
	defer h.distMu.Unlock()
	if e, ok := h.distCache[name]; ok && e.modTime.Equal(info.ModTime()) && e.size == info.Size() {
		return e.sum, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(hash.Sum(nil))
	h.distCache[name] = distEntry{info.ModTime(), info.Size(), sum}
	return sum, nil
}

// GET /install.sh, /install.ps1 — the installers, with the current binaries' checksums baked in.
func (h *Hub) handleInstaller(script string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sums := map[string]string{}
		for key, name := range distFiles {
			sum, err := h.distSum(name)
			if err != nil {
				http.Error(w, "installer not available yet", http.StatusServiceUnavailable)
				return
			}
			sums[key] = sum
		}
		public := strings.TrimRight(h.cfg.PublicURL, "/")
		sources := append(slices.Clone(h.cfg.DLMirrors), public+"/dl")
		var buf bytes.Buffer
		if err := h.scripts.ExecuteTemplate(&buf, script, map[string]any{"PublicURL": public, "SHA": sums, "Sources": sources}); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buf.Bytes())
	}
}

// GET /dl/{name}
func (h *Hub) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// The signed release manifest (cmd/cfrelease) is served as is; probers verify it themselves.
	allowed := name == "manifest.json" || name == "manifest.json.sig"
	for _, file := range distFiles {
		allowed = allowed || file == name
	}
	if !allowed {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	if strings.HasPrefix(name, "manifest.") {
		w.Header().Set("Cache-Control", "no-cache") // a CDN mirror must not hold back a release
	}
	http.ServeFile(w, r, filepath.Join(h.cfg.DistDir, name))
}

// GET /healthz
func (h *Hub) handleHealth(w http.ResponseWriter, r *http.Request) {
	_, at := h.snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "net_ready": h.net.Ready(), "aggregated_at": at})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("Referrer-Policy", "same-origin")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

func (h *Hub) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.handleIndex)
	mux.HandleFunc("GET /join", h.handleJoin)
	mux.HandleFunc("GET /me", h.handleMe)
	mux.HandleFunc("POST /me/token", h.handleRotateToken)
	mux.HandleFunc("GET /login", h.handleLogin)
	mux.HandleFunc("GET /auth/callback", h.handleCallback)
	mux.HandleFunc("POST /logout", h.handleLogout)
	mux.HandleFunc("GET /admin", h.handleAdmin)
	mux.HandleFunc("POST /admin/user/{id}/{action}", h.handleAdminUser)
	mux.HandleFunc("POST /admin/isp/{isp}/{action}", h.handleAdminISP)
	mux.HandleFunc("GET /api/v1/pools", h.handleAPIPools)
	mux.HandleFunc("GET /api/v1/history", h.handleAPIHistory)
	mux.HandleFunc("GET /api/v1/summary", h.handleAPISummary)
	mux.HandleFunc("GET /api/v1/regions", h.handleAPIRegions)
	mux.HandleFunc("POST /api/v1/probe/report", h.handleReport)
	mux.HandleFunc("GET /api/v1/probe/candidates", h.handleCandidates)
	mux.HandleFunc("GET /internal/isp-table", h.handleISPTable)
	mux.HandleFunc("GET /install.sh", h.handleInstaller("install.sh.tmpl"))
	mux.HandleFunc("GET /install.ps1", h.handleInstaller("install.ps1.tmpl"))
	mux.HandleFunc("GET /dl/{name}", h.handleDownload)
	mux.HandleFunc("GET /healthz", h.handleHealth)
	static := http.FileServerFS(staticFS) // request paths are /static/<file>, matching the embedded tree
	mux.HandleFunc("GET /static/{file}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		static.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/logo.png", http.StatusMovedPermanently)
	})
	return securityHeaders(mux)
}
