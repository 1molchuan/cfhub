package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	maxReportIPs   = 64
	maxReportBody  = 64 << 10
	maxCandidates  = 64
	candidatesEach = 8 // top IPs taken from each other prober's latest report
)

// clientAddr is the caller's address. X-Real-IP is trusted only from loopback, i.e. from our own
// Caddy, which overwrites it with the TCP peer (header_up X-Real-IP {remote_host}); a direct
// connection's own header is ignored, so a reporter cannot claim another network.
func clientAddr(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}
	peer = peer.Unmap()
	if peer.IsLoopback() {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Real-IP")); forwarded != "" {
			if addr, err := netip.ParseAddr(forwarded); err == nil {
				return addr.Unmap(), nil
			}
		}
	}
	return peer, nil
}

// networkPrefix is the reporter's /24 (IPv6 /48): the unit of "one line, one vote".
func networkPrefix(addr netip.Addr) string {
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	prefix, _ := addr.Prefix(bits)
	return prefix.String()
}

func (h *Hub) probeUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	auth := r.Header.Get("Authorization")
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if !strings.HasPrefix(auth, "Bearer ") || token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return User{}, false
	}
	u, err := h.store.UserForToken(token, unixNow())
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return User{}, false
	}
	if u.Banned {
		http.Error(w, "this account is banned from reporting", http.StatusForbidden)
		return User{}, false
	}
	return u, true
}

type reportRequest struct {
	Family  int        `json:"family"`
	IPs     []ReportIP `json:"ips"`
	Version string     `json:"version"`
}

// validateReport keeps well-formed Cloudflare addresses of the reported family, in order, deduplicated.
// Anything else is dropped and counted, not fatal: candidate domains can resolve to non-Cloudflare
// reverse proxies, and a prober should not lose a whole run over one of them.
func (h *Hub) validateReport(req reportRequest) ([]ReportIP, int, error) {
	if req.Family != 4 && req.Family != 6 {
		return nil, 0, errors.New("family must be 4 or 6")
	}
	if len(req.IPs) > maxReportIPs {
		return nil, 0, fmt.Errorf("at most %d addresses per report", maxReportIPs)
	}
	var kept []ReportIP
	seen := map[netip.Addr]bool{}
	dropped := 0
	for _, item := range req.IPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(item.IP))
		if err != nil || addr.Zone() != "" {
			dropped++
			continue
		}
		addr = addr.Unmap()
		if (req.Family == 4) != addr.Is4() || seen[addr] || !h.net.IsCloudflare(addr) {
			dropped++
			continue
		}
		if item.Rounds < 1 || item.Rounds > 50 || item.OK < 0 || item.OK > item.Rounds || item.MedianMS < 0 || item.MedianMS > 60000 {
			dropped++
			continue
		}
		seen[addr] = true
		kept = append(kept, ReportIP{IP: addr.String(), MedianMS: item.MedianMS, OK: item.OK, Rounds: item.Rounds})
	}
	if len(kept) == 0 {
		return nil, dropped, errors.New("no usable Cloudflare addresses in the report")
	}
	return kept, dropped, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// POST /api/v1/probe/report
func (h *Hub) handleReport(w http.ResponseWriter, r *http.Request) {
	u, ok := h.probeUser(w, r)
	if !ok {
		return
	}
	if !h.net.Ready() {
		http.Error(w, "hub is starting (network data not loaded yet)", http.StatusServiceUnavailable)
		return
	}
	var req reportRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxReportBody)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	addr, err := clientAddr(r)
	if err != nil {
		http.Error(w, "cannot determine your address", http.StatusBadRequest)
		return
	}
	now := unixNow()
	// Limited per prober (user + line), so one person's several servers do not crowd each other out.
	prefix := networkPrefix(addr)
	if last, err := h.store.LastReportAt(u.ID, prefix, req.Family); err == nil && last > 0 {
		if wait := h.cfg.ReportInterval - time.Duration(now-last)*time.Second; wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			http.Error(w, "reporting too often", http.StatusTooManyRequests)
			return
		}
	}
	ips, dropped, err := h.validateReport(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	isp := h.net.ISPOf(addr)
	if isp == "" {
		isp = "other"
	}
	version := req.Version
	if len(version) > 32 {
		version = version[:32]
	}
	report := Report{UserID: u.ID, At: now, Prefix: prefix, ISP: isp, Family: req.Family, IPs: ips, Dropped: dropped, Version: version}
	if err := h.store.InsertReport(report); err != nil {
		log.Printf("report: %v", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	reply := map[string]any{"ok": true, "isp": isp, "name": operatorNames[isp], "accepted": len(ips), "dropped": dropped}
	if provider := h.net.ProviderOf(addr); provider != "" {
		reply["provider"], reply["name"] = provider, operatorNames[isp]+" · "+providerName(provider)
	}
	writeJSON(w, http.StatusOK, reply)
}

// GET /api/v1/probe/candidates?family=4 — addresses to re-test besides the prober's own sample: its
// operator's current pool plus the top of other probers' recent reports on the same operator. This is
// what lets independent probers converge on common IPs (a majority needs overlapping lists).
func (h *Hub) handleCandidates(w http.ResponseWriter, r *http.Request) {
	u, ok := h.probeUser(w, r)
	if !ok {
		return
	}
	family := 4
	if r.URL.Query().Get("family") == "6" {
		family = 6
	}
	addr, err := clientAddr(r)
	if err != nil {
		http.Error(w, "cannot determine your address", http.StatusBadRequest)
		return
	}
	isp := h.net.ISPOf(addr)
	if isp == "" {
		isp = "other"
	}
	var out []string
	seen := map[string]bool{}
	add := func(ip string) {
		if len(out) < maxCandidates && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	if pool := h.pool(isp, family); pool != nil {
		for _, ip := range pool.IPs {
			add(ip.IP)
		}
	}
	if reports, err := h.store.ActiveReports(time.Now().Add(-h.cfg.ReportTTL).Unix()); err == nil {
		// One list per other prober (line), not this caller's own line; other users' probers first,
		// since only IPs that several people find can make the pool.
		used := map[string]bool{networkPrefix(addr): true}
		for _, own := range []bool{false, true} {
			for _, report := range reports {
				if report.ISP != isp || report.Family != family || used[report.Prefix] || (report.UserID == u.ID) != own {
					continue
				}
				used[report.Prefix] = true
				for i, ip := range report.IPs {
					if i >= candidatesEach {
						break
					}
					add(ip.IP)
				}
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"isp": isp, "name": operatorNames[isp], "family": family, "ips": out})
}
