package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// h3Check measures QUIC+ECH for each host against exactly what the DoH server hands out (its A
// records and ECH config) and reports a verdict per host to /admin/h3. The server advertises h3 in
// a host's HTTPS record only while every prober's verdict is positive. Only ECH handshakes are made
// (no plaintext control), so the probing itself cannot trigger the GFW's residual blocking.
// A run passes a host when at most one in ten handshakes fails; testing stops early once that is
// lost. Verdicts are asymmetric because Chromium, once QUIC has worked for a host, prefers it and
// stalls when it later black-holes: a failed run reports false at once, but true is reported only
// after h3HistoryRuns consecutive passing runs (kept in historyPath). A host passing but not yet
// proven gets no verdict, so the server's default applies.
const h3HistoryRuns = 3

func h3Check(doh string, hosts []string, rounds int, timeout time.Duration, reportURL, token, source string, ttl int, historyPath string) {
	history := map[string][]bool{}
	if historyPath != "" {
		if b, err := os.ReadFile(historyPath); err == nil {
			_ = json.Unmarshal(b, &history)
		}
	}
	verdicts := map[string]bool{}
	allowedFails := rounds / 10
	for _, host := range hosts {
		ech, _, _, err := queryHTTPS(doh, host)
		if err != nil || len(ech) == 0 {
			fmt.Printf("skip  %-24s no ECH config from the DoH server (%v)\n", host, err)
			continue
		}
		ips, err := queryA(doh, host)
		if err != nil || len(ips) == 0 {
			fmt.Printf("skip  %-24s no addresses from the DoH server (%v)\n", host, err)
			continue
		}
		if len(ips) > 3 {
			ips = ips[:3]
		}
		ok, fails := 0, 0
		var lat []int64
		var lastErr string
		for i := 0; i < rounds && fails <= allowedFails; i++ {
			a := handshakeQUIC(ips[i%len(ips)], host, ech, timeout)
			if a.Handshake && a.ECHAccepted {
				ok++
				lat = append(lat, a.Millis)
				continue
			}
			fails++
			lastErr = a.Error
			if a.Handshake {
				lastErr = "handshake without ECH"
			}
		}
		passed := fails <= allowedFails
		runs := append(history[host], passed)
		if len(runs) > h3HistoryRuns {
			runs = runs[len(runs)-h3HistoryRuns:]
		}
		history[host] = runs
		label := h3Decide(runs)
		switch label {
		case "h3":
			verdicts[host] = true
		case "h2":
			verdicts[host] = false
		}
		median := int64(0)
		if len(lat) > 0 {
			sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
			median = lat[len(lat)/2]
		}
		detail := ""
		if lastErr != "" {
			detail = "; last error: " + lastErr
		}
		fmt.Printf("%-5s %-24s QUIC+ECH %d/%d ok, median %dms, recent runs %v%s\n", label, host, ok, ok+fails, median, runs, detail)
	}
	if historyPath != "" {
		if b, err := json.Marshal(history); err == nil {
			if err := os.WriteFile(historyPath, b, 0o600); err != nil {
				fmt.Fprintln(os.Stderr, "h3 history save failed:", err)
			}
		}
	}
	if len(verdicts) == 0 {
		fmt.Println("no host has a settled verdict yet; not reporting")
		return
	}
	if reportURL != "" {
		body, _ := json.Marshal(map[string]any{"source": source, "ttl": ttl, "verdicts": verdicts})
		dohTransport.CloseIdleConnections()
		if status, err := postReport(reportURL, token, body); err != nil || status != http.StatusOK {
			fmt.Fprintln(os.Stderr, "h3 report failed:", err, status)
			os.Exit(4)
		}
	}
}

// h3Decide maps a host's recent run results (oldest first) to "h3", "h2", or "wait" (no verdict).
func h3Decide(runs []bool) string {
	if len(runs) == 0 || !runs[len(runs)-1] {
		return "h2"
	}
	if len(runs) < h3HistoryRuns {
		return "wait"
	}
	for _, passed := range runs[len(runs)-h3HistoryRuns:] {
		if !passed {
			return "wait"
		}
	}
	return "h3"
}

// fetchH3Verdicts reads the server's effective QUIC+ECH verdicts (GET /admin/h3) so the self-check
// judges h3 advertisements against measurements rather than a fixed list.
func fetchH3Verdicts(adminURL, token string) (map[string]bool, error) {
	u, err := url.Parse(adminURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/admin/h3"
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		H3 struct {
			Effective map[string]bool `json:"effective"`
		} `json:"h3"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.H3.Effective, nil
}

// h3Forbidden: the most specific measured verdict covering host decides; without one, the static
// suffix list does (hosts known to fail QUIC+ECH).
func h3Forbidden(host string, measured map[string]bool, static []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	best := ""
	for h := range measured {
		if (host == h || strings.HasSuffix(host, "."+h)) && len(h) > len(best) {
			best = h
		}
	}
	if best != "" {
		return !measured[best]
	}
	return hasSuffix(host, static)
}
