package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The report must use exactly the field names cfhub reads (work/cfhub reportRequest / ReportIP).
func TestHubReportBodyMatchesCfhub(t *testing.T) {
	body := hubReportBody([]rankedIP{{IP: "104.16.1.1", Median: 180, Rounds: 6}, {IP: "104.16.2.1", Median: 190, Rounds: 6}}, 4)
	var got struct {
		Family int `json:"family"`
		IPs    []struct {
			IP       string `json:"ip"`
			MedianMS int    `json:"median_ms"`
			OK       int    `json:"ok"`
			Rounds   int    `json:"rounds"`
		} `json:"ips"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Family != 4 || len(got.IPs) != 2 || got.IPs[0].IP != "104.16.1.1" || got.IPs[0].MedianMS != 180 || got.IPs[0].OK != 6 || got.IPs[0].Rounds != 6 || got.Version != probeVersion {
		t.Fatalf("report body %s", body)
	}
}

func TestHubClientSendsTokenAndReadsCandidates(t *testing.T) {
	var reported []byte
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cfp_test" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/probe/candidates":
			if r.URL.Query().Get("family") != "6" {
				http.Error(w, "family", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"isp": "chinanet", "name": "电信", "ips": []string{"2606:4700::1"}})
		case "/api/v1/probe/report":
			reported = make([]byte, r.ContentLength)
			_, _ = r.Body.Read(reported)
			http.Error(w, "reporting too often", http.StatusTooManyRequests)
		}
	}))
	defer hub.Close()

	got, err := fetchHubCandidates(plainRoutes([]string{hub.URL}), "cfp_test", 6)
	if err != nil || got.ISP != "chinanet" || !reflect.DeepEqual(got.IPs, []string{"2606:4700::1"}) {
		t.Fatalf("candidates %+v, %v", got, err)
	}
	if _, err := fetchHubCandidates(plainRoutes([]string{hub.URL}), "cfp_wrong", 6); err == nil {
		t.Fatal("a refused token must be an error")
	}
	status, _, err := postHubReport(plainRoutes([]string{hub.URL}), "cfp_test", []byte(`{"family":4}`))
	if err != nil || status != http.StatusTooManyRequests || string(reported) != `{"family":4}` {
		t.Fatalf("post: %d %v, sent %q", status, err, reported)
	}
}

// Reports try the signed manifest's routes first: an unreachable route is skipped, but an HTTP
// answer (even a refusal) is final, so a report is never sent twice through two routes.
func TestHubAPIRoutesFallBackOnlyOnTransportFailure(t *testing.T) {
	var hits []string
	serve := func(name string, status int) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits = append(hits, name)
			w.WriteHeader(status)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close() // connection refused
	edge, hub := serve("edge", http.StatusTooManyRequests), serve("hub", http.StatusOK)

	// httptest serves plain http; apiBases keeps https routes only, so test the fallback on a list
	// built by hand and the filtering separately.
	status, _, err := postHubReport(plainRoutes([]string{dead.URL, edge.URL, hub.URL}), "cfp_test", []byte(`{}`))
	if err != nil || status != http.StatusTooManyRequests || !reflect.DeepEqual(hits, []string{"edge"}) {
		t.Fatalf("status %d err %v hits %v; want the edge's 429 and no second delivery", status, err, hits)
	}
	m := releaseManifest{API: []string{"https://edge.example/", "http://plain.example", "https://hub.example"}}
	if got, want := apiBases(m, "https://hub.example"), []string{"https://edge.example", "https://hub.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes %v, want %v (https only, the hub once and last)", got, want)
	}
	if got := apiBases(releaseManifest{}, "https://hub.example"); !reflect.DeepEqual(got, []string{"https://hub.example"}) {
		t.Fatalf("without routes: %v, want the hub only", got)
	}
}

// An IPv6 route dials the measured Cloudflare address over IPv6 whatever the URL's name resolves to,
// and keeps only IPv6 addresses (at most maxPinnedIPv6, best first).
func TestIPv6RouteDialsThePinnedAddress(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	var seen string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.RemoteAddr
		w.WriteHeader(http.StatusTeapot)
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if conn, err := net.Dial("tcp6", ln.Addr().String()); err != nil {
		t.Skip("IPv6 loopback not reachable here:", err) // some Windows setups refuse it
	} else {
		conn.Close()
	}

	routes := ipv6Routes([]string{"http://api6.invalid:" + port}, []string{"104.16.1.1", "::1", "2606:4700::2", "2606:4700::3"})
	if len(routes) != 2 || routes[0].via != "::1" || routes[1].via != "2606:4700::2" {
		t.Fatalf("routes %v; want ::1 then 2606:4700::2 (IPv6 only, two at most)", routes)
	}
	status, _, err := postHubReport(routes[:1], "cfp_test", []byte(`{}`))
	if err != nil || status != http.StatusTeapot || !strings.HasPrefix(seen, "[::1]:") {
		t.Fatalf("status %d err %v from %q; want the pinned [::1]", status, err, seen)
	}
	if got := ipv6Routes(nil, []string{"::1"}); len(got) != 0 {
		t.Fatalf("no api6 bases: %v, want no routes", got)
	}
	if got := ipv6Routes([]string{"https://api6.example"}, nil); len(got) != 1 || got[0].via != "" {
		t.Fatalf("no measured address: %v, want the name dialed over IPv6", got)
	}
}

// A report that reaches no route is retried after the backoff (a line's NAT can refuse new
// connections for a while right after a run), and stops once any route answers.
func TestHubReportRetriesUntilARouteAnswers(t *testing.T) {
	saved := reportBackoff
	reportBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { reportBackoff = saved })
	var calls atomic.Int32
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 { // the first two attempts: the connection dies without an answer
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(hub.Close)
	status, _, err := sendHubReport(plainRoutes([]string{hub.URL}), "cfp_test", []byte(`{}`))
	if err != nil || status != http.StatusOK || calls.Load() != 3 {
		t.Fatalf("status %d err %v after %d calls; want 200 on the third", status, err, calls.Load())
	}

	// Every attempt failing: 1 + len(reportBackoff) tries, then the error.
	calls.Store(-100)
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	t.Cleanup(dead.Close)
	if _, _, err := sendHubReport(plainRoutes([]string{dead.URL}), "cfp_test", []byte(`{}`)); err == nil || calls.Load() != -100+4 {
		t.Fatalf("err %v after %d calls; want an error after 4 attempts", err, calls.Load()+100)
	}
	// Any HTTP answer is final, even a refusal: never retried.
	calls.Store(0)
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	t.Cleanup(refuse.Close)
	if status, _, err := sendHubReport(plainRoutes([]string{refuse.URL}), "cfp_test", []byte(`{}`)); err != nil || status != http.StatusTooManyRequests || calls.Load() != 1 {
		t.Fatalf("status %d err %v after %d calls; want one 429", status, err, calls.Load())
	}
}
