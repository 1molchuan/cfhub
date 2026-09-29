package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type testEnv struct {
	hub    *Hub
	server *httptest.Server
	doh    *httptest.Server
	pushed []map[string]any
	mu     sync.Mutex
}

func newTestEnv(t *testing.T, linuxdo string) *testEnv {
	t.Helper()
	te := &testEnv{}
	te.doh = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hub-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		te.mu.Lock()
		te.pushed = append(te.pushed, body)
		te.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}))
	t.Cleanup(te.doh.Close)
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	nd := newNetData(dir, "", nil)
	if err := nd.setISP("chinanet 58.247.0.0/16\ncernet 58.247.22.0/24\ncmcc 120.192.0.0/10\n"); err != nil {
		t.Fatal(err)
	}
	if err := nd.setCF("104.16.0.0/13\n172.64.0.0/13\n2606:4700::/32\n"); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PublicURL: "https://cfhub.example", DistDir: filepath.Join(dir, "dist"),
		ClientID: "cid", ClientSecret: "csecret",
		AuthorizeURL: linuxdo + "/oauth2/authorize", TokenURL: linuxdo + "/oauth2/token", UserURL: linuxdo + "/api/user",
		SessionKey: []byte(strings.Repeat("k", 32)), Admins: map[int64]bool{1: true}, MinTrust: 1,
		DoHURL: te.doh.URL, HubToken: "hub-secret",
		Quorum: 2, PoolSize: 6, PushTTL: 1800,
		ReportTTL: 150 * time.Minute, ReportInterval: 20 * time.Minute, AggregateEvery: 5 * time.Minute,
	}
	te.hub = newHub(cfg, store, nd)
	te.server = httptest.NewServer(te.hub.routes())
	t.Cleanup(te.server.Close)
	return te
}

func (te *testEnv) user(t *testing.T, id int64, name string) string {
	t.Helper()
	if _, err := te.hub.store.UpsertUser(User{ID: id, Username: name, TrustLevel: 2}, unixNow()); err != nil {
		t.Fatal(err)
	}
	token, err := te.hub.store.RotateToken(id, unixNow())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// do sends a request as if it came through Caddy from `from` (the test client always connects from loopback).
func (te *testEnv) do(t *testing.T, method, path, token, from string, body any, extra ...[2]string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest(method, te.server.URL+path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if from != "" {
		req.Header.Set("X-Real-IP", from)
	}
	for _, kv := range extra {
		req.Header.Set(kv[0], kv[1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func report(ips ...string) map[string]any {
	list := []map[string]any{}
	for i, ip := range ips {
		list = append(list, map[string]any{"ip": ip, "median_ms": 100 + i, "ok": 6, "rounds": 6})
	}
	return map[string]any{"family": 4, "ips": list, "version": "test"}
}

func TestReportIsTaggedFilteredAndRateLimited(t *testing.T) {
	te := newTestEnv(t, "")
	token := te.user(t, 10, "alice")
	resp := te.do(t, "POST", "/api/v1/probe/report", token, "58.247.1.9", report("104.16.1.1", "203.0.113.9", "104.16.1.1", "not-an-ip"))
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("report: %d %s", resp.StatusCode, b)
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["isp"] != "chinanet" || got["accepted"] != float64(1) || got["dropped"] != float64(3) {
		t.Fatalf("unexpected reply %v (want chinanet, 1 accepted, 3 dropped: non-Cloudflare, duplicate, malformed)", got)
	}
	stored, _ := te.hub.store.UserReports(10, 5)
	if len(stored) != 1 || stored[0].Prefix != "58.247.1.0/24" {
		t.Fatalf("stored %+v; want only the /24, never the full address", stored)
	}
	if resp := te.do(t, "POST", "/api/v1/probe/report", token, "58.247.1.9", report("104.16.1.2")); resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second report within the interval: %d, want 429 with Retry-After", resp.StatusCode)
	}
}

func TestReportRejectsBadTokensBannedUsersAndNonCloudflareOnly(t *testing.T) {
	te := newTestEnv(t, "")
	token := te.user(t, 11, "bob")
	if resp := te.do(t, "POST", "/api/v1/probe/report", "cfp_wrong", "58.247.1.9", report("104.16.1.1")); resp.StatusCode != 401 {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	if resp := te.do(t, "POST", "/api/v1/probe/report", token, "58.247.1.9", report("203.0.113.9", "8.8.8.8")); resp.StatusCode != 400 {
		t.Fatalf("report with no Cloudflare address: %d, want 400", resp.StatusCode)
	}
	_ = te.hub.store.SetBanned(11, true, "test")
	if resp := te.do(t, "POST", "/api/v1/probe/report", token, "58.247.1.9", report("104.16.1.1")); resp.StatusCode != 403 {
		t.Fatalf("banned user: %d, want 403", resp.StatusCode)
	}
}

func TestClientAddrTrustsXRealIPOnlyFromLoopback(t *testing.T) {
	spoofed := httptest.NewRequest("POST", "/", nil)
	spoofed.RemoteAddr = "203.0.113.5:4444"
	spoofed.Header.Set("X-Real-IP", "58.247.1.9")
	if addr, _ := clientAddr(spoofed); addr.String() != "203.0.113.5" {
		t.Fatalf("a direct client claimed %s via X-Real-IP", addr)
	}
	viaCaddy := httptest.NewRequest("POST", "/", nil)
	viaCaddy.RemoteAddr = "127.0.0.1:5555"
	viaCaddy.Header.Set("X-Real-IP", "58.247.1.9")
	if addr, _ := clientAddr(viaCaddy); addr.String() != "58.247.1.9" {
		t.Fatalf("Caddy's X-Real-IP ignored: %s", addr)
	}
}

func TestQuorumOneVotePerUserAndPerLineThenPush(t *testing.T) {
	te := newTestEnv(t, "")
	alice, bob, carol := te.user(t, 20, "alice"), te.user(t, 21, "bob"), te.user(t, 22, "carol")
	// Alice alone: below quorum, nothing pushed.
	te.do(t, "POST", "/api/v1/probe/report", alice, "58.247.1.9", report("104.16.1.1", "104.16.2.1", "104.16.3.1"))
	te.hub.runAggregation(context.Background())
	if p := te.hub.pool("chinanet", 4); p == nil || p.Published || len(te.pushed) != 0 {
		t.Fatalf("one prober must not publish: %+v, pushed %v", p, te.pushed)
	}
	// Carol on Alice's /24: same line, still one vote (the line's newest report, Carol's, is its vote).
	te.do(t, "POST", "/api/v1/probe/report", carol, "58.247.1.77", report("104.16.2.1", "104.16.1.1", "104.16.8.8"))
	te.hub.runAggregation(context.Background())
	if p := te.hub.pool("chinanet", 4); p.Published || p.Probers != 1 {
		t.Fatalf("two accounts on one /24 counted as %d probers, published=%v", p.Probers, p.Published)
	}
	// Bob on another telecom /24 agrees on two IPs: published, pushed to the DoH as isp:chinanet.
	te.do(t, "POST", "/api/v1/probe/report", bob, "58.247.200.3", report("104.16.2.1", "104.16.1.1", "104.16.7.7"))
	te.hub.runAggregation(context.Background())
	p := te.hub.pool("chinanet", 4)
	if !p.Published || p.Probers != 2 || !reflect.DeepEqual(p.addresses(), []string{"104.16.2.1", "104.16.1.1"}) {
		t.Fatalf("pool %+v, want published [104.16.2.1 104.16.1.1] from 2 probers", p)
	}
	if len(te.pushed) != 1 || te.pushed[0]["scope"] != "isp:chinanet" || te.pushed[0]["ttl"] != float64(1800) {
		t.Fatalf("pushed %v", te.pushed)
	}
	if got := te.pushed[0]["ipv4"]; !reflect.DeepEqual(got, []any{"104.16.2.1", "104.16.1.1"}) {
		t.Fatalf("pushed ipv4 %v", got)
	}
	// A ban takes the user's vote out: back below quorum, nothing more pushed.
	_ = te.hub.store.SetBanned(21, true, "")
	te.hub.runAggregation(context.Background())
	if te.hub.pool("chinanet", 4).Published || len(te.pushed) != 1 {
		t.Fatal("a banned user's report still counted")
	}
}

func TestAggregateLeavesOtherAndSuspendedUnpublished(t *testing.T) {
	r := func(user int64, prefix, isp string, ips ...string) Report {
		list := []ReportIP{}
		for _, ip := range ips {
			list = append(list, ReportIP{IP: ip, MedianMS: 100, OK: 6, Rounds: 6})
		}
		return Report{UserID: user, Prefix: prefix, ISP: isp, Family: 4, IPs: list}
	}
	reports := []Report{
		r(1, "1.1.1.0/24", "other", "104.16.1.1"), r(2, "2.2.2.0/24", "other", "104.16.1.1"),
		r(3, "3.3.3.0/24", "cmcc", "104.16.1.1", "104.16.2.1"), r(4, "4.4.4.0/24", "cmcc", "104.16.1.1", "104.16.2.1"),
	}
	pools := aggregate(reports, 2, 6, map[string]bool{"cmcc": true})
	if pools[poolKey{"other", 4}].Published || pools[poolKey{"cmcc", 4}].Published {
		t.Fatal("'other' and a suspended operator must never be published")
	}
	if pools := aggregate(reports, 2, 6, nil); !pools[poolKey{"cmcc", 4}].Published {
		t.Fatal("cmcc with quorum should publish when not suspended")
	}
}

func TestOneUserWithSeveralServers(t *testing.T) {
	te := newTestEnv(t, "")
	alice, bob := te.user(t, 40, "alice"), te.user(t, 41, "bob")
	// Two of Alice's servers on different telecom /24s: both accepted (the limit is per server)...
	for _, from := range []string{"58.247.1.9", "58.247.2.9"} {
		if resp := te.do(t, "POST", "/api/v1/probe/report", alice, from, report("104.16.1.1", "104.16.2.1", "104.16.3.1")); resp.StatusCode != 200 {
			t.Fatalf("alice's server %s: %d, want 200", from, resp.StatusCode)
		}
	}
	te.hub.runAggregation(context.Background())
	// ...and both vote, but one person alone publishes nothing.
	if p := te.hub.pool("chinanet", 4); p.Published || p.Probers != 2 || p.Users != 1 {
		t.Fatalf("one user's two servers: %+v, want 2 probers, 1 user, unpublished", p)
	}
	// Bob agrees on two of Alice's three IPs. 104.16.3.1 has a majority (Alice's two servers) but no
	// second person behind it, so it stays out.
	te.do(t, "POST", "/api/v1/probe/report", bob, "58.247.200.3", report("104.16.1.1", "104.16.2.1", "104.16.9.9"))
	te.hub.runAggregation(context.Background())
	p := te.hub.pool("chinanet", 4)
	if !p.Published || p.Probers != 3 || p.Users != 2 || !reflect.DeepEqual(p.addresses(), []string{"104.16.1.1", "104.16.2.1"}) {
		t.Fatalf("pool %+v, want [104.16.1.1 104.16.2.1] from 3 probers of 2 users", p)
	}
	if p.IPs[0].Votes != 3 || p.IPs[0].Users != 2 {
		t.Fatalf("first IP %+v, want 3 votes from 2 users", p.IPs[0])
	}
}

func TestOneUserCountsAtMostFiveServersPerPool(t *testing.T) {
	var reports []Report
	for i := range 7 {
		reports = append(reports, Report{UserID: 1, Prefix: fmt.Sprintf("58.247.%d.0/24", i), ISP: "chinanet", Family: 4, IPs: []ReportIP{{IP: "104.16.1.1", Rounds: 6, OK: 6}}})
	}
	if p := aggregate(reports, 2, 6, nil)[poolKey{"chinanet", 4}]; p.Probers != maxProbersPerUser {
		t.Fatalf("one user's 7 servers counted as %d probers, want %d", p.Probers, maxProbersPerUser)
	}
}

func TestCloudServersFormTheirOwnCategory(t *testing.T) {
	te := newTestEnv(t, "")
	if err := te.hub.net.setCloud("aliyun 47.100.0.0/16\ntencent 43.128.0.0/16\n"); err != nil {
		t.Fatal(err)
	}
	alice, bob := te.user(t, 50, "alice"), te.user(t, 51, "bob")
	resp := te.do(t, "POST", "/api/v1/probe/report", alice, "47.100.1.9", report("104.16.1.1", "104.16.2.1"))
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["isp"] != "cloud" || got["provider"] != "aliyun" || got["name"] != "国内云厂商 · 阿里云" {
		t.Fatalf("aliyun server reported as %v", got)
	}
	// A Tencent server of another user: same "cloud" pool, published and pushed as isp:cloud.
	te.do(t, "POST", "/api/v1/probe/report", bob, "43.128.5.5", report("104.16.2.1", "104.16.1.1"))
	te.hub.runAggregation(context.Background())
	if p := te.hub.pool("cloud", 4); p == nil || !p.Published {
		t.Fatalf("cloud pool %+v, want published", p)
	}
	if len(te.pushed) != 1 || te.pushed[0]["scope"] != "isp:cloud" {
		t.Fatalf("pushed %v, want isp:cloud", te.pushed)
	}
	// The DoH learns the cloud ranges as "cloud", ahead of the carriers, from the same table.
	if text := te.hub.net.ISPTableText(); !strings.Contains(text, "cloud 47.100.0.0/16\n") || strings.Index(text, "cloud ") > strings.Index(text, "chinanet ") {
		t.Fatalf("served table does not list the cloud ranges first as \"cloud\":\n%s", text)
	}
}

func TestCloudRangesRefreshFromRIPEstatAndKeepTheLastGoodCopy(t *testing.T) {
	failing := false
	ripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asn := strings.TrimPrefix(r.URL.Query().Get("resource"), "AS")
		if failing && asn == "45090" {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"prefixes": []map[string]string{
			{"prefix": "10." + asn[len(asn)-2:] + ".0.0/16"}, {"prefix": "2400:" + asn[len(asn)-2:] + "::/32"},
		}}})
	}))
	t.Cleanup(ripe.Close)
	nd := newNetData(t.TempDir(), "", nil)
	nd.asnURL = ripe.URL + "/?resource=AS%d"
	if err := nd.setISP("chinanet 58.247.0.0/16\n"); err != nil {
		t.Fatal(err)
	}
	if err := nd.refreshCloud(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Alibaba is AS37963, Tencent AS45090: "10.63.x" and "10.90.x" in this fake.
	if nd.ISPOf(netip.MustParseAddr("10.63.1.1")) != "cloud" || nd.ProviderOf(netip.MustParseAddr("10.90.1.1")) != "tencent" || nd.ISPOf(netip.MustParseAddr("58.247.1.1")) != "chinanet" {
		t.Fatal("cloud or carrier ranges misclassified after refresh")
	}
	failing = true
	if err := nd.refreshCloud(context.Background()); err == nil {
		t.Fatal("a failed ASN must fail the refresh")
	}
	if nd.ProviderOf(netip.MustParseAddr("10.90.1.1")) != "tencent" {
		t.Fatal("a failed refresh dropped the previous cloud table")
	}
	reloaded := newNetData(nd.dir, "", nil)
	reloaded.Load()
	if reloaded.ProviderOf(netip.MustParseAddr("10.63.1.1")) != "aliyun" {
		t.Fatal("the cloud table is not kept on disk")
	}
}

func TestCandidatesShareOtherProbersButNotYourOwn(t *testing.T) {
	te := newTestEnv(t, "")
	alice, bob := te.user(t, 30, "alice"), te.user(t, 31, "bob")
	te.do(t, "POST", "/api/v1/probe/report", alice, "58.247.1.9", report("104.16.1.1"))
	te.do(t, "POST", "/api/v1/probe/report", bob, "58.247.9.9", report("104.16.5.5"))
	resp := te.do(t, "GET", "/api/v1/probe/candidates?family=4", alice, "58.247.1.9", nil)
	var got struct {
		ISP string   `json:"isp"`
		IPs []string `json:"ips"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.ISP != "chinanet" || !reflect.DeepEqual(got.IPs, []string{"104.16.5.5"}) {
		t.Fatalf("candidates %+v, want bob's IP only", got)
	}
}

func fakeLinuxdo(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			id, secret, ok := r.BasicAuth()
			_ = r.ParseForm()
			if !ok || id != "cid" || secret != "csecret" || r.PostFormValue("code_verifier") == "" || r.PostFormValue("redirect_uri") != "https://cfhub.example/auth/callback" {
				writeJSON(w, 401, map[string]any{"error": "invalid_client"})
				return
			}
			writeJSON(w, 200, map[string]any{"access_token": "at-" + r.PostFormValue("code")})
		case "/api/user":
			tl := 2
			if r.Header.Get("Authorization") == "Bearer at-tl0" {
				tl = 0
			}
			writeJSON(w, 200, map[string]any{"id": 42, "username": "neo", "name": "Neo", "trust_level": tl, "active": true, "silenced": false})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cookieFrom(resp *http.Response, name string) string {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestLinuxdoLoginWithStateAndPKCE(t *testing.T) {
	ld := fakeLinuxdo(t)
	te := newTestEnv(t, ld.URL)
	login := te.do(t, "GET", "/login", "", "", nil)
	loc, _ := url.Parse(login.Header.Get("Location"))
	q := loc.Query()
	if login.StatusCode != 302 || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("redirect_uri") != "https://cfhub.example/auth/callback" {
		t.Fatalf("login redirect %d %s", login.StatusCode, loc)
	}
	oauth := cookieFrom(login, oauthCookie)
	callback := func(code, state string) *http.Response {
		return te.do(t, "GET", "/auth/callback?code="+code+"&state="+url.QueryEscape(state), "", "", nil, [2]string{"Cookie", oauthCookie + "=" + oauth})
	}
	if resp := callback("good", "forged-state"); resp.StatusCode != 400 {
		t.Fatalf("state mismatch accepted: %d", resp.StatusCode)
	}
	resp := callback("good", q.Get("state"))
	if resp.StatusCode != 303 || cookieFrom(resp, sessionCookie) == "" {
		t.Fatalf("callback %d, session cookie %q", resp.StatusCode, cookieFrom(resp, sessionCookie))
	}
	if u, err := te.hub.store.GetUser(42); err != nil || u.Username != "neo" || u.TrustLevel != 2 {
		t.Fatalf("user not stored: %+v %v", u, err)
	}
	if resp := callback("tl0", q.Get("state")); resp.StatusCode != 403 {
		t.Fatalf("trust level 0 let in: %d", resp.StatusCode)
	}
}

func TestAdminIsHiddenAndFormsNeedCSRF(t *testing.T) {
	te := newTestEnv(t, "")
	te.user(t, 1, "admin")
	victim := te.user(t, 50, "mallory")
	session := func(id int64) (string, string) {
		raw := te.hub.signedValue("session", time.Hour, strconv.FormatInt(id, 10))
		return sessionCookie + "=" + raw, te.hub.csrfToken(session{Raw: raw})
	}
	userCookie, _ := session(50)
	if resp := te.do(t, "GET", "/admin", "", "", nil, [2]string{"Cookie", userCookie}); resp.StatusCode != 404 {
		t.Fatalf("non-admin sees /admin: %d", resp.StatusCode)
	}
	adminCookie, csrf := session(1)
	if resp := te.do(t, "GET", "/admin", "", "", nil, [2]string{"Cookie", adminCookie}); resp.StatusCode != 200 {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}
	form := func(token string) *http.Response {
		req, _ := http.NewRequest("POST", te.server.URL+"/admin/user/50/ban", strings.NewReader(url.Values{"csrf": {token}, "reason": {"spam"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", adminCookie)
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if resp := form("wrong"); resp.StatusCode != 403 {
		t.Fatalf("ban without a valid CSRF token: %d", resp.StatusCode)
	}
	if resp := form(csrf); resp.StatusCode != 303 {
		t.Fatalf("ban: %d", resp.StatusCode)
	}
	if u, _ := te.hub.store.GetUser(50); !u.Banned || u.BanReason != "spam" {
		t.Fatalf("user not banned: %+v", u)
	}
	if resp := te.do(t, "POST", "/api/v1/probe/report", victim, "58.247.1.9", report("104.16.1.1")); resp.StatusCode != 401 {
		t.Fatalf("a banned user's token still works: %d (ban must revoke it)", resp.StatusCode)
	}
}

// A user who already has a token must still find the install commands (for another machine), with
// a placeholder: the token is stored hashed and must not be regenerated just to see them.
func TestJoinShowsInstallCommandsToUsersWithAToken(t *testing.T) {
	te := newTestEnv(t, "")
	te.user(t, 7, "carol")
	raw := te.hub.signedValue("session", time.Hour, "7")
	get := func(cookie string) string {
		resp := te.do(t, "GET", "/join", "", "", nil, [2]string{"Cookie", cookie})
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}
	body := get(sessionCookie + "=" + raw)
	for _, want := range []string{"重新生成 token", "install.sh | sudo bash -s -- &lt;你的 token&gt;", "CFHUB_TOKEN=&lt;你的 token&gt;", "-Token &lt;你的 token&gt;"} {
		if !strings.Contains(body, want) {
			t.Fatalf("/join for a user with a token lacks %q", want)
		}
	}
	if strings.Contains(get(""), "install.sh | sudo bash") {
		t.Fatal("/join shows install commands to visitors who are not logged in")
	}
	req, _ := http.NewRequest("POST", te.server.URL+"/me/token", strings.NewReader(url.Values{"csrf": {te.hub.csrfToken(session{Raw: raw})}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", sessionCookie+"="+raw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	fresh, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(fresh), "install.sh | sudo bash -s -- cfp_") || strings.Contains(string(fresh), "&lt;你的 token&gt;") {
		t.Fatal("a fresh token is not filled into the install commands")
	}
}

func TestMyProbersAndAdminPagesShowCloudLinesAndServerCounts(t *testing.T) {
	te := newTestEnv(t, "")
	if err := te.hub.net.setCloud("aliyun 47.100.0.0/16\n"); err != nil {
		t.Fatal(err)
	}
	alice, bob := te.user(t, 1, "alice"), te.user(t, 2, "bob") // alice is the admin in newTestEnv
	te.do(t, "POST", "/api/v1/probe/report", alice, "47.100.1.9", report("104.16.1.1", "104.16.2.1"))
	te.do(t, "POST", "/api/v1/probe/report", alice, "47.100.2.9", report("104.16.1.1", "104.16.2.1"))
	te.do(t, "POST", "/api/v1/probe/report", bob, "47.100.3.9", report("104.16.1.1", "104.16.2.1"))
	te.hub.runAggregation(context.Background())
	cookie := sessionCookie + "=" + te.hub.signedValue("session", time.Hour, "1")
	get := func(path string) string {
		resp := te.do(t, "GET", path, "", "", nil, [2]string{"Cookie", cookie})
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
		return string(body)
	}
	if body := get("/me"); !strings.Contains(body, "国内云厂商 · 阿里云") || !strings.Contains(body, "47.100.2.0/24") {
		t.Fatal("/me does not show the cloud provider and each server's line")
	}
	if body := get("/admin"); !strings.Contains(body, "alice ×2") || !strings.Contains(body, "2 人 3 台探针") {
		t.Fatal("/admin does not count alice's two servers under one tag")
	}
	if body := get("/"); !strings.Contains(body, "3 台 / 2 人") {
		t.Fatal("dashboard does not show votes as servers / people")
	}
}

func TestISPTableOnlyForLocalCallersNotThroughCaddy(t *testing.T) {
	te := newTestEnv(t, "")
	if resp := te.do(t, "GET", "/internal/isp-table", "", "", nil); resp.StatusCode != 200 {
		t.Fatalf("local DoH fetch: %d", resp.StatusCode)
	}
	if resp := te.do(t, "GET", "/internal/isp-table", "", "8.8.8.8", nil); resp.StatusCode != 404 {
		t.Fatalf("a request through Caddy got the internal table: %d", resp.StatusCode)
	}
}

func TestInstallerCarriesChecksums(t *testing.T) {
	te := newTestEnv(t, "")
	if resp := te.do(t, "GET", "/install.sh", "", "", nil); resp.StatusCode != 503 {
		t.Fatalf("installer served without binaries: %d", resp.StatusCode)
	}
	if err := os.MkdirAll(te.hub.cfg.DistDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range distFiles {
		if err := os.WriteFile(filepath.Join(te.hub.cfg.DistDir, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resp := te.do(t, "GET", "/install.sh", "", "", nil)
	body, _ := io.ReadAll(resp.Body)
	sum, _ := te.hub.distSum("cfprobe-linux-amd64")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "SHA="+sum) || !strings.Contains(string(body), `HUB="https://cfhub.example"`) {
		t.Fatalf("installer %d:\n%s", resp.StatusCode, body)
	}
	if resp := te.do(t, "GET", "/dl/../hub.db", "", "", nil); resp.StatusCode == 200 {
		t.Fatal("download escaped the allowlist")
	}
	// With a mirror configured, both installers try it first and fall back to the hub's own /dl.
	te.hub.cfg.DLMirrors = []string{"https://mirror.example/cfprobe"}
	sh, _ := io.ReadAll(te.do(t, "GET", "/install.sh", "", "", nil).Body)
	if !strings.Contains(string(sh), `for SRC in "https://mirror.example/cfprobe" "https://cfhub.example/dl" ; do`) {
		t.Fatalf("install.sh sources:\n%s", sh)
	}
	ps, _ := io.ReadAll(te.do(t, "GET", "/install.ps1", "", "", nil).Body)
	if !strings.Contains(string(ps), `foreach ($src in @('https://mirror.example/cfprobe', 'https://cfhub.example/dl'))`) {
		t.Fatalf("install.ps1 sources:\n%s", ps)
	}
	script := filepath.Join(t.TempDir(), "install.sh")
	_ = os.WriteFile(script, sh, 0o644)
	// POSIX sh (OpenWrt's ash, Debian's dash) as well as bash. busybox/dash are checked when installed.
	for _, shell := range [][]string{{"bash", "-n"}, {"bash", "--posix", "-n"}, {"dash", "-n"}, {"busybox", "sh", "-n"}} {
		if path, err := exec.LookPath(shell[0]); err == nil {
			if out, err := exec.Command(path, append(shell[1:], script)...).CombinedOutput(); err != nil {
				t.Fatalf("rendered install.sh does not parse with %v: %v\n%s", shell, err, out)
			}
		}
	}
	// Every platform the installer can pick has its own checksum, and OpenWrt runs from cron.
	for key, name := range distFiles {
		if key == "windows" || strings.HasPrefix(key, "darwin") { // install.ps1; macOS is set up by hand
			continue
		}
		sum, _ := te.hub.distSum(name)
		if !strings.Contains(string(sh), key+") SHA="+sum) {
			t.Errorf("install.sh lacks the %s checksum", key)
		}
	}
	for _, want := range []string{"/etc/openwrt_release", "DISTRIB_ARCH", "/etc/crontabs/cfprobe", "logger -t cfprobe", "opkg install", "apk add", "apt-get install", "ca-certificates", "--dir", `--direct) DIRECT=" -direct auto"`, "history4.json$UPDATE$DIRECT"} {
		if !strings.Contains(string(sh), want) {
			t.Errorf("install.sh lacks %q", want)
		}
	}
	// Self-update: the binary sits in the state dir, auto-update can be turned off, and the signed
	// manifest is downloadable (uncached) while other files in dist stay hidden.
	if !strings.Contains(string(sh), "BIN=$STATE/cfprobe") || !strings.Contains(string(sh), `--no-auto-update) UPDATE=" -no-update"`) || !strings.Contains(string(sh), "history4.json$UPDATE") {
		t.Fatal("install.sh does not install into the state dir with an auto-update switch")
	}
	if !strings.Contains(string(ps), "[switch]$NoAutoUpdate") || !strings.Contains(string(ps), `cfprobe.log"$update`) {
		t.Fatal("install.ps1 has no -NoAutoUpdate switch")
	}
	for _, name := range []string{"manifest.json", "manifest.json.sig", "secret.key"} {
		_ = os.WriteFile(filepath.Join(te.hub.cfg.DistDir, name), []byte(name), 0o644)
	}
	if resp := te.do(t, "GET", "/dl/manifest.json", "", "", nil); resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest: %d cache-control %q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	if resp := te.do(t, "GET", "/dl/manifest.json.sig", "", "", nil); resp.StatusCode != 200 {
		t.Fatalf("manifest signature: %d", resp.StatusCode)
	}
	if resp := te.do(t, "GET", "/dl/secret.key", "", "", nil); resp.StatusCode != 404 {
		t.Fatalf("a file outside the allowlist was served: %d", resp.StatusCode)
	}
}

func TestPagesRender(t *testing.T) {
	te := newTestEnv(t, "")
	for _, path := range []string{"/", "/join", "/api/v1/pools", "/api/v1/summary", "/api/v1/history?isp=chinanet", "/healthz", "/static/app.css", "/static/logo.svg", "/static/logo.png"} {
		if resp := te.do(t, "GET", path, "", "", nil); resp.StatusCode != 200 {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	if resp := te.do(t, "GET", "/static/logo.png", "", "", nil); resp.Header.Get("Content-Type") != "image/png" {
		t.Errorf("logo.png served as %q", resp.Header.Get("Content-Type"))
	}
	if resp := te.do(t, "GET", "/static/", "", "", nil); resp.StatusCode == 200 {
		t.Error("/static/ must not list the directory")
	}
}
