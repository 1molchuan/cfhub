package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// lineReports gives one line (isp) two users' probers that agree on ips, so its pool publishes them.
func lineReports(isp string, block int, ips ...string) []Report {
	var out []Report
	for i := 0; i < 2; i++ {
		list := []ReportIP{}
		for _, ip := range ips {
			list = append(list, ReportIP{IP: ip, MedianMS: 100, OK: 6, Rounds: 6})
		}
		out = append(out, Report{UserID: int64(block*10 + i), Prefix: "10." + string(rune('0'+block)) + "." + string(rune('0'+i)) + ".0/24", ISP: isp, Family: 4, IPs: list})
	}
	return out
}

func addresses(p *Pool) []string {
	if p == nil {
		return nil
	}
	return p.addresses()
}

func TestNationalPoolCombinesLinesOneVoteEach(t *testing.T) {
	var reports []Report
	reports = append(reports, lineReports("chinanet", 1, "104.16.1.1", "104.16.2.1", "104.16.3.1", "104.16.4.1")...)
	reports = append(reports, lineReports("unicom", 2, "104.16.9.1", "104.16.2.1", "104.16.1.1")...)
	reports = append(reports, lineReports("cmcc", 3, "104.16.8.1", "104.16.1.1")...)
	// "other" (overseas) never feeds the nationwide pool, however loud.
	reports = append(reports, lineReports("other", 4, "104.16.7.1", "104.16.7.2")...)
	pools := aggregate(reports, 2, 6, nil)
	p := pools[poolKey{nationalISP, 4}]
	if p == nil || !p.Published {
		t.Fatalf("nationwide pool %+v, want published", p)
	}
	// 104.16.1.1 is in all three lines, 104.16.2.1 in two; an IP only one line picked is left out.
	want := []string{"104.16.1.1", "104.16.2.1"}
	if got := addresses(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("nationwide pool %v, want %v", got, want)
	}
	if !reflect.DeepEqual(p.IPs[0].Lines, []string{"chinanet", "unicom", "cmcc"}) || p.IPs[0].Users != 6 || p.IPs[0].Votes != 6 {
		t.Fatalf("first IP %+v, want 3 lines, 6 probers of 6 users", p.IPs[0])
	}
	if p.Users != 6 || p.Probers != 6 {
		t.Fatalf("pool counts %d users / %d probers, want 6 / 6 (the other line's excluded)", p.Users, p.Probers)
	}
	for _, ip := range p.IPs {
		if strings.HasPrefix(ip.IP, "104.16.7.") {
			t.Fatal("an 'other' IP got into the nationwide pool")
		}
	}
}

func TestNationalPoolNeedsTwoLinesAndHonoursSuspension(t *testing.T) {
	one := lineReports("chinanet", 1, "104.16.1.1", "104.16.2.1")
	if p := aggregate(one, 2, 6, nil)[poolKey{nationalISP, 4}]; p == nil || p.Published || !strings.Contains(p.Reason, "2 类线路") {
		t.Fatalf("one line: %+v, want an unpublished pool asking for 2 lines", p)
	}
	// Two lines that share only one IP: nothing to publish (the DoH falls back to its own probers).
	lone := append(slices.Clone(one), lineReports("cloud", 2, "104.16.1.1", "104.16.5.1")...)
	if p := aggregate(lone, 2, 6, nil)[poolKey{nationalISP, 4}]; p.Published || !strings.Contains(p.Reason, "都认可的 IP 不足") {
		t.Fatalf("two lines sharing one IP: %+v, want unpublished", p)
	}
	two := append(slices.Clone(one), lineReports("cloud", 2, "104.16.1.1", "104.16.2.1", "104.16.5.1")...)
	if p := aggregate(two, 2, 6, nil)[poolKey{nationalISP, 4}]; !p.Published {
		t.Fatalf("two lines: %+v", p)
	}
	if p := aggregate(two, 2, 6, map[string]bool{nationalISP: true})[poolKey{nationalISP, 4}]; p.Published {
		t.Fatal("a suspended nationwide pool was published")
	}
	// A suspended line is not published, so it does not count either.
	if p := aggregate(two, 2, 6, map[string]bool{"cloud": true})[poolKey{nationalISP, 4}]; p.Published {
		t.Fatal("a suspended line still fed the nationwide pool")
	}
	if p := aggregate(lineReports("other", 1, "104.16.1.1"), 2, 6, nil)[poolKey{nationalISP, 4}]; p != nil {
		t.Fatalf("no published line, yet a nationwide pool: %+v", p)
	}
}

// Pools serve only IPs within fastTier of their fastest median: the DoH rotates through the whole
// pool, so a slow member gets its share of connections. Fewer than two fast ones are topped up.
func TestPoolsKeepOnlyTheFastTier(t *testing.T) {
	timed := func(isp string, block int, medians map[string]int, order ...string) []Report {
		reports := lineReports(isp, block, order...)
		for _, r := range reports {
			for i := range r.IPs {
				r.IPs[i].MedianMS = medians[r.IPs[i].IP]
			}
		}
		return reports
	}
	medians := map[string]int{"104.16.1.1": 200, "104.16.2.1": 250, "104.16.3.1": 750, "104.16.4.1": 255, "104.16.5.1": 700}
	reports := timed("chinanet", 1, medians, "104.16.1.1", "104.16.3.1", "104.16.2.1", "104.16.5.1", "104.16.4.1")
	p := aggregate(reports, 2, 6, nil)[poolKey{"chinanet", 4}]
	if got := addresses(p); !reflect.DeepEqual(got, []string{"104.16.1.1", "104.16.2.1", "104.16.4.1"}) {
		t.Fatalf("pool %v, want only the IPs within 1.3x of 200 ms, in rank order", got)
	}
	if p.MedianMS != 250 {
		t.Fatalf("pool median %d, want 250 (of the IPs served)", p.MedianMS)
	}
	// One fast IP: the next in rank order within 2x tops the pool up to two, skipping slower ones.
	mixed := map[string]int{"104.16.1.1": 100, "104.16.3.1": 900, "104.16.5.1": 180}
	q := aggregate(timed("unicom", 2, mixed, "104.16.1.1", "104.16.3.1", "104.16.5.1"), 2, 6, nil)[poolKey{"unicom", 4}]
	if got := addresses(q); !reflect.DeepEqual(got, []string{"104.16.1.1", "104.16.5.1"}) || !q.Published {
		t.Fatalf("pool %v (published %v), want the fast IP and the next one within 2x", got, q.Published)
	}
	// None within 2x: the pool is not published, so no 900 ms IP gets half the connections.
	slow := map[string]int{"104.16.1.1": 100, "104.16.3.1": 900, "104.16.5.1": 800}
	r := aggregate(timed("cmcc", 3, slow, "104.16.1.1", "104.16.3.1", "104.16.5.1"), 2, 6, nil)[poolKey{"cmcc", 4}]
	if r.Published || !reflect.DeepEqual(addresses(r), []string{"104.16.1.1"}) || !strings.Contains(r.Reason, "不足") {
		t.Fatalf("pool %v (published %v, %q), want one IP and unpublished", addresses(r), r.Published, r.Reason)
	}
}

func TestNationalPoolKeepsTwoPerBlock(t *testing.T) {
	var reports []Report
	reports = append(reports, lineReports("chinanet", 1, "104.16.1.1", "104.16.1.2", "104.16.1.3")...)
	reports = append(reports, lineReports("unicom", 2, "104.16.1.1", "104.16.1.2", "104.16.1.3", "104.16.2.1")...)
	p := aggregate(reports, 2, 6, nil)[poolKey{nationalISP, 4}]
	if got := addresses(p); !reflect.DeepEqual(got, []string{"104.16.1.1", "104.16.1.2"}) {
		t.Fatalf("pool %v, want at most two addresses from 104.16.1.0/24 (and not unicom's own 104.16.2.1)", got)
	}
}

func TestNationalPoolIsPushedAndShown(t *testing.T) {
	te := newTestEnv(t, "")
	a, b, c := te.user(t, 60, "a"), te.user(t, 61, "b"), te.user(t, 62, "c")
	// Two telecom users agree; cmcc has one user (unpublished), so only one line: no nationwide push.
	te.do(t, "POST", "/api/v1/probe/report", a, "58.247.1.9", report("104.16.1.1", "104.16.2.1"))
	te.do(t, "POST", "/api/v1/probe/report", b, "58.247.2.9", report("104.16.1.1", "104.16.2.1"))
	te.hub.runAggregation(context.Background())
	for _, push := range te.pushed {
		if push["scope"] == "isp:national" {
			t.Fatal("pushed a nationwide pool built from one line")
		}
	}
	// A second line (cmcc: two users) publishes, and so does the nationwide pool.
	te.do(t, "POST", "/api/v1/probe/report", c, "120.192.1.9", report("104.16.1.1", "104.16.2.1", "104.16.3.1"))
	d := te.user(t, 63, "d")
	te.do(t, "POST", "/api/v1/probe/report", d, "120.192.2.9", report("104.16.1.1", "104.16.2.1", "104.16.3.1"))
	te.hub.runAggregation(context.Background())
	var national map[string]any
	for _, push := range te.pushed {
		if push["scope"] == "isp:national" {
			national = push
		}
	}
	if national == nil || !reflect.DeepEqual(national["ipv4"], []any{"104.16.1.1", "104.16.2.1"}) {
		t.Fatalf("nationwide push %v", national)
	}
	body, _ := io.ReadAll(te.do(t, "GET", "/", "", "", nil).Body)
	for _, want := range []string{"全国 <small>IPv4", "认可的线路", `<span class="tag">电信</span><span class="tag">移动</span>`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if resp := te.do(t, "GET", "/api/v1/history?isp=national", "", "", nil); resp.StatusCode != 200 {
		t.Fatalf("history for the nationwide pool: %d", resp.StatusCode)
	}
}

// Probers are asked to re-test the nationwide pool too (a line without its own pool gets nothing
// else from the hub), and configured extras of their family that are Cloudflare's.
func TestCandidatesIncludeTheNationwidePoolAndExtras(t *testing.T) {
	te := newTestEnv(t, "")
	te.hub.cfg.ExtraCandidates = []netip.Addr{netip.MustParseAddr("104.16.9.9"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("2606:4700::9")}
	for i, from := range []string{"58.247.1.9", "58.247.2.9", "120.192.1.9", "120.192.2.9"} {
		tok := te.user(t, int64(70+i), fmt.Sprintf("u%d", i))
		te.do(t, "POST", "/api/v1/probe/report", tok, from, report("104.16.1.1", "104.16.2.1"))
	}
	te.hub.runAggregation(context.Background())
	if p := te.hub.pool(nationalISP, 4); p == nil || !p.Published {
		t.Fatalf("no nationwide pool to hand out: %+v", p)
	}
	edu := te.user(t, 80, "edu") // 58.247.22.0/24 is CERNET in the test table: no line pool yet
	var got struct {
		ISP string   `json:"isp"`
		IPs []string `json:"ips"`
	}
	_ = json.NewDecoder(te.do(t, "GET", "/api/v1/probe/candidates?family=4", edu, "58.247.22.5", nil).Body).Decode(&got)
	if got.ISP != "cernet" || !reflect.DeepEqual(got.IPs[:3], []string{"104.16.1.1", "104.16.2.1", "104.16.9.9"}) || slices.Contains(got.IPs, "203.0.113.1") {
		t.Fatalf("candidates %+v; want the nationwide pool, then the Cloudflare extra, never the non-Cloudflare one", got)
	}
	_ = json.NewDecoder(te.do(t, "GET", "/api/v1/probe/candidates?family=6", edu, "58.247.22.5", nil).Body).Decode(&got)
	if !reflect.DeepEqual(got.IPs, []string{"2606:4700::9"}) {
		t.Fatalf("IPv6 candidates %v; want just the IPv6 extra", got.IPs)
	}
}
