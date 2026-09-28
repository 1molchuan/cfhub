package main

import (
	"context"
	"io"
	"reflect"
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
	// 104.16.1.1 is in all three lines, 104.16.2.1 in two; then each line's best in turn.
	want := []string{"104.16.1.1", "104.16.2.1", "104.16.9.1", "104.16.8.1", "104.16.3.1", "104.16.4.1"}
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
	two := append(one, lineReports("cloud", 2, "104.16.1.1", "104.16.5.1")...)
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

func TestNationalPoolKeepsTwoPerBlock(t *testing.T) {
	var reports []Report
	reports = append(reports, lineReports("chinanet", 1, "104.16.1.1", "104.16.1.2", "104.16.1.3")...)
	reports = append(reports, lineReports("unicom", 2, "104.16.1.1", "104.16.1.2", "104.16.1.3", "104.16.2.1")...)
	p := aggregate(reports, 2, 6, nil)[poolKey{nationalISP, 4}]
	if got := addresses(p); !reflect.DeepEqual(got, []string{"104.16.1.1", "104.16.1.2", "104.16.2.1"}) {
		t.Fatalf("pool %v, want at most two addresses from 104.16.1.0/24", got)
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
	te.do(t, "POST", "/api/v1/probe/report", c, "120.192.1.9", report("104.16.1.1", "104.16.3.1"))
	d := te.user(t, 63, "d")
	te.do(t, "POST", "/api/v1/probe/report", d, "120.192.2.9", report("104.16.1.1", "104.16.3.1"))
	te.hub.runAggregation(context.Background())
	var national map[string]any
	for _, push := range te.pushed {
		if push["scope"] == "isp:national" {
			national = push
		}
	}
	if national == nil || !reflect.DeepEqual(national["ipv4"], []any{"104.16.1.1", "104.16.2.1", "104.16.3.1"}) {
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
