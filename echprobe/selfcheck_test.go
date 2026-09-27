package main

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func msg(answers ...dnsmessage.Resource) *dnsmessage.Message {
	return &dnsmessage.Message{Answers: answers}
}

func rrA(name string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{104, 16, 1, 1}},
	}
}

func rrCNAME(name, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func rrHTTPS(name string, alpn []byte, ech bool) dnsmessage.Resource {
	var params []dnsmessage.SVCParam
	if alpn != nil {
		params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamALPN, Value: alpn})
	}
	if ech {
		params = append(params, dnsmessage.SVCParam{Key: dnsmessage.SVCParamECH, Value: []byte{0, 4, 0xfe, 0x0d, 0, 0}})
	}
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.Type(65), Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("."), Params: params}},
	}
}

var h2only = []byte{2, 'h', '2'}

func TestChromiumProblems(t *testing.T) {
	cases := []struct {
		name          string
		a, aaaa, http *dnsmessage.Message
		noH3          bool
		want          string // substring of the single problem, "" for none
	}{
		{"flattened answer is fine", msg(rrA("abs.twimg.com.")), msg(), msg(rrHTTPS("abs.twimg.com.", h2only, true)), true, ""},
		{"CNAME'd addresses, HTTPS at the query name", msg(rrCNAME("abs.twimg.com.", "twimg.twitter.map.fastly.net."), rrA("twimg.twitter.map.fastly.net.")), msg(),
			msg(rrHTTPS("abs.twimg.com.", h2only, true)), true, "addresses are at twimg.twitter.map.fastly.net."},
		{"no ECH", msg(rrA("x.com.")), msg(), msg(rrHTTPS("x.com.", h2only, false)), true, "no ECH config"},
		{"h3 on an X host", msg(rrA("x.com.")), msg(), msg(rrHTTPS("x.com.", []byte{2, 'h', '3', 2, 'h', '2'}, true)), true, "advertises h3"},
		{"h3 is fine elsewhere", msg(rrA("linux.do.")), msg(), msg(rrHTTPS("linux.do.", []byte{2, 'h', '3', 2, 'h', '2'}, true)), false, ""},
		{"no HTTPS record", msg(rrA("abs-0.twimg.com.")), msg(), msg(), true, "no HTTPS record"},
	}
	for _, c := range cases {
		got := chromiumProblems(c.a, c.aaaa, c.http, c.noH3)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: unexpected problems %v", c.name, got)
			}
			continue
		}
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%s: got %v, want one problem containing %q", c.name, got, c.want)
		}
	}
}

func TestHTTPSLagAllowanceMatchesChromium(t *testing.T) {
	for _, c := range []struct{ addresses, want time.Duration }{
		{10 * time.Millisecond, 5 * time.Millisecond},   // floor
		{100 * time.Millisecond, 20 * time.Millisecond}, // 20%
		{400 * time.Millisecond, 50 * time.Millisecond}, // cap
	} {
		if got := httpsLagAllowance(c.addresses); got != c.want {
			t.Errorf("allowance(%v) = %v, want %v", c.addresses, got, c.want)
		}
	}
}

func TestH3ForbiddenPrefersMeasurements(t *testing.T) {
	static := []string{"twimg.com", "instagram.com"}
	measured := map[string]bool{"twimg.com": true, "pbs.twimg.com": false, "linux.do": false}
	for _, c := range []struct {
		host string
		want bool
	}{
		{"abs.twimg.com", false},    // measured OK overrides the static list
		{"pbs.twimg.com", true},     // most specific measurement wins
		{"cdn.linux.do", true},      // measured failure covers subdomains
		{"www.instagram.com", true}, // never measured: static list
		{"example.org", false},
	} {
		if got := h3Forbidden(c.host, measured, static); got != c.want {
			t.Errorf("h3Forbidden(%s) = %v, want %v", c.host, got, c.want)
		}
	}
	if !h3Forbidden("x.com", nil, []string{"x.com"}) {
		t.Error("without measurements the static list must apply")
	}
}

func TestH3DecideIsQuickToDisableSlowToEnable(t *testing.T) {
	for _, c := range []struct {
		runs []bool
		want string
	}{
		{[]bool{false}, "h2"},
		{[]bool{true, true, false}, "h2"},
		{[]bool{true}, "wait"},
		{[]bool{false, true, true}, "wait"},
		{[]bool{true, true, true}, "h3"},
	} {
		if got := h3Decide(c.runs); got != c.want {
			t.Errorf("h3Decide(%v) = %s, want %s", c.runs, got, c.want)
		}
	}
}

func TestHasSuffix(t *testing.T) {
	if !hasSuffix("abs.twimg.com", []string{"twimg.com"}) || !hasSuffix("x.com", []string{".x.com"}) || hasSuffix("notx.com", []string{"x.com"}) {
		t.Fatal("suffix matching is wrong")
	}
}
