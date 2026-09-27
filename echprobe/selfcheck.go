package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// selfCheck resolves each host's A, AAAA and HTTPS through the DoH server the way Chromium does
// (in parallel, over one HTTP/2 connection) and checks what Chromium needs to actually use ECH.
// Every failure here makes browsers connect with a plaintext SNI, which the GFW resets — the
// symptom is a page that loads but whose styles/images do not. Checked per host:
//   - all A/AAAA records sit at one name, and the HTTPS record is at that same name
//     (net/dns/host_cache.cc; a CNAME chain left in the answer breaks this);
//   - the HTTPS record carries an ECH config;
//   - hosts where QUIC+ECH fails do not advertise h3 (per the server's measured verdicts from
//     -h3check, falling back to -selfcheck-no-h3 for hosts never measured);
//   - the HTTPS answer is not later than Chromium waits for it after the addresses.
//
// The verdict is printed, optionally POSTed to /admin/selfcheck, and sets the exit status.
func selfCheck(doh string, hosts, noH3 []string, reportURL, token, source string) {
	// Open the connection first so the three parallel queries share it, as in a browser.
	if _, err := dohRoundTrip(doh, "example.com", dnsmessage.TypeA); err != nil {
		fmt.Fprintln(os.Stderr, "selfcheck: DoH unreachable:", err)
		os.Exit(1)
	}
	var measured map[string]bool
	if reportURL != "" && token != "" {
		var err error
		if measured, err = fetchH3Verdicts(reportURL, token); err != nil {
			fmt.Fprintln(os.Stderr, "selfcheck: cannot read QUIC+ECH verdicts, using the static list:", err)
		}
	}
	var problems []string
	for _, host := range hosts {
		found := checkHost(doh, host, h3Forbidden(host, measured, noH3))
		if len(found) == 0 {
			fmt.Printf("ok    %s\n", host)
		}
		for _, p := range found {
			fmt.Printf("FAIL  %s: %s\n", host, p)
			problems = append(problems, host+": "+p)
		}
	}
	ok := len(problems) == 0
	if reportURL != "" {
		body, _ := json.Marshal(map[string]any{"source": source, "ok": ok, "problems": problems, "hosts": len(hosts)})
		dohTransport.CloseIdleConnections()
		if _, err := postReport(reportURL, token, body); err != nil {
			fmt.Fprintln(os.Stderr, "selfcheck report failed:", err)
		}
	}
	if !ok {
		os.Exit(1)
	}
}

type timedAnswer struct {
	msg  *dnsmessage.Message
	took time.Duration
	err  error
}

func resolveTriple(doh, host string) (a, aaaa, https timedAnswer) {
	var wg sync.WaitGroup
	run := func(t dnsmessage.Type, out *timedAnswer) {
		defer wg.Done()
		start := time.Now()
		out.msg, out.err = dohRoundTrip(doh, host, t)
		out.took = time.Since(start)
	}
	wg.Add(3)
	go run(dnsmessage.TypeA, &a)
	go run(dnsmessage.TypeAAAA, &aaaa)
	go run(dnsmessage.Type(65), &https)
	wg.Wait()
	return
}

// httpsLagAllowance mirrors Chromium's UseDnsHttpsSvcbSecureExtraTime{Percent,Min,Max}: after the
// address queries finish it waits 20% of their duration for HTTPS, clamped to [5ms, 50ms].
func httpsLagAllowance(addresses time.Duration) time.Duration {
	return min(max(addresses/5, 5*time.Millisecond), 50*time.Millisecond)
}

func checkHost(doh, host string, noH3 bool) []string {
	a, aaaa, https := resolveTriple(doh, host)
	for _, q := range []struct {
		name string
		ans  timedAnswer
	}{{"A", a}, {"AAAA", aaaa}, {"HTTPS", https}} {
		if q.ans.err != nil {
			return []string{q.name + " query failed: " + q.ans.err.Error()}
		}
	}
	problems := chromiumProblems(a.msg, aaaa.msg, https.msg, noH3)
	// One late answer can be network jitter on the prober's side; only a repeat counts.
	for attempt := 0; attempt < 2; attempt++ {
		addresses := max(a.took, aaaa.took)
		lag := https.took - addresses
		if lag <= httpsLagAllowance(addresses) {
			break
		}
		if attempt == 1 {
			problems = append(problems, fmt.Sprintf("HTTPS answered %dms after the addresses; Chromium waits only %dms, then connects without ECH",
				lag.Milliseconds(), httpsLagAllowance(addresses).Milliseconds()))
			break
		}
		a, aaaa, https = resolveTriple(doh, host)
		if a.err != nil || aaaa.err != nil || https.err != nil {
			break
		}
	}
	return problems
}

// chromiumProblems applies Chromium's rules for using an HTTPS record to one set of answers.
func chromiumProblems(a, aaaa, https *dnsmessage.Message, noH3 bool) []string {
	owners := map[string]bool{}
	for _, m := range []*dnsmessage.Message{a, aaaa} {
		for _, rr := range m.Answers {
			switch rr.Body.(type) {
			case *dnsmessage.AResource, *dnsmessage.AAAAResource:
				owners[strings.ToLower(rr.Header.Name.String())] = true
			}
		}
	}
	if len(owners) == 0 {
		return []string{"no A/AAAA addresses"}
	}
	if len(owners) > 1 {
		return []string{fmt.Sprintf("A/AAAA records sit at different names %v, so Chromium ignores the HTTPS record", keys(owners))}
	}
	canonical := keys(owners)[0]
	var service bool
	var matched *dnsmessage.HTTPSResource
	var at string
	for _, rr := range https.Answers {
		h, ok := rr.Body.(*dnsmessage.HTTPSResource)
		if !ok || h.Priority == 0 {
			continue
		}
		service = true
		target := h.Target.String()
		if target == "." {
			target = rr.Header.Name.String()
		}
		at = strings.ToLower(target)
		if at == canonical {
			matched = h
			break
		}
	}
	if !service {
		return []string{"no HTTPS record, so no ECH"}
	}
	if matched == nil {
		return []string{fmt.Sprintf("addresses are at %s but the HTTPS record is at %s, so Chromium ignores it", canonical, at)}
	}
	var problems []string
	if ech, ok := matched.GetParam(dnsmessage.SVCParamECH); !ok || len(ech) == 0 {
		problems = append(problems, "the HTTPS record carries no ECH config")
	}
	if alpn, ok := matched.GetParam(dnsmessage.SVCParamALPN); ok && noH3 {
		for i := 0; i < len(alpn); i += 1 + int(alpn[i]) {
			if end := i + 1 + int(alpn[i]); end <= len(alpn) && string(alpn[i+1:end]) == "h3" {
				problems = append(problems, "advertises h3, but QUIC+ECH fails for this host (browsers waste a QUIC attempt)")
			}
		}
	}
	return problems
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasSuffix(host string, suffixes []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "."))
		if s != "" && (host == s || strings.HasSuffix(host, "."+s)) {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
