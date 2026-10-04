package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAppendUnique(t *testing.T) {
	got := appendUnique([]string{"a", "b"}, "b", "c", "a", "d")
	if !reflect.DeepEqual(got, []string{"a", "b", "c", "d"}) {
		t.Fatalf("appendUnique = %v", got)
	}
}

func TestShareFamiliesCoverTheFastlyWildcards(t *testing.T) {
	for _, rd := range []string{"githubusercontent.com", "github.io", "githubassets.com"} {
		if !shareFamilies[rd] {
			t.Errorf("%s should be a shared-cert family (sibling IPs rescue each other)", rd)
		}
	}
	// github.com hosts are separate services (codeload ≠ github ≠ api), not a shared wildcard family.
	if shareFamilies["github.com"] {
		t.Error("github.com must not be a shared family")
	}
}

func TestRegistrableDomain(t *testing.T) {
	for host, want := range map[string]string{
		"raw.githubusercontent.com": "githubusercontent.com",
		"github.com":                "github.com",
		"a.b.github.io":             "github.io",
		"localhost":                 "localhost",
	} {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%s) = %s, want %s", host, got, want)
		}
	}
}

func TestGithubHostMatch(t *testing.T) {
	filter := []string{"github.com", "api.github.com", ".githubusercontent.com"}
	yes := []string{"github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "githubusercontent.com"}
	no := []string{"gist.github.com", "notgithub.com", "example.com", "github.com.evil.com"}
	for _, h := range yes {
		if !githubHostMatch(h, filter) {
			t.Errorf("%s should match", h)
		}
	}
	for _, h := range no {
		if githubHostMatch(h, filter) {
			t.Errorf("%s should not match", h)
		}
	}
}

func TestParseHostsFile(t *testing.T) {
	body := `# GitHub520 style
140.82.116.4              github.com
140.82.116.6              api.github.com
185.199.108.133           raw.githubusercontent.com objects.githubusercontent.com
2606:50c0::133            raw.githubusercontent.com
# comment 1.1.1.1 github.com
203.0.113.9               unrelated.example.com
185.199.110.133 raw.githubusercontent.com  # trailing comment
`
	filter := []string{"github.com", "api.github.com", ".githubusercontent.com"}
	out := map[string]map[string]bool{}
	parseHostsFile(body, filter, out)

	want := map[string][]string{
		"github.com":                    {"140.82.116.4"},
		"api.github.com":                {"140.82.116.6"},
		"raw.githubusercontent.com":     {"185.199.108.133", "185.199.110.133"},
		"objects.githubusercontent.com": {"185.199.108.133"},
	}
	got := map[string][]string{}
	for host, set := range out {
		for ip := range set {
			got[host] = append(got[host], ip)
		}
	}
	// order-independent compare
	norm := func(m map[string][]string) map[string]map[string]bool {
		r := map[string]map[string]bool{}
		for h, ips := range m {
			r[h] = map[string]bool{}
			for _, ip := range ips {
				r[h][ip] = true
			}
		}
		return r
	}
	if !reflect.DeepEqual(norm(got), norm(want)) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	if _, ok := out["unrelated.example.com"]; ok {
		t.Fatal("unrelated host must be filtered out")
	}
	// The IPv6 address for raw must be skipped (IPv4 only).
	if out["raw.githubusercontent.com"]["2606:50c0::133"] {
		t.Fatal("IPv6 candidate must be skipped")
	}
}

func TestFetchGithubCandidatesLocalFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "github-extra-hosts")
	body := "# regional entry IPs\n20.27.177.113 github.com\n185.199.108.133 raw.githubusercontent.com\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	filter := []string{"github.com", ".githubusercontent.com"}

	// A source without a scheme is read from disk instead of http.Client.Get.
	got := fetchGithubCandidates([]string{path}, filter, "")
	want := map[string][]string{
		"github.com":                {"20.27.177.113"},
		"raw.githubusercontent.com": {"185.199.108.133"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("local-file candidates = %v, want %v", got, want)
	}

	// An unreadable local source is skipped like an unreachable URL, not fatal.
	got = fetchGithubCandidates([]string{filepath.Join(t.TempDir(), "no-such-file"), path}, filter, "")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("after a missing local source, candidates = %v, want %v", got, want)
	}
}
