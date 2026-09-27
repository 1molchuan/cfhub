package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHistoryPruneAndRate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := probeHistory{}
	// Seven runs 30 minutes apart; only the newest historyMaxRuns are kept.
	for i := 7; i >= 1; i-- {
		ok := 4
		if i == 2 {
			ok = 1 // one bad run among the retained six
		}
		h.record("104.18.1.1", runRecord{At: now.Add(-time.Duration(i) * 30 * time.Minute).Unix(), OK: ok, Rounds: 4, Median: 600})
	}
	h.record("172.64.1.1", runRecord{At: now.Add(-7 * time.Hour).Unix(), OK: 4, Rounds: 4, Median: 500})
	h.prune(now)

	if _, ok := h["172.64.1.1"]; ok {
		t.Fatal("entries older than historyMaxAge must be dropped")
	}
	rate, runs := h.rate("104.18.1.1")
	if runs != historyMaxRuns {
		t.Fatalf("runs = %d, want %d", runs, historyMaxRuns)
	}
	// 5 perfect runs + one 1/4 run over 24 handshakes = 21/24 = 0.875 → below the 0.9 bar.
	if rate >= historyMinRate {
		t.Fatalf("rate = %.3f, want < %.2f so the flapping IP is excluded", rate, historyMinRate)
	}
}

func TestHistoryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	h := probeHistory{}
	h.record("104.18.1.1", runRecord{At: 1, OK: 4, Rounds: 4, Median: 600})
	if err := saveHistory(path, h); err != nil {
		t.Fatal(err)
	}
	if got := loadHistory(path); len(got["104.18.1.1"]) != 1 {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if got := loadHistory(filepath.Join(t.TempDir(), "missing.json")); len(got) != 0 {
		t.Fatal("missing file must load as empty history")
	}
}
