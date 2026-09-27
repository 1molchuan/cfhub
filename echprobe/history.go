package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// runRecord is one prober run's result for one IP.
type runRecord struct {
	At     int64 `json:"at"`
	OK     int   `json:"ok"`
	Rounds int   `json:"rounds"`
	Median int64 `json:"median_ms"`
}

// probeHistory keeps recent per-IP results across runs so an IP that passes one run by luck
// but fails intermittently over hours is not reported as preferred.
type probeHistory map[string][]runRecord

const (
	historyMaxRuns = 6
	historyMaxAge  = 6 * time.Hour
	// Minimum success rate over the retained runs for an IP to stay eligible.
	historyMinRate = 0.9
)

func loadHistory(path string) probeHistory {
	h := probeHistory{}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &h)
	}
	return h
}

func (h probeHistory) record(ip string, rec runRecord) {
	h[ip] = append(h[ip], rec)
}

func (h probeHistory) prune(now time.Time) {
	cutoff := now.Add(-historyMaxAge).Unix()
	for ip, runs := range h {
		kept := runs[:0]
		for _, r := range runs {
			if r.At >= cutoff {
				kept = append(kept, r)
			}
		}
		if len(kept) > historyMaxRuns {
			kept = kept[len(kept)-historyMaxRuns:]
		}
		if len(kept) == 0 {
			delete(h, ip)
		} else {
			h[ip] = kept
		}
	}
}

// rate returns the aggregate success rate and number of runs retained for ip.
func (h probeHistory) rate(ip string) (float64, int) {
	ok, rounds := 0, 0
	for _, r := range h[ip] {
		ok += r.OK
		rounds += r.Rounds
	}
	if rounds == 0 {
		return 0, 0
	}
	return float64(ok) / float64(rounds), len(h[ip])
}

func saveHistory(path string, h probeHistory) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
