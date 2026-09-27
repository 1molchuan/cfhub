package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
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

	got, err := fetchHubCandidates(hub.URL, "cfp_test", 6)
	if err != nil || got.ISP != "chinanet" || !reflect.DeepEqual(got.IPs, []string{"2606:4700::1"}) {
		t.Fatalf("candidates %+v, %v", got, err)
	}
	if _, err := fetchHubCandidates(hub.URL, "cfp_wrong", 6); err == nil {
		t.Fatal("a refused token must be an error")
	}
	status, _, err := postHubReport(hub.URL, "cfp_test", []byte(`{"family":4}`))
	if err != nil || status != http.StatusTooManyRequests || string(reported) != `{"family":4}` {
		t.Fatalf("post: %d %v, sent %q", status, err, reported)
	}
}
