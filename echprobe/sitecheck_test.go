package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testECH builds an X25519 ECHConfigList (public name public.example) and the matching server key.
func testECH(t *testing.T) ([]byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	var c []byte
	c = append(c, 1)                             // config_id
	c = binary.BigEndian.AppendUint16(c, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	c = binary.BigEndian.AppendUint16(c, 4)
	c = append(c, 0, 1, 0, 1) // HKDF-SHA256, AES-128-GCM
	c = append(c, 0)          // maximum_name_length
	name := "public.example"
	c = append(c, byte(len(name)))
	c = append(c, name...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	config := binary.BigEndian.AppendUint16([]byte{0xfe, 0x0d}, uint16(len(c)))
	config = append(config, c...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(config)))
	return append(list, config...), tls.EncryptedClientHelloKey{Config: config, PrivateKey: priv.Bytes(), SendAsRetry: true}
}

func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// colo is one fake Cloudflare colo. With originDown, /cdn-cgi/trace (answered by the edge) still
// works but /about.json (needs the origin) hangs; /srv/status is a fast 403 bot challenge either way.
func colo(t *testing.T, name string, originDown bool, cert tls.Certificate, key tls.EncryptedClientHelloKey) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cdn-cgi/trace":
			_, _ = w.Write([]byte("fl=1\ncolo=" + name + "\n"))
		case "/srv/status":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(strings.Repeat("challenge ", 100)))
		default:
			if originDown {
				select {
				case <-time.After(3 * time.Second):
				case <-r.Context().Done():
				}
				return
			}
			_, _ = w.Write([]byte(`{"about":{}}`))
		}
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{key}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// fakeColos routes fake IPs to local colos: 10.0.1-3.x → SIN (origin down), 10.0.4-6.x → FRA.
func fakeColos(t *testing.T) []byte {
	t.Helper()
	ech, key := testECH(t)
	cert, roots := testCert(t, "forum.example", "public.example")
	sin := colo(t, "SIN", true, cert, key)
	fra := colo(t, "FRA", false, cert, key)
	oldAddr, oldRoots, oldDeadline := siteAddr, siteRoots, rankDeadline
	t.Cleanup(func() { siteAddr, siteRoots, rankDeadline = oldAddr, oldRoots, oldDeadline })
	siteRoots = roots
	rankDeadline = time.Time{}
	siteAddr = func(ip string) string {
		switch {
		case strings.HasPrefix(ip, "10.0.1.") || strings.HasPrefix(ip, "10.0.2.") || strings.HasPrefix(ip, "10.0.3."):
			return sin
		case strings.HasPrefix(ip, "10.0.4.") || strings.HasPrefix(ip, "10.0.5.") || strings.HasPrefix(ip, "10.0.6."):
			return fra
		}
		return "127.0.0.1:1" // nothing listens: connection refused
	}
	return ech
}

var sitePaths = []string{"/srv/status", "/about.json"}

func TestSiteCheckMovesAHangingSiteToAColoThatReachesItsOrigin(t *testing.T) {
	ech := fakeColos(t)
	pool := []string{"10.0.1.1", "10.0.2.1"}
	candidates := []string{"10.0.3.1", "10.9.9.9", "10.0.4.1", "10.0.4.2", "10.0.4.3", "10.0.5.1"}
	isDegraded, alt := checkSite("forum.example", ech, sitePaths, pool, candidates, 400*time.Millisecond)
	if !isDegraded {
		t.Fatal("pool whose origin requests hang was not reported degraded")
	}
	if len(alt) < siteMinPool {
		t.Fatalf("alternatives = %v, want at least %d", alt, siteMinPool)
	}
	block4 := 0
	for _, ip := range alt {
		if !strings.HasPrefix(ip, "10.0.4.") && !strings.HasPrefix(ip, "10.0.5.") {
			t.Errorf("alternative %s is not in the healthy colo", ip)
		}
		if strings.HasPrefix(ip, "10.0.4.") {
			block4++
		}
	}
	if block4 > 2 {
		t.Errorf("%d alternatives from one /24, want at most 2: %v", block4, alt)
	}
}

func TestSiteCheckLeavesAHealthySiteAlone(t *testing.T) {
	ech := fakeColos(t)
	// A fast 403 (the edge's bot challenge) is not a failure: only hangs and broken connections are.
	isDegraded, alt := checkSite("forum.example", ech, sitePaths, []string{"10.0.4.1", "10.0.5.1"}, []string{"10.0.6.1"}, 400*time.Millisecond)
	if isDegraded || alt != nil {
		t.Fatalf("healthy pool: degraded=%v alternatives=%v, want false/nil", isDegraded, alt)
	}
}

func TestSiteCheckGivesNoOverrideItCouldNotVerify(t *testing.T) {
	ech := fakeColos(t)
	isDegraded, alt := checkSite("forum.example", ech, sitePaths, []string{"10.0.1.1"}, []string{"10.0.2.1", "10.9.9.9"}, 400*time.Millisecond)
	if !isDegraded || alt != nil {
		t.Fatalf("no healthy candidate: degraded=%v alternatives=%v, want true/nil", isDegraded, alt)
	}
}

func TestRetestOrderCapsHistoryBestFirstThenPeers(t *testing.T) {
	old := maxKnown
	t.Cleanup(func() { maxKnown = old })
	maxKnown = 2
	hist := probeHistory{
		"1.0.0.1": {{At: 1, OK: 9, Rounds: 10, Median: 100}},
		"1.0.0.2": {{At: 1, OK: 10, Rounds: 10, Median: 300}},
		"1.0.0.3": {{At: 1, OK: 10, Rounds: 10, Median: 200}},
	}
	known := map[string]bool{"1.0.0.1": true, "1.0.0.2": true, "1.0.0.3": true}
	order, fromHistory := retestOrder(hist, known, []string{"1.0.0.3", "2.0.0.1"})
	want := []string{"1.0.0.3", "1.0.0.2", "2.0.0.1"} // perfect IPs by latency, capped at 2; then new peers
	if fromHistory != 2 || strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v (from history %d), want %v (2)", order, fromHistory, want)
	}
}

func TestBudgetStopsStartingNewIPs(t *testing.T) {
	old := rankDeadline
	t.Cleanup(func() { rankDeadline = old })
	rankDeadline = time.Now().Add(-time.Second)
	if stats := testAll([]string{"10.9.9.1", "10.9.9.2"}, []string{"x.example"}, nil, 1, time.Second, true); len(stats) != 0 {
		t.Fatalf("past the deadline %d IPs were still tested", len(stats))
	}
	if got := probeAll([]string{"10.9.9.1"}, "x.example", nil, nil, time.Second); len(got) != 0 {
		t.Fatalf("past the deadline probeAll still tested %d IPs", len(got))
	}
}
