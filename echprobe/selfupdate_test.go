package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRelease struct {
	manifest []byte
	sig      string
	files    map[string][]byte // served at /dl/<name>
	mirror   map[string][]byte // served at /mirror/<name>
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// updateEnv serves rel from a local hub and points the updater at a temp "running binary".
func updateEnv(t *testing.T, pub ed25519.PublicKey, rel *fakeRelease) (hub, exe string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dl/manifest.json":
			_, _ = w.Write(rel.manifest)
		case r.URL.Path == "/dl/manifest.json.sig":
			_, _ = w.Write([]byte(rel.sig))
		case strings.HasPrefix(r.URL.Path, "/dl/") && rel.files[strings.TrimPrefix(r.URL.Path, "/dl/")] != nil:
			_, _ = w.Write(rel.files[strings.TrimPrefix(r.URL.Path, "/dl/")])
		case strings.HasPrefix(r.URL.Path, "/mirror/") && rel.mirror[strings.TrimPrefix(r.URL.Path, "/mirror/")] != nil:
			_, _ = w.Write(rel.mirror[strings.TrimPrefix(r.URL.Path, "/mirror/")])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	exe = filepath.Join(t.TempDir(), "cfprobe")
	if err := os.WriteFile(exe, []byte("old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldClient, oldExe, oldKey := updateClient, updateExecutable, updatePublicKey
	t.Cleanup(func() { updateClient, updateExecutable, updatePublicKey = oldClient, oldExe, oldKey })
	updateClient = srv.Client()
	updateExecutable = func() (string, error) { return exe, nil }
	updatePublicKey = base64.StdEncoding.EncodeToString(pub)
	return srv.URL, exe
}

func signed(t *testing.T, priv ed25519.PrivateKey, m releaseManifest) ([]byte, string) {
	t.Helper()
	raw, _ := json.MarshalIndent(m, "", "  ")
	return raw, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
}

func TestSelfUpdateInstallsOnlyASignedNewerMatchingRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, strangerKey, _ := ed25519.GenerateKey(rand.Reader)
	newBin := []byte("new binary")
	name := releaseFileName()
	good := releaseManifest{Seq: releaseSeq + 1, Files: map[string]string{name: sha(newBin)}}

	cases := []struct {
		name    string
		release func(hub string) *fakeRelease
		wantSeq int
		wantErr string
	}{
		{"a newer signed release is installed", func(string) *fakeRelease {
			raw, sig := signed(t, priv, good)
			return &fakeRelease{manifest: raw, sig: sig, files: map[string][]byte{name: newBin}}
		}, releaseSeq + 1, ""},
		{"a bad mirror is skipped for the next source", func(string) *fakeRelease {
			m := good
			m.Sources = []string{"MIRROR"} // replaced below with the fake hub's /mirror
			raw, sig := signed(t, priv, m)
			return &fakeRelease{manifest: raw, sig: sig, files: map[string][]byte{name: newBin}, mirror: map[string][]byte{name: []byte("tampered")}}
		}, releaseSeq + 1, ""},
		{"a manifest signed by another key is refused", func(string) *fakeRelease {
			raw, sig := signed(t, strangerKey, good)
			return &fakeRelease{manifest: raw, sig: sig, files: map[string][]byte{name: newBin}}
		}, 0, "signature is invalid"},
		{"a manifest edited after signing is refused", func(string) *fakeRelease {
			raw, sig := signed(t, priv, good)
			raw = []byte(strings.Replace(string(raw), sha(newBin), sha([]byte("evil")), 1))
			return &fakeRelease{manifest: raw, sig: sig, files: map[string][]byte{name: []byte("evil")}}
		}, 0, "signature is invalid"},
		{"an older or equal release is ignored (no rollback)", func(string) *fakeRelease {
			m := good
			m.Seq = releaseSeq
			raw, sig := signed(t, priv, m)
			return &fakeRelease{manifest: raw, sig: sig, files: map[string][]byte{name: newBin}}
		}, 0, ""},
		{"a binary that does not match the signed checksum is refused", func(string) *fakeRelease {
			raw, sig := signed(t, priv, good)
			return &fakeRelease{manifest: raw, sig: sig, files: map[string][]byte{name: []byte("tampered")}}
		}, 0, "no source gave the signed binary"},
		{"a release without this platform is refused", func(string) *fakeRelease {
			m := releaseManifest{Seq: releaseSeq + 1, Files: map[string]string{"cfprobe-plan9-mips": sha(newBin)}}
			raw, sig := signed(t, priv, m)
			return &fakeRelease{manifest: raw, sig: sig}
		}, 0, "has no " + name},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel := tc.release("")
			hub, exe := updateEnv(t, pub, rel)
			if strings.Contains(string(rel.manifest), `"MIRROR"`) {
				m := good
				m.Sources = []string{hub + "/mirror"}
				rel.manifest, rel.sig = signed(t, priv, m)
			}
			m, err := loadManifest(hub)
			seq := 0
			if err == nil {
				seq, err = selfUpdate(hub, m)
			}
			if seq != tc.wantSeq || (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("selfUpdate = %d, %v; want %d, error containing %q", seq, err, tc.wantSeq, tc.wantErr)
			}
			got, _ := os.ReadFile(exe)
			if want := map[bool]string{true: "new binary", false: "old binary"}[tc.wantSeq > 0]; string(got) != want {
				t.Fatalf("binary is %q, want %q", got, want)
			}
		})
	}
}

func TestThisBuildCarriesAReleaseKey(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString(releasePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		t.Fatalf("releasePublicKey is not a base64 ed25519 public key: %q", releasePublicKey)
	}
}
