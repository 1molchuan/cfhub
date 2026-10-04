package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Volunteer self-update (-hub mode). A release is a manifest listing each platform binary's sha256,
// signed with an ed25519 key that never leaves the maintainer's own machine (cfhub/cmd/cfrelease).
// The hub only serves the manifest and binaries, so a compromised hub or mirror cannot push code:
// a binary is installed only if the manifest verifies against releasePublicKey below, its seq is
// higher than this build's releaseSeq (an old signed manifest cannot roll probers back), and the
// download matches the signed checksum. The running binary is replaced in place (it lives in the
// prober's own state directory); the new one takes effect at the next run. -no-update turns it off.

// releaseSeq is this build's release number. Bump it for every release, before building.
const releaseSeq = 10

// releasePublicKey verifies release manifests (base64, ed25519).
const releasePublicKey = "pZvca84iii/7oUhLtAuvGls4U5dNbh64pCqhJnDTZps="

var probeVersion = fmt.Sprintf("cfprobe/%d", releaseSeq)

type releaseManifest struct {
	Seq     int               `json:"seq"`
	Files   map[string]string `json:"files"`   // "cfprobe-linux-amd64" -> hex sha256
	Sources []string          `json:"sources"` // base URLs serving the files, tried in order
	// API lists base URLs that proxy the hub's /api/v1/probe/* (e.g. a CDN that mainland lines reach
	// better than the hub itself), tried in order before the hub. It comes from the signed manifest,
	// so a hub or mirror cannot redirect reports, and the route can change without a new binary.
	API []string `json:"api,omitempty"`
	// API6 lists base URLs of the probe API behind Cloudflare. An IPv6 run tries them first, connected
	// over IPv6 to Cloudflare addresses this line measured, so the hub sees the line's IPv6 address and
	// files the report under its IPv6 prefix and operator (the other routes are IPv4 only).
	API6 []string `json:"api6,omitempty"`
}

const maxReleaseBinary = 64 << 20

// releaseFileName is this platform's binary name in a release.
func releaseFileName() string {
	name := "cfprobe-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// Swapped by tests.
var (
	updateClient     = hubClient
	updateExecutable = os.Executable
	updatePublicKey  = releasePublicKey
)

// verifyManifest checks the signature over the exact manifest bytes and parses it.
func verifyManifest(raw, sig []byte, publicKey string) (releaseManifest, error) {
	var m releaseManifest
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return m, errors.New("no valid release public key in this build")
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), raw, signature) {
		return m, errors.New("release manifest signature is invalid")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("release manifest: %w", err)
	}
	return m, nil
}

func fetchLimited(url string, limit int64) ([]byte, error) {
	resp, err := updateClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return body, nil
}

// loadManifest fetches the hub's release manifest and verifies its signature.
func loadManifest(hub string) (releaseManifest, error) {
	raw, err := fetchLimited(hub+"/dl/manifest.json", 64<<10)
	if err != nil {
		return releaseManifest{}, err
	}
	sig, err := fetchLimited(hub+"/dl/manifest.json.sig", 4<<10)
	if err != nil {
		return releaseManifest{}, err
	}
	return verifyManifest(raw, sig, updatePublicKey)
}

// selfUpdate installs the release m describes if it is newer than this build. It returns the new seq
// when it replaced the binary, 0 otherwise. Errors are for logging only: the run goes on with this
// binary.
func selfUpdate(hub string, m releaseManifest) (int, error) {
	if m.Seq <= releaseSeq {
		return 0, nil // up to date (or an old manifest)
	}
	name := releaseFileName()
	want := strings.ToLower(m.Files[name])
	if len(want) != 64 {
		return 0, fmt.Errorf("release %d has no %s", m.Seq, name)
	}
	exe, err := updateExecutable()
	if err != nil {
		return 0, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return 0, err
	}
	var bin []byte
	var lastErr error
	for _, src := range append(m.Sources, hub+"/dl") {
		body, err := fetchLimited(strings.TrimRight(src, "/")+"/"+name, maxReleaseBinary)
		if err != nil {
			lastErr = err
			continue
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != want {
			lastErr = fmt.Errorf("%s/%s does not match the signed checksum", src, name)
			continue
		}
		bin = body
		break
	}
	if bin == nil {
		return 0, fmt.Errorf("release %d: no source gave the signed binary (last: %v)", m.Seq, lastErr)
	}
	if err := replaceExecutable(exe, bin); err != nil {
		return 0, err
	}
	return m.Seq, nil
}

// replaceExecutable swaps the file at exe for bin. The new file is written next to it and renamed
// into place; on Windows the running binary is moved aside first (it cannot be overwritten while it
// runs, but it can be renamed), and the leftover is removed on a later run.
func replaceExecutable(exe string, bin []byte) error {
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		old := exe + ".old"
		_ = os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, exe); err != nil {
			_ = os.Rename(old, exe)
			return err
		}
		return nil
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// cleanupOldExecutable removes the binary a previous Windows update moved aside.
func cleanupOldExecutable() {
	if exe, err := updateExecutable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
