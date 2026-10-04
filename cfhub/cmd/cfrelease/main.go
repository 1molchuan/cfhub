// cfrelease signs cfprobe releases for the volunteers' self-update (echprobe/selfupdate.go).
// Run it on the maintainer's own machine; the private key must never be copied to the hub.
//
//	cfrelease -genkey release.key          # once: prints the public key for releasePublicKey
//	cfrelease -key release.key -seq 3 -dist ./dist -sources https://mirror.example/cfprobe
//
// Signing writes dist/manifest.json (seq, sha256 of every cfprobe binary in dist, download sources)
// and dist/manifest.json.sig (base64 ed25519 signature over the exact manifest bytes). Copy the
// binaries and both files to the hub's dist directory; probers install a release only if its seq is
// above their own releaseSeq, so build the binaries with releaseSeq set to the same number.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var binaries = []string{
	"cfprobe-linux-amd64", "cfprobe-linux-arm64", "cfprobe-linux-arm", "cfprobe-linux-mips", "cfprobe-linux-mipsle",
	"cfprobe-darwin-amd64", "cfprobe-darwin-arm64", "cfprobe-windows-amd64.exe",
}

type manifest struct {
	Seq     int               `json:"seq"`
	Files   map[string]string `json:"files"`
	Sources []string          `json:"sources"`
	API     []string          `json:"api,omitempty"`
	API6    []string          `json:"api6,omitempty"`
}

func main() {
	genkey := flag.String("genkey", "", "write a new private key to this file and print its public key")
	keyFile := flag.String("key", "", "private key file (from -genkey)")
	seq := flag.Int("seq", 0, "release number; must equal releaseSeq in the binaries being released")
	dist := flag.String("dist", "", "directory holding the cfprobe binaries")
	sources := flag.String("sources", "", "comma-separated https base URLs serving the binaries (the hub's /dl is always tried last)")
	api := flag.String("api", "", "comma-separated https base URLs proxying the hub's /api/v1/probe/* (the hub itself is always tried last)")
	api6 := flag.String("api6", "", "comma-separated https base URLs of the probe API reachable over IPv6 through Cloudflare, used first by IPv6 runs so the hub sees the line's IPv6 address")
	flag.Parse()

	if *genkey != "" {
		if _, err := os.Stat(*genkey); err == nil {
			fail("%s exists; refusing to overwrite a release key", *genkey)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		check(err)
		check(os.WriteFile(*genkey, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600))
		fmt.Println(base64.StdEncoding.EncodeToString(pub))
		return
	}
	if *keyFile == "" || *seq < 1 || *dist == "" {
		fail("usage: cfrelease -key FILE -seq N -dist DIR [-sources URL,...]  |  cfrelease -genkey FILE")
	}
	raw, err := os.ReadFile(*keyFile)
	check(err)
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("%s is not a cfrelease key", *keyFile)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	m := manifest{Seq: *seq, Files: map[string]string{}, Sources: []string{}}
	for _, name := range binaries {
		body, err := os.ReadFile(filepath.Join(*dist, name))
		check(err)
		sum := sha256.Sum256(body)
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	m.Sources = httpsList(*sources)
	m.API = httpsList(*api)
	m.API6 = httpsList(*api6)
	body, err := json.MarshalIndent(m, "", "  ")
	check(err)
	body = append(body, '\n')
	sig := ed25519.Sign(priv, body)
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), body, sig) {
		fail("signature does not verify")
	}
	check(os.WriteFile(filepath.Join(*dist, "manifest.json"), body, 0o644))
	check(os.WriteFile(filepath.Join(*dist, "manifest.json.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644))
	names := make([]string, 0, len(m.Files))
	for name := range m.Files {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Printf("release %d signed by %s\n", m.Seq, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	for _, name := range names {
		fmt.Printf("  %s  %s\n", m.Files[name], name)
	}
}

// httpsList splits a comma-separated list of https base URLs, refusing anything else.
func httpsList(list string) []string {
	out := []string{}
	for _, s := range strings.Split(list, ",") {
		if s = strings.TrimRight(strings.TrimSpace(s), "/"); s != "" {
			if !strings.HasPrefix(s, "https://") {
				fail("%q is not an https URL", s)
			}
			out = append(out, s)
		}
	}
	return out
}

func check(err error) {
	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cfrelease: "+format+"\n", args...)
	os.Exit(1)
}
