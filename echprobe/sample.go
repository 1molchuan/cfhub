package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
)

// sampleIPv4 draws n random addresses from IPv4 ranges, weighted by range size, at most one per /24
// and never a .0 or .255. The community preferred domains keep returning the same few hundred
// addresses; drawing from Cloudflare's own ranges finds IPs nobody publishes, and -history keeps
// re-testing the ones that pass. One per /24 spreads the draw over routes: within a /24 the path
// from a given network is almost always the same. Returns fewer than n when the ranges run out.
func sampleIPv4(cidrs []string, n int, rnd *rand.Rand) ([]string, error) {
	type block struct {
		base uint32
		size uint64
	}
	var blocks []block
	var total uint64
	for _, c := range cidrs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, err
		}
		ones, bits := network.Mask.Size()
		if bits != 32 {
			return nil, fmt.Errorf("%s: only IPv4 ranges can be sampled", c)
		}
		if ones < 8 {
			return nil, fmt.Errorf("%s: range too broad", c)
		}
		size := uint64(1) << (32 - ones)
		blocks = append(blocks, block{binary.BigEndian.Uint32(network.IP.To4()), size})
		total += size
	}
	if total == 0 || n <= 0 {
		return nil, nil
	}
	picked := map[uint32]bool{}
	var out []string
	for tries := 0; len(out) < n && tries < n*50; tries++ {
		r := uint64(rnd.Int63n(int64(total)))
		var addr uint32
		for _, b := range blocks {
			if r < b.size {
				addr = b.base + uint32(r)
				break
			}
			r -= b.size
		}
		if last := addr & 0xff; last == 0 || last == 255 || picked[addr>>8] {
			continue
		}
		picked[addr>>8] = true
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], addr)
		out = append(out, net.IP(ip[:]).String())
	}
	return out, nil
}
