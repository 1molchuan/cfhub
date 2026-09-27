package main

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Port of combineRankings in src/preferred.ts (the DoH's nationwide pool), so an operator pool is
// voted exactly like the pool it replaces. Keep the two in step: rank_test.go carries the same cases
// as test/scope-xclassify.test.ts.
const (
	maxPerBlock  = 2 // most addresses served from one /24 (IPv6: /48)
	minConsensus = 2 // below this many majority-vouched IPs, interleave the lists instead
)

// addressBlock mirrors the TS helper: "a.b.c" for IPv4, the first six bytes for IPv6, and the string
// itself for anything unparsable (test fixtures use letters).
func addressBlock(ip string) string {
	if strings.Contains(ip, ":") {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return ip
		}
		b := addr.As16()
		parts := make([]string, 6)
		for i := range parts {
			parts[i] = strconv.Itoa(int(b[i]))
		}
		return strings.Join(parts, ".")
	}
	if dot := strings.LastIndex(ip, "."); dot > 0 {
		return ip[:dot]
	}
	return ip
}

func nonEmptyLists(lists [][]string) [][]string {
	var out [][]string
	for _, list := range lists {
		if len(list) > 0 {
			out = append(out, list)
		}
	}
	return out
}

// combineRankings merges per-prober rankings (best first). An IP qualifies when a strict majority of
// non-empty lists vouch for it; more votes rank first, then the better average position, at most
// maxPerBlock per block. With too little agreement the lists are interleaved so each still counts.
func combineRankings(lists [][]string, size int) []string {
	nonEmpty := nonEmptyLists(lists)
	if len(nonEmpty) <= 1 {
		if len(nonEmpty) == 0 {
			return []string{}
		}
		return head(nonEmpty[0], size)
	}
	consensus := majorityConsensus(nonEmpty, nil)
	if len(consensus) >= minConsensus {
		return head(consensus, size)
	}
	interleaved := []string{}
	seen := map[string]bool{}
	for index := 0; len(interleaved) < size; index++ {
		any := false
		for _, list := range nonEmpty {
			if index >= len(list) {
				continue
			}
			any = true
			if ip := list[index]; !seen[ip] {
				seen[ip] = true
				interleaved = append(interleaved, ip)
			}
			if len(interleaved) >= size {
				break
			}
		}
		if !any {
			break
		}
	}
	return interleaved
}

// minBackers: every IP in a volunteer pool must be vouched for by probers of at least this many
// different users, so one person's servers cannot put an IP in by themselves, however many they run.
const minBackers = 2

// strictConsensus is the volunteer-pool vote over one list per prober (owners[i] is the user who runs
// prober i): only IPs a strict majority of probers vouches for AND probers of minBackers different
// users back, never the interleaving fallback. That fallback suits a few trusted probers, but with
// strangers it would let a single prober fill half the pool. Fewer than minConsensus agreed IPs → nothing.
func strictConsensus(lists [][]string, owners []int64, size int) []string {
	var nonEmpty [][]string
	backers := map[string]map[int64]bool{}
	for i, list := range lists {
		if len(list) == 0 {
			continue
		}
		nonEmpty = append(nonEmpty, list)
		for _, ip := range list {
			if backers[ip] == nil {
				backers[ip] = map[int64]bool{}
			}
			backers[ip][owners[i]] = true
		}
	}
	if len(nonEmpty) < 2 {
		return []string{}
	}
	consensus := majorityConsensus(nonEmpty, func(ip string) bool { return len(backers[ip]) >= minBackers })
	if len(consensus) < minConsensus {
		return []string{}
	}
	return head(consensus, size)
}

// majorityConsensus ranks the IPs a strict majority of (non-empty) lists vouch for and `keep` (if
// set) accepts, at most maxPerBlock per block.
func majorityConsensus(nonEmpty [][]string, keep func(ip string) bool) []string {
	needed := len(nonEmpty)/2 + 1
	type tally struct {
		ip        string
		votes     int
		positions int
	}
	var order []*tally // first-appearance order: the stable tie-break, like the TS Map
	byIP := map[string]*tally{}
	for _, list := range nonEmpty {
		for index, ip := range list {
			entry := byIP[ip]
			if entry == nil {
				entry = &tally{ip: ip}
				byIP[ip] = entry
				order = append(order, entry)
			}
			entry.votes++
			entry.positions += index
		}
	}
	var qualified []*tally
	for _, entry := range order {
		if entry.votes >= needed && (keep == nil || keep(entry.ip)) {
			qualified = append(qualified, entry)
		}
	}
	sort.SliceStable(qualified, func(i, j int) bool {
		a, b := qualified[i], qualified[j]
		if a.votes != b.votes {
			return a.votes > b.votes
		}
		return float64(a.positions)/float64(a.votes) < float64(b.positions)/float64(b.votes)
	})
	perBlock := map[string]int{}
	consensus := []string{}
	for _, entry := range qualified {
		key := addressBlock(entry.ip)
		used := perBlock[key]
		perBlock[key] = used + 1
		if used < maxPerBlock {
			consensus = append(consensus, entry.ip)
		}
	}
	return consensus
}

func head(list []string, size int) []string {
	if len(list) > size {
		list = list[:size]
	}
	return append([]string{}, list...)
}
