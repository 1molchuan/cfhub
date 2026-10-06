package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"sort"
	"time"
)

type poolKey struct {
	ISP    string
	Family int
}

type PoolIP struct {
	IP       string   `json:"ip"`
	MedianMS int      `json:"median_ms"`
	Votes    int      `json:"votes"`           // probers that vouch for it
	Users    int      `json:"users"`           // distinct users behind those probers
	Lines    []string `json:"lines,omitempty"` // nationwide pool: the lines whose pools include it
	voters   []int64  // user id per vouching prober, for the admin view only
}

// nationalISP keys the nationwide pool, combined from every mainland line's published pool (see
// national) and pushed to the DoH as "isp:national".
const nationalISP = "national"

// minNationalLines is how many lines need a published pool before the nationwide pool is published:
// a single line's pool is that line's, not a nationwide one.
const minNationalLines = 2

type Pool struct {
	ISP       string   `json:"isp"`
	Name      string   `json:"name"`
	Family    int      `json:"family"`
	IPs       []PoolIP `json:"ips"`
	Probers   int      `json:"probers"`
	Users     int      `json:"users"`
	MedianMS  int      `json:"median_ms"`
	Published bool     `json:"published"`
	Reason    string   `json:"reason,omitempty"`
	// tier is every consensus candidate in the line's fast tier, in rank order, not just the size
	// served: the nationwide pool looks for IPs several lines share in it, since lines rarely pick
	// the same six.
	tier []PoolIP
}

// maxProbersPerUser caps how many of one user's probers (distinct /24s) vote in one pool: more
// servers add weight to what others also found, but one person cannot outnumber everyone else.
const maxProbersPerUser = 5

func (p *Pool) addresses() []string {
	out := make([]string, len(p.IPs))
	for i, ip := range p.IPs {
		out[i] = ip.IP
	}
	return out
}

// fastTier is how much slower than a pool's fastest IP (by median handshake time) another IP may be
// and still be served. The DoH hands the pool out in rotation and browsers dial the first address,
// so every slow member sends its share of connections the slow way.
const fastTier = 1.3

// topUpLimit is how much slower than the fastest an IP topping a short pool up to minConsensus may be.
// None closer: the pool stays short and unpublished, and the DoH serves a wider pool instead of
// giving a 900 ms IP half the connections next to a 100 ms one.
const topUpLimit = 2.0

// fastest keeps, in order, the IPs within fastTier of the fastest median, topped up with the next
// ones in order within topUpLimit to at least minConsensus if it can, and at most size. Candidates
// come ranked by consensus, so a pool asked for more than size can still fill up with fast ones.
func fastest(ips []PoolIP, size int) []PoolIP {
	best := 0
	for _, ip := range ips {
		if ip.MedianMS > 0 && (best == 0 || ip.MedianMS < best) {
			best = ip.MedianMS
		}
	}
	kept := []PoolIP{}
	var rest []PoolIP
	for _, ip := range ips {
		if best == 0 || (ip.MedianMS > 0 && float64(ip.MedianMS) <= float64(best)*fastTier) {
			kept = append(kept, ip)
		} else {
			rest = append(rest, ip)
		}
	}
	for _, ip := range rest {
		if len(kept) >= minConsensus {
			break
		}
		if ip.MedianMS > 0 && float64(ip.MedianMS) <= float64(best)*topUpLimit {
			kept = append(kept, ip)
		}
	}
	if len(kept) > size {
		kept = kept[:size]
	}
	return kept
}

// seated picks at most size IPs of the tier, in its rank order, incumbents first: an IP the pool
// served last time keeps its seat while it is still in the fast tier, and only the seats left go to
// the others by rank. Without it the pool traded members whose medians differ by noise every few
// rounds (2026-10-06 review: 229-261 ms IPs swapped three times in 25 minutes), and each swap left
// DoH answers cached with the old pool. A much faster newcomer still gets in: it pushes the slow
// incumbents out of the fast tier.
func seated(tier []PoolIP, incumbents []string, size int) []PoolIP {
	chosen := map[string]bool{}
	for _, ip := range tier {
		if len(chosen) < size && slices.Contains(incumbents, ip.IP) {
			chosen[ip.IP] = true
		}
	}
	for _, ip := range tier {
		if len(chosen) < size {
			chosen[ip.IP] = true
		}
	}
	out := []PoolIP{}
	for _, ip := range tier {
		if chosen[ip.IP] {
			out = append(out, ip)
		}
	}
	return out
}

func median(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Clone(values)
	sort.Ints(sorted)
	return sorted[len(sorted)/2]
}

// aggregate turns recent reports (newest first) into one pool per (operator, family).
//
// Each prober votes: a prober is one /24 (IPv6 /48), and its newest report is its vote, whoever
// sent it, so many accounts on one line still count once. One person may run several servers, and
// each counts, but at most maxProbersPerUser per pool, and strictConsensus admits only IPs that
// probers of minBackers different users vouch for: a single person's servers can add weight to what
// others found, never publish an IP alone. A pool needs probers of at least `quorum` users.
// incumbents are the IPs each pool served last time (see seated).
func aggregate(reports []Report, quorum, size int, suspended map[string]bool, incumbents map[poolKey][]string) map[poolKey]*Pool {
	byKey := map[poolKey][]Report{}
	seenPrefix := map[poolKey]map[string]bool{}
	perUser := map[poolKey]map[int64]int{}
	for _, r := range reports {
		key := poolKey{r.ISP, r.Family}
		if seenPrefix[key] == nil {
			seenPrefix[key], perUser[key] = map[string]bool{}, map[int64]int{}
		}
		if seenPrefix[key][r.Prefix] || perUser[key][r.UserID] >= maxProbersPerUser {
			continue
		}
		seenPrefix[key][r.Prefix] = true
		perUser[key][r.UserID]++
		byKey[key] = append(byKey[key], r)
	}
	pools := map[poolKey]*Pool{}
	for key, list := range byKey {
		lists := make([][]string, len(list))
		owners := make([]int64, len(list))
		medians := map[string][]int{}
		voters := map[string][]int64{}
		for i, r := range list {
			owners[i] = r.UserID
			for _, ip := range r.IPs {
				lists[i] = append(lists[i], ip.IP)
				medians[ip.IP] = append(medians[ip.IP], ip.MedianMS)
				voters[ip.IP] = append(voters[ip.IP], r.UserID)
			}
		}
		users := len(perUser[key])
		pool := &Pool{ISP: key.ISP, Name: operatorNames[key.ISP], Family: key.Family, IPs: []PoolIP{}, Probers: len(list), Users: users}
		var candidates []PoolIP
		for _, ip := range strictConsensus(lists, owners, 2*size) {
			distinct := map[int64]bool{}
			for _, id := range voters[ip] {
				distinct[id] = true
			}
			candidates = append(candidates, PoolIP{IP: ip, MedianMS: median(medians[ip]), Votes: len(voters[ip]), Users: len(distinct), voters: voters[ip]})
		}
		pool.tier = fastest(candidates, len(candidates))
		pool.IPs = seated(pool.tier, incumbents[key], size)
		var poolMedians []int
		for _, ip := range pool.IPs {
			poolMedians = append(poolMedians, ip.MedianMS)
		}
		pool.MedianMS = median(poolMedians)
		switch {
		case key.ISP == "other":
			pool.Reason = "非三大运营商、教育网或国内云厂商的线路(境外、其他网络)不单独分池"
		case suspended[key.ISP]:
			pool.Reason = "管理员已暂停发布"
		case users < quorum:
			pool.Reason = fmt.Sprintf("需要至少 %d 个不同用户的探针(当前 %d 人、%d 台)", quorum, users, len(list))
		case len(pool.IPs) == 0:
			pool.Reason = fmt.Sprintf("探针之间没有至少 %d 个多数一致、且有 %d 人以上认可的 IP", minConsensus, minBackers)
		case len(pool.IPs) < minConsensus:
			pool.Reason = fmt.Sprintf("中位延迟不超过最快那个 %g 倍的 IP 不足 %d 个", topUpLimit, minConsensus)
		default:
			pool.Published = true
		}
		pools[key] = pool
	}
	for _, family := range []int{4, 6} {
		var lines []string
		users := map[int64]bool{}
		for _, isp := range operators {
			key := poolKey{isp, family}
			if p := pools[key]; p != nil && p.Published {
				lines = append(lines, isp)
				for id := range perUser[key] {
					users[id] = true
				}
			}
		}
		if len(lines) > 0 {
			pools[poolKey{nationalISP, family}] = national(pools, lines, family, size, len(users), suspended[nationalISP], incumbents[poolKey{nationalISP, family}])
		}
	}
	return pools
}

// national combines the published pools of the mainland lines (carriers, CERNET, domestic clouds; not
// "other") into one pool for clients on none of them, and for the address family a line lacks. Each
// line counts once however many probers it has, and only IPs in the fast tier of at least two lines
// are taken (each line's tier: its consensus candidates within fastTier of its own fastest, up to
// twice the pool size, as the six served rarely coincide across lines), those in the most lines
// first (then by average rank), at most maxPerBlock per /24. An IP only one line measured as fast
// says nothing about the others, and its clients are exactly the ones whose line is unknown
// (2026-10-06 review: unicom's and mobile's own picks were the slowest two on unicom). Too few
// shared IPs leave the pool unpublished, and the DoH falls back to its own probers' pool. Every
// input already passed its line's quorum and minBackers.
func national(pools map[poolKey]*Pool, lines []string, family, size, users int, suspended bool, incumbents []string) *Pool {
	pool := &Pool{ISP: nationalISP, Name: operatorNames[nationalISP], Family: family, IPs: []PoolIP{}, Users: users}
	type entry struct {
		lines   []string
		rankSum int
		medians []int
		votes   int
		voters  []int64
	}
	entries := map[string]*entry{}
	for _, isp := range lines {
		p := pools[poolKey{isp, family}]
		pool.Probers += p.Probers
		for rank, ip := range p.tier {
			e := entries[ip.IP]
			if e == nil {
				e = &entry{}
				entries[ip.IP] = e
			}
			e.lines = append(e.lines, isp)
			e.rankSum += rank
			e.medians = append(e.medians, ip.MedianMS)
			e.votes += ip.Votes
			e.voters = append(e.voters, ip.voters...)
		}
	}
	// No fast-tier cut here: each input is already within fastTier of its own line's fastest, and
	// medians measured on different lines are not comparable (one line's 600 ms can be its best).
	perBlock := map[string]int{}
	add := func(ip string) {
		if len(pool.IPs) >= size || slices.ContainsFunc(pool.IPs, func(p PoolIP) bool { return p.IP == ip }) || perBlock[addressBlock(ip)] >= maxPerBlock {
			return
		}
		perBlock[addressBlock(ip)]++
		e := entries[ip]
		distinct := map[int64]bool{}
		for _, id := range e.voters {
			distinct[id] = true
		}
		pool.IPs = append(pool.IPs, PoolIP{IP: ip, MedianMS: median(e.medians), Votes: e.votes, Users: len(distinct), Lines: e.lines, voters: e.voters})
	}
	var shared []string
	for ip, e := range entries {
		if len(e.lines) >= 2 {
			shared = append(shared, ip)
		}
	}
	sort.Slice(shared, func(i, j int) bool {
		a, b := entries[shared[i]], entries[shared[j]]
		if len(a.lines) != len(b.lines) {
			return len(a.lines) > len(b.lines)
		}
		if l, r := a.rankSum*len(b.lines), b.rankSum*len(a.lines); l != r {
			return l < r // lower average rank
		}
		return shared[i] < shared[j]
	})
	// Incumbents still shared keep their seats (see seated); the rest go by rank, shown in rank order.
	for _, ip := range shared {
		if slices.Contains(incumbents, ip) {
			add(ip)
		}
	}
	for _, ip := range shared {
		add(ip)
	}
	order := map[string]int{}
	for i, ip := range shared {
		order[ip] = i
	}
	sort.SliceStable(pool.IPs, func(i, j int) bool { return order[pool.IPs[i].IP] < order[pool.IPs[j].IP] })
	var poolMedians []int
	for _, ip := range pool.IPs {
		poolMedians = append(poolMedians, ip.MedianMS)
	}
	pool.MedianMS = median(poolMedians)
	switch {
	case suspended:
		pool.Reason = "管理员已暂停发布"
	case len(lines) < minNationalLines:
		pool.Reason = fmt.Sprintf("需要至少 %d 类线路的池已发布(当前 %d 类)", minNationalLines, len(lines))
	case len(pool.IPs) < minConsensus:
		pool.Reason = fmt.Sprintf("至少 2 类线路都认可的 IP 不足 %d 个", minConsensus)
	default:
		pool.Published = true
	}
	return pool
}

// pushPools sends each operator's published pool to the DoH, both families in one request (the DoH
// replaces the whole pool of a scope). Operators with nothing publishable are skipped; their DoH pool
// then expires on its own and clients fall back to the nationwide pool.
func pushPools(ctx context.Context, client *http.Client, url, token string, ttl int, pools map[poolKey]*Pool) error {
	var errs []error
	for _, isp := range append(slices.Clone(operators), nationalISP) {
		v4, v6 := pools[poolKey{isp, 4}], pools[poolKey{isp, 6}]
		body := map[string]any{"ttl": ttl, "source": "cfhub", "scope": "isp:" + isp, "ipv4": []string{}, "ipv6": []string{}}
		any := false
		if v4 != nil && v4.Published {
			body["ipv4"], any = v4.addresses(), true
		}
		if v6 != nil && v6.Published {
			body["ipv6"], any = v6.addresses(), true
		}
		if !any {
			continue
		}
		raw, _ := json.Marshal(body)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", isp, err))
			continue
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("%s: HTTP %d %s", isp, resp.StatusCode, bytes.TrimSpace(msg)))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("push to DoH: %v", errs)
	}
	return nil
}

// runAggregation recomputes every pool, publishes, and records history. Called on a timer; it is
// cheap and idempotent, and re-publishing every cycle is what re-seeds a freshly restarted DoH.
func (h *Hub) runAggregation(ctx context.Context) {
	h.aggMu.Lock()
	defer h.aggMu.Unlock()
	now := time.Now()
	// One query for the longer window; reports come newest first, so the voting window is a prefix.
	day, err := h.store.ActiveReports(now.Add(-max(h.cfg.ReportTTL, regionWindow)).Unix())
	if err != nil {
		log.Printf("aggregate: %v", err)
		return
	}
	cut := now.Add(-h.cfg.ReportTTL).Unix()
	reports := day[:sort.Search(len(day), func(i int) bool { return day[i].At < cut })]
	suspended := map[string]bool{}
	for _, isp := range append(slices.Clone(operators), nationalISP) {
		suspended[isp] = h.store.Setting("suspended:"+isp) == "1"
	}
	// What each pool served last (its newest history point, so it survives a restart).
	incumbents := map[poolKey][]string{}
	for _, isp := range append(slices.Clone(operators), nationalISP) {
		for _, family := range []int{4, 6} {
			if last, ok, err := h.store.LastHistory(isp, family); err == nil && ok {
				incumbents[poolKey{isp, family}] = last.IPs
			}
		}
	}
	pools := aggregate(reports, h.cfg.Quorum, h.cfg.PoolSize, suspended, incumbents)
	cut = now.Add(-regionWindow).Unix()
	regions := regionStats(day[:sort.Search(len(day), func(i int) bool { return day[i].At < cut })], h.region.Province)
	leaders, err := h.store.Leaders(now.Unix(), 50)
	if err != nil {
		log.Printf("leaders: %v", err)
	}
	h.mu.Lock()
	h.pools, h.regions, h.leaders, h.aggregatedAt = pools, regions, leaders, now.Unix()
	h.mu.Unlock()

	if h.cfg.HubToken != "" && h.cfg.DoHURL != "" {
		if err := pushPools(ctx, h.client, h.cfg.DoHURL, h.cfg.HubToken, h.cfg.PushTTL, pools); err != nil {
			log.Print(err)
		}
	}
	for key, pool := range pools {
		if !pool.Published {
			continue
		}
		last, ok, err := h.store.LastHistory(key.ISP, key.Family)
		if err != nil {
			continue
		}
		ips := pool.addresses()
		if ok && slices.Equal(last.IPs, ips) && now.Unix()-last.At < 3600 {
			continue // unchanged and recent: no new point
		}
		if err := h.store.InsertHistory(now.Unix(), key.ISP, key.Family, ips, pool.Probers, pool.MedianMS); err != nil {
			log.Printf("history: %v", err)
		}
	}
}

// snapshot returns the latest pools, sorted for display.
func (h *Hub) snapshot() ([]*Pool, int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Pool, 0, len(h.pools))
	for _, p := range h.pools {
		out = append(out, p)
	}
	rank := map[string]int{}
	for i, isp := range append(append([]string{nationalISP}, operators...), "other") {
		rank[isp] = i
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ISP != out[j].ISP {
			return rank[out[i].ISP] < rank[out[j].ISP]
		}
		return out[i].Family < out[j].Family
	})
	return out, h.aggregatedAt
}

func (h *Hub) pool(isp string, family int) *Pool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pools[poolKey{isp, family}]
}
