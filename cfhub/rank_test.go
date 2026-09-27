package main

import (
	"reflect"
	"testing"
)

// Same cases as test/scope-xclassify.test.ts "combining default pools from several probers": the
// operator pools must be voted exactly like the DoH's nationwide pool.
func TestCombineRankingsMatchesTheDoH(t *testing.T) {
	cases := []struct {
		name  string
		lists [][]string
		size  int
		want  []string
	}{
		{"every prober vouches, ordered by summed rank",
			[][]string{{"a", "b", "c", "d", "e", "x"}, {"c", "a", "y", "b", "d", "e"}}, 6,
			[]string{"a", "c", "b", "d", "e"}},
		{"just the two both vouch for",
			[][]string{{"a", "b", "x"}, {"b", "y", "a"}}, 6,
			[]string{"b", "a"}},
		{"interleave when they barely agree",
			[][]string{{"a", "b", "c"}, {"x", "y", "a"}}, 4,
			[]string{"a", "x", "b", "y"}},
		{"three probers: two of three, all three first",
			[][]string{
				{"1.0.1.1", "1.0.2.1", "1.0.3.1"},
				{"1.0.4.1", "1.0.1.1", "1.0.5.1", "1.0.2.1"},
				{"1.0.5.1", "1.0.4.1", "1.0.6.1", "1.0.2.1", "1.0.1.1"},
			}, 6,
			[]string{"1.0.1.1", "1.0.2.1", "1.0.4.1", "1.0.5.1"}},
		{"at most two per IPv4 /24",
			[][]string{
				{"172.64.229.1", "172.64.229.2", "172.64.229.3", "104.16.1.1", "104.16.2.1"},
				{"172.64.229.1", "172.64.229.2", "172.64.229.3", "104.16.1.1", "104.16.2.1"},
			}, 6,
			[]string{"172.64.229.1", "172.64.229.2", "104.16.1.1", "104.16.2.1"}},
		{"at most two per IPv6 /48",
			[][]string{
				{"2606:4700:57::1", "2606:4700:57::2", "2606:4700:57:1::3", "2a06:98c1:3100::1"},
				{"2606:4700:57::1", "2606:4700:57::2", "2606:4700:57:1::3", "2a06:98c1:3100::1"},
			}, 6,
			[]string{"2606:4700:57::1", "2606:4700:57::2", "2a06:98c1:3100::1"}},
		{"a single list is cut to size", [][]string{{"1", "2", "3"}, {}}, 2, []string{"1", "2"}},
		{"no lists", nil, 6, []string{}},
	}
	for _, tc := range cases {
		if got := combineRankings(tc.lists, tc.size); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Volunteer pools never fall back to interleaving: that would let one stranger fill half the pool.
func TestStrictConsensusPublishesOnlyMajorityAgreement(t *testing.T) {
	cases := []struct {
		name   string
		lists  [][]string
		owners []int64 // nil: every prober belongs to a different user
		want   []string
	}{
		{"disjoint lists publish nothing", [][]string{{"a", "b", "c"}, {"x", "y", "z"}}, nil, []string{}},
		{"one shared IP is below the minimum", [][]string{{"a", "b", "c"}, {"x", "y", "a"}}, nil, []string{}},
		{"one list alone publishes nothing", [][]string{{"a", "b"}}, nil, []string{}},
		{"two shared IPs are published", [][]string{{"a", "b", "x"}, {"b", "y", "a"}}, nil, []string{"b", "a"}},
		{"three probers: two of three is a majority", [][]string{{"a", "b"}, {"b", "a"}, {"q", "r"}}, nil, []string{"a", "b"}},
		// One person with several servers: their probers vote, but cannot publish an IP by themselves.
		{"one user's two servers alone publish nothing", [][]string{{"a", "b"}, {"b", "a"}}, []int64{1, 1}, []string{}},
		{"a majority made of one user's servers is not enough", [][]string{{"a", "b"}, {"a", "b"}, {"c", "d"}}, []int64{1, 1, 2}, []string{}},
		{"only IPs a second user also vouches for", [][]string{{"a", "b", "c"}, {"a", "b", "c"}, {"a", "b", "d"}}, []int64{1, 1, 2}, []string{"a", "b"}},
	}
	for _, tc := range cases {
		owners := tc.owners
		if owners == nil {
			for i := range tc.lists {
				owners = append(owners, int64(i+1))
			}
		}
		if got := strictConsensus(tc.lists, owners, 6); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
