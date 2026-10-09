package layers

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Merge is documented to give the earlier layer precedence over every later
// match it overlaps, whatever the lengths are. This probes the rule directly,
// with one match per layer and nothing else in play.
func TestLayers_MergeGivesTheEarlierLayerPrecedence(t *testing.T) {
	text := strings.Repeat("x", 40)
	cases := []struct {
		name         string
		early, late  [2]int
		wantEarlyWin bool
	}{
		{"later contains earlier", [2]int{17, 26}, [2]int{9, 26}, true},
		{"earlier contains later", [2]int{9, 26}, [2]int{17, 26}, true},
		{"same span", [2]int{9, 26}, [2]int{9, 26}, true},
		{"later starts before and ends inside", [2]int{17, 30}, [2]int{9, 20}, true},
		{"later starts inside and ends after", [2]int{9, 20}, [2]int{17, 30}, true},
		{"disjoint", [2]int{9, 16}, [2]int{17, 30}, false},
	}
	for _, tc := range cases {
		early := []detect.Match{{Start: tc.early[0], End: tc.early[1], Value: text[tc.early[0]:tc.early[1]], Kind: detect.KindHost, Source: "early"}}
		late := []detect.Match{{Start: tc.late[0], End: tc.late[1], Value: text[tc.late[0]:tc.late[1]], Kind: detect.KindEmail, Source: "late"}}
		got := detect.Merge(early, late)
		if tc.wantEarlyWin {
			if len(got) != 1 || got[0].Source != "early" {
				t.Errorf("%s: Merge = %s, want the early layer alone", tc.name, where(got))
			}
			continue
		}
		if len(got) != 2 {
			t.Errorf("%s: Merge = %s, want both", tc.name, where(got))
		}
	}
}
