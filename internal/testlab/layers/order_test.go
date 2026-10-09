package layers

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Merge gives the layers a precedence: an earlier layer wins against every
// later match it overlaps. One exception is built in front of it: a later
// match that contains an earlier one whole is promoted and wins as a whole,
// so a term that names a part of a directory does not uncover the rest of
// it. A later match that merely crosses an earlier one still loses, see
// TestLayers_CrossingOverlapDropsTheLaterMatchWhole.
func TestLayers_EarlierLayerWinsOverTheLongerLaterMatch(t *testing.T) {
	host, rest := node(1), dir(2)
	segment := host + "-" + rest
	text := abs("mnt", segment, "data")

	terms := lab.Host(t, host)
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})

	if got := paths.Scan(text); spans(got) != string(detect.KindPathSegment)+":"+segment {
		t.Fatalf("path layer alone = %q, want the whole segment", spans(got))
	}

	c := detect.NewComposite(nil, terms, paths)
	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if spans(got) != string(detect.KindPathSegment)+":"+segment {
		t.Fatalf("composite = %q, want the containing segment promoted", spans(got))
	}
	out := roundTrip(t, text, c)
	if strings.Contains(out, rest) || strings.Contains(out, host) {
		t.Fatalf("a part of the segment leaves in the clear: %q", out)
	}
}

// Two layers that report exactly the same span: the earlier one decides the
// kind, and with it the shape of the pseudonym. A host inside a path is
// therefore rendered as a host when it is on the term list and as a path
// segment when it is not, and the two are different pseudonyms for the same
// machine.
func TestLayers_SameSpanTakesTheKindOfTheEarlierLayer(t *testing.T) {
	host := node(3)
	text := abs("mnt", host, "data")
	terms := lab.Host(t, host)
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})

	first := detect.NewComposite(nil, terms, paths).Scan(text)
	second := detect.NewComposite(nil, paths, terms).Scan(text)
	checkDisjoint(t, text, first)
	checkDisjoint(t, text, second)
	if len(first) != 1 || first[0].Kind != detect.KindHost || first[0].Source != "terms" {
		t.Fatalf("term layer first = %q from %q", spans(first), sources(first))
	}
	if len(second) != 1 || second[0].Kind != detect.KindPathSegment || second[0].Source != "paths" {
		t.Fatalf("path layer first = %q from %q", spans(second), sources(second))
	}

	g := lab.Gen()
	asHost := g.Pseudonym(detect.KindHost, host, 0)
	asSegment := g.Pseudonym(detect.KindPathSegment, host, 0)
	if asHost == asSegment {
		t.Fatalf("both kinds render %q as %q", host, asHost)
	}
	t.Logf("layer order decides the shape: %q as a term, %q through the path layer", asHost, asSegment)
}

// A later match that only crosses an accepted one is dropped whole, not
// truncated to its free part. The splice depends on it: a truncated span
// would no longer be the value it carries.
func TestLayers_CrossingOverlapDropsTheLaterMatchWhole(t *testing.T) {
	// Six four-letter tokens separated by blanks, so every span below ends
	// on a token boundary and the restorer accepts it.
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = strings.Repeat(string(rune('a'+i)), 4)
	}
	text := strings.Join(parts, " ")

	early := fakeLayer{"early", detect.KindHost, [][2]int{{5, 14}}}
	late := fakeLayer{"late", detect.KindPathSegment, [][2]int{{10, 19}, {25, 29}}}
	c := detect.NewComposite(nil, early, late)

	got := c.Scan(text)
	checkDisjoint(t, text, got)
	want := string(detect.KindHost) + ":" + text[5:14] + " " + string(detect.KindPathSegment) + ":" + text[25:29]
	if spans(got) != want {
		t.Fatalf("composite = %q, want %q", spans(got), want)
	}
	if out := roundTrip(t, text, c); strings.Contains(out, text[10:19]) {
		t.Fatalf("forward = %q, the crossing match must not be spliced", out)
	}
}

// Merge has two strategies for the same rule and switches between them at 64
// candidates. Both must accept the same hits, or a long log would be
// filtered differently from a short one. The host stands as a segment of
// its own here, so the term hit and the path hit cover the same span and
// the earlier layer decides.
func TestLayers_PrecedenceHoldsAcrossTheBitsetThreshold(t *testing.T) {
	host := node(4)
	unit := abs("mnt", host, "data") + " "
	terms := lab.Host(t, host)
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})
	c := detect.NewComposite(nil, terms, paths)

	for _, n := range []int{10, 40} {
		text := strings.Repeat(unit, n)
		got := c.Scan(text)
		checkDisjoint(t, text, got)
		if len(got) != n {
			t.Fatalf("n=%d: %d matches, want %d", n, len(got), n)
		}
		for i, m := range got {
			if m.Value != host || m.Source != "terms" {
				t.Fatalf("n=%d: match %d is %q from %q, want the term hit", n, i, m.Value, m.Source)
			}
		}
		roundTrip(t, text, c)
	}
}

// A nil layer is skipped without taking a rank with it, so the precedence of
// the remaining layers is the order in which they were given.
func TestLayers_NilLayerKeepsThePrecedence(t *testing.T) {
	host := node(6)
	text := abs("mnt", host, "data")
	terms := lab.Host(t, host)
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})

	c := detect.NewComposite(nil, nil, terms, nil, paths, nil)
	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if len(got) != 1 || got[0].Kind != detect.KindHost {
		t.Fatalf("composite with nil layers = %q from %q", spans(got), sources(got))
	}
}

// Merge trusts its detectors. The Scan contract says a span lies inside the
// text, and nothing checks it, so a layer with a wrong span reaches the
// splice instead of being dropped. No detector of the plugin does this; it
// is a note for whoever writes the next one.
func TestLayers_SpanOutsideTheTextIsNotRejected(t *testing.T) {
	text := strings.Repeat("a", 8)
	bad := fakeLayer{"bad", detect.KindHost, [][2]int{{1, len(text) + 40}}}

	got := detect.NewComposite(nil, bad).Scan(text)
	if len(got) != 1 || got[0].End <= len(text) {
		t.Fatalf("Scan = %+v, want the out-of-range span passed through", got)
	}
	panicked := func() (p bool) {
		defer func() { p = recover() != nil }()
		lab.Forward(text, detect.NewComposite(nil, bad), lab.Table())
		return
	}()
	t.Logf("span [%d,%d) in a text of %d bytes survives Merge, and the splice over it panics: %v",
		got[0].Start, got[0].End, len(text), panicked)
}
