package layers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// The identifying values of this package are assembled at run time from
// numbers, like lab.V4 and lab.MAC. Every file of this tree passes through
// the running filter on its way to disk, so a name written as a literal may
// arrive as something else, and the probe would no longer be what it claims
// to be.

// node builds a host name.
func node(n int) string { return fmt.Sprintf("nd%02dx", n) }

// dir builds a directory name that is on no preserve list, stands for no
// device and is not all digits.
func dir(n int) string { return fmt.Sprintf("kd%02dx", n) }

// zone builds a domain name with a single dot.
func zone(n int) string { return fmt.Sprintf("z%02dx.tl%02d", n, n) }

// local builds the local part of a mail address.
func local(n int) string { return fmt.Sprintf("p%02d.q%02d", n, n+1) }

// sep is the path separator, assembled at run time for the same reason: a
// path written as a literal is itself something the filter replaces, and the
// probe would no longer be the probe.
var sep = string(rune('/'))

// abs joins the segments into an absolute path.
func abs(segs ...string) string { return sep + strings.Join(segs, sep) }

// spans renders matches as "kind:value" for a compact comparison.
func spans(ms []detect.Match) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = string(m.Kind) + ":" + m.Value
	}
	return strings.Join(parts, " ")
}

// sources renders the detector names of the matches, in order.
func sources(ms []detect.Match) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = m.Source
	}
	return strings.Join(parts, " ")
}

// where renders source, kind and span of every match without its value. A
// value printed into a test log is restored on its way out of this machine,
// so a failure is described by its form, not by the text it found.
func where(ms []detect.Match) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = fmt.Sprintf("%s/%s[%d,%d)", m.Source, m.Kind, m.Start, m.End)
	}
	return strings.Join(parts, " ")
}

// checkDisjoint asserts the contract of Merge: the matches are sorted by
// Start, no two of them overlap, every span lies inside text and every Value
// is the text it claims to be. A splice over the result is only correct as
// long as all four hold.
func checkDisjoint(t *testing.T, text string, ms []detect.Match) {
	t.Helper()
	prev := 0
	for i, m := range ms {
		switch {
		case m.Start < 0 || m.End > len(text) || m.Start >= m.End:
			t.Fatalf("match %d has span [%d,%d) in a text of %d bytes", i, m.Start, m.End, len(text))
		case m.Start < prev:
			t.Fatalf("match %d starts at %d, inside the match before it that ends at %d", i, m.Start, prev)
		case text[m.Start:m.End] != m.Value:
			t.Fatalf("match %d has value %q, but text[%d:%d] is %q", i, m.Value, m.Start, m.End, text[m.Start:m.End])
		}
		prev = m.End
	}
}

// roundTrip runs text through the detector and back and returns what would
// leave the machine. The table is filled completely before the restorer is
// taken, which is what mapping.Table requires.
func roundTrip(t *testing.T, text string, d detect.Detector) string {
	t.Helper()
	tab := lab.Table()
	out := lab.Forward(text, d, tab)
	if back := lab.Back(out, tab); back != text {
		t.Fatalf("round trip returned %q, want %q", back, text)
	}
	return out
}

// fakeLayer reports fixed spans, so a test can arrange an overlap that no
// real detector produces.
type fakeLayer struct {
	name  string
	kind  detect.Kind
	spans [][2]int
}

func (f fakeLayer) Name() string { return f.name }

func (f fakeLayer) Scan(text string) []detect.Match {
	out := make([]detect.Match, 0, len(f.spans))
	for _, s := range f.spans {
		v := ""
		if s[0] >= 0 && s[0] < len(text) && s[0] < s[1] {
			v = text[s[0]:min(s[1], len(text))]
		}
		out = append(out, detect.Match{Start: s[0], End: s[1], Value: v, Kind: f.kind, Source: f.name})
	}
	return out
}
