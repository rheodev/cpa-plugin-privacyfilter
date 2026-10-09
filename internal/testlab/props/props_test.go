// Package props states the filter's invariants as properties over random
// input instead of chosen examples. Every target here is an ordinary test
// over its seed corpus and takes -fuzz for a longer run, so the suite stays
// fast while the same code can be driven for minutes on demand.
//
// The values that carry meaning are assembled at run time. Every file of this
// tree passes through the running filter on its way to disk, and a literal
// address or a literal token in pseudonym shape could arrive as something
// else; the plain words used as terms cannot.
package props

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// maxFuzzInput bounds the work of one iteration. Longer inputs cost run time
// without reaching states the short ones miss.
const maxFuzzInput = 2048

// The fixture terms, one per shape a pseudonym can take on the term layer.
// They are ordinary words, so nothing on the way to disk changes them.
const (
	termHost    = "zeus.lan"
	termDomain  = "beispiel.example"
	termSegment = "kunde-x"
	termPerson  = "Bertha Schmitt"
)

// fixtureTerms is the literal list the round-trip targets run against.
func fixtureTerms() []detect.Term {
	return []detect.Term{
		{Value: termHost, Kind: detect.KindHost},
		{Value: termDomain, Kind: detect.KindDomain},
		{Value: termSegment, Kind: detect.KindPathSegment},
		{Value: termPerson, Kind: detect.KindPerson},
	}
}

// fixturePatterns switches on the structural classes with a shape of their
// own. Every class of PatternsConfig is off by default, so the ones a target
// needs have to be named.
func fixturePatterns() detect.PatternsConfig {
	return detect.PatternsConfig{
		IPv4:        true,
		IPv6:        true,
		CIDR:        true,
		MAC:         true,
		Email:       true,
		UUID:        true,
		HexID:       true,
		Fingerprint: true,
	}
}

// rig is one generator with its table and one detector over it. The exclude
// is the table's own knowledge, the way the plugin wires it; without it a
// second forward pass would replace the pseudonyms of the first.
type rig struct {
	gen *pseudo.Generator
	tab *mapping.Table
	det detect.Detector
}

// newRig builds a rig whose layers are given in order of precedence.
func newRig(t *testing.T, layers ...detect.Detector) *rig {
	t.Helper()
	gen := lab.Gen()
	tab := mapping.NewTable(gen)
	return &rig{
		gen: gen,
		tab: tab,
		det: detect.NewComposite(tab.Knows, layers...),
	}
}

// termRig is the rig over the fixture term list alone.
func termRig(t *testing.T) *rig {
	t.Helper()
	return newRig(t, lab.Terms(t, fixtureTerms()...))
}

// patternRig is the rig over the structural layer alone.
func patternRig(t *testing.T) *rig {
	t.Helper()
	return newRig(t, lab.Patterns(t, fixturePatterns()))
}

// forwardOnce replaces and returns the result.
func (r *rig) forwardOnce(text string) string {
	return lab.Forward(text, r.det, r.tab)
}

// checkIdempotent asserts that a second forward pass over the replaced text
// changes nothing and that the detector finds nothing left in it.
func checkIdempotent(t *testing.T, r *rig, text, mid string) {
	t.Helper()
	if again := r.forwardOnce(mid); again != mid {
		t.Errorf("second forward pass changed the text\n in:    %q\n once:  %q\n twice: %q", text, mid, again)
	}
	if left := r.det.Scan(mid); len(left) > 0 {
		t.Errorf("forward left a detectable value in %q: %q of kind %s", mid, left[0].Value, left[0].Kind)
	}
}

// checkNoOriginals asserts that no value the forward pass replaced is
// reported again in its result. An occurrence the detector never reported is
// a different question and not this one.
func checkNoOriginals(t *testing.T, r *rig, text, mid string) {
	t.Helper()
	before := make(map[string]detect.Kind)
	for _, m := range r.det.Scan(text) {
		before[m.Value] = m.Kind
	}
	if len(before) == 0 {
		return
	}
	for _, m := range r.det.Scan(mid) {
		if kind, ok := before[m.Value]; ok {
			t.Errorf("forward left the original %q of kind %s in %q", m.Value, kind, mid)
		}
	}
}

// checkRoundTrip asserts that the return direction undoes the forward one.
//
// A text that already carries a pseudonym of this table cannot close the
// circle: the return pass resolves what the forward pass never replaced,
// and rightly so, since the table belongs to the conversation. The case is
// skipped here.
func checkRoundTrip(t *testing.T, r *rig, text, mid string) {
	t.Helper()
	if lab.Back(text, r.tab) != text {
		return
	}
	if out := lab.Back(mid, r.tab); out != text {
		t.Errorf("round trip changed the text\n in:  %q\n mid: %q\n out: %q", text, mid, out)
	}
}

// fillTable enters one value of every shape the return pass has to cope with
// and returns the table with its pseudonyms in the order of entry.
func fillTable(t *testing.T) (*mapping.Table, []string) {
	t.Helper()
	tab := lab.Table()
	values := []struct {
		kind  detect.Kind
		value string
	}{
		{detect.KindHost, termHost},
		{detect.KindDomain, termDomain},
		{detect.KindPathSegment, termSegment},
		{detect.KindPerson, termPerson},
		{detect.KindIPv4, lab.V4(10, 0, 0, 7)},
		{detect.KindMAC, lab.MAC(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01)},
		{detect.KindFileName, "bericht.pdf"},
		{detect.KindSecret, "geheimwort"},
	}
	ps := make([]string, 0, len(values))
	for _, v := range values {
		ps = append(ps, tab.Lookup(v.kind, v.value))
	}
	return tab, ps
}

// allKinds lists every declared kind, so a target can walk them all.
func allKinds() []detect.Kind {
	return []detect.Kind{
		detect.KindIPv4, detect.KindIPv6, detect.KindCIDR, detect.KindMAC,
		detect.KindEmail, detect.KindHost, detect.KindDomain,
		detect.KindPathSegment, detect.KindFileName, detect.KindPerson,
		detect.KindIBAN, detect.KindURL, detect.KindUUID, detect.KindHexID,
		detect.KindFingerprint, detect.KindSerial, detect.KindSecret,
	}
}

// textSeeds are the corpus every text-shaped target starts from: the edge
// cases the example probes of this lab turned up, plus the plain ones.
func textSeeds() []string {
	hex12 := strings.Repeat("ab", 6)
	return []string{
		"",
		" ",
		"ssh " + termHost,
		termHost + ":22 and " + termHost,
		"scan_" + lab.V4(10, 0, 0, 7) + ".log",
		lab.V4(100, 109, 108, 254),
		lab.V4(1, 2, 3, 4),
		lab.V4(10, 0, 0, 7) + "/24",
		lab.MAC(0x02, 0x42, 0xac, 0x11, 0x00, 0x02),
		lab.MAC(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01),
		"/mnt/" + termSegment + "/bericht.pdf",
		"mail an " + termPerson + " und " + termPerson,
		"kontakt@" + termDomain,
		pseudo.PrefixHost + hex12,
		pseudo.PrefixSecret + hex12,
		pseudo.PrefixDomain + hex12 + pseudo.SuffixDomain,
		"gruesse aus " + termHost + "\r\n",
		`{"host":"` + termHost + `"}`,
		strings.Repeat(termHost+" ", 8),
		"STRASSBURGER " + strings.ToUpper(termHost),
		"weiß " + termHost + " München",
		termHost + termHost,
		"x" + termHost + "y",
	}
}
