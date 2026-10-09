package props

// Properties of the generator itself. The forward pass is only idempotent
// because Composite.Exclude recognises what the generator wrote, so every
// output of Pseudonym has to be accepted by IsPseudonym. The rest are the
// promises the package documentation makes: determinism, the length bound of
// MaxLen, and an output that reads the same in a text field and inside a
// partial_json fragment.

import (
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// shapeSeeds are the originals the corpus feeds to every kind: the forms the
// detectors produce plus a few that no detector would.
func shapeSeeds() []string {
	return []string{
		"zeus.lan",
		"beispiel.example",
		"kunde-x",
		"Bertha Schmitt",
		"bericht.pdf",
		"bericht.tar.gz",
		"archiv.SEHRLANGEENDUNG",
		lab.V4(10, 0, 0, 7),
		lab.V4(10, 0, 0, 0) + "/8",
		lab.V4(10, 0, 0, 0) + "/" + lab.V4(255, 255, 0, 0),
		lab.MAC(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01),
		"fd7a:115c:a1e0::1",
		"fd7a:115c:a1e0::/48",
		"DE02120300000000202051",
		"kein-format",
		".",
		"/",
		"ä",
		strings.Repeat("x", 200),
	}
}

// Everything the generator writes has to be recognised, reproducible, bounded
// and free of characters JSON escapes.
func FuzzPropsPseudonymShape(f *testing.F) {
	for _, value := range shapeSeeds() {
		for kindIndex := range allKinds() {
			f.Add(value, uint8(kindIndex), uint8(0))
		}
	}
	f.Fuzz(func(t *testing.T, value string, kindIndex, attempt uint8) {
		if value == "" || len(value) > 256 || !utf8.ValidString(value) {
			return
		}
		kinds := allKinds()
		kind := kinds[int(kindIndex)%len(kinds)]
		if kind == detect.KindCIDR {
			if _, err := netip.ParsePrefix(value); err != nil {
				// A cidr term whose value is no network renders to something
				// IsPseudonym does not know. TestProps_CidrTermWithoutAPrefix
				// holds that finding; skipping it here keeps this target
				// looking for others.
				return
			}
		}

		gen := lab.Gen()
		p := gen.Pseudonym(kind, value, int(attempt))
		if p == "" {
			t.Fatalf("Pseudonym(%s, %q, %d) is empty", kind, value, attempt)
		}
		if !gen.IsPseudonym(p) {
			t.Errorf("IsPseudonym rejects the generator's own output: kind %s, value %q, attempt %d gives %q",
				kind, value, attempt, p)
		}
		if again := gen.Pseudonym(kind, value, int(attempt)); again != p {
			t.Errorf("Pseudonym is not deterministic for kind %s, value %q: %q then %q", kind, value, p, again)
		}
		if len(p) > gen.MaxLen() {
			t.Errorf("pseudonym %q of kind %s is %d bytes, above MaxLen %d", p, kind, len(p), gen.MaxLen())
		}
		if i := strings.IndexAny(p, "\"\\\n\r\t"); i >= 0 {
			t.Errorf("pseudonym %q of kind %s holds a character JSON escapes at %d", p, kind, i)
		}
	})
}

// Two different values must not share a pseudonym inside one table. The table
// resolves a collision by raising the attempt, and both values have to resolve
// back to themselves afterwards.
func FuzzPropsTableSeparatesValues(f *testing.F) {
	f.Add("zeus.lan", "hera.lan", uint8(5))
	f.Add(lab.V4(10, 0, 0, 7), lab.V4(10, 0, 0, 8), uint8(0))
	f.Add("a", "b", uint8(9))
	f.Fuzz(func(t *testing.T, first, second string, kindIndex uint8) {
		if first == "" || second == "" || first == second {
			return
		}
		if len(first) > 128 || len(second) > 128 {
			return
		}
		if !utf8.ValidString(first) || !utf8.ValidString(second) {
			return
		}
		kinds := allKinds()
		kind := kinds[int(kindIndex)%len(kinds)]

		tab := lab.Table()
		a := tab.Lookup(kind, first)
		b := tab.Lookup(kind, second)
		if a == b {
			t.Errorf("the table gives %q and %q the same pseudonym %q under kind %s", first, second, a, kind)
		}
		if e, ok := tab.Original(a); !ok || e.Original != first {
			t.Errorf("the table does not resolve %q back to %q", a, first)
		}
		if e, ok := tab.Original(b); !ok || e.Original != second {
			t.Errorf("the table does not resolve %q back to %q", b, second)
		}
	})
}
