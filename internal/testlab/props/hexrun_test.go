package props

// The boundary rule of the structural layer against runs that are longer than
// an address. hasTokenBoundaries asks whether a letter or a digit stands next
// to the match; the separator of the address itself, the dot and the colon,
// is not a letter and not a digit, so a window inside a longer run of octets
// or hex groups passed that test. The fuzzer found it in the round-trip
// target. The layer now looks one step further: a separator directly outside
// the window with a digit of the same run beyond it makes the window part of
// something longer, and it is not an address. The values here are built from
// numbers, so the shape is the same on every machine.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// dottedOctets joins n numbers below 256 with dots, the way an IPv4 address
// is written. Five of them are one more than any address has.
func dottedOctets(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("%d", 17+i)
	}
	return strings.Join(parts, ".")
}

// hexGroups joins n groups of width hex digits with colons, the way an IPv6
// address is written with four digits and a key fingerprint with two.
func hexGroups(n, width int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("%0*x", width, 0x11+i)
	}
	return strings.Join(parts, ":")
}

// A run that cannot be an address must not be reported as one.
func TestProps_AddressInsideALongerRun(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"five octets", dottedOctets(5)},
		{"six octets", dottedOctets(6)},
		{"nine hex groups", hexGroups(9, 4)},
		{"twelve hex groups", hexGroups(12, 4)},
		{"a fingerprint of twenty groups", hexGroups(20, 2)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := patternRig(t)
			hits := r.det.Scan(c.text)
			if len(hits) == 0 {
				return
			}
			kinds := make([]string, 0, len(hits))
			covered := 0
			for _, h := range hits {
				kinds = append(kinds, string(h.Kind))
				covered += h.Len()
			}
			t.Errorf("a run of %d bytes that is no address is reported as %d hit(s) of kind %s covering %d bytes",
				len(c.text), len(hits), strings.Join(kinds, ","), covered)
		})
	}
}

// The counter-probe: the lengths that are an address are matched whole, are
// replaced whole and come back.
func TestProps_AddressOfItsOwnLength(t *testing.T) {
	for _, text := range []string{dottedOctets(4), hexGroups(8, 4)} {
		r := patternRig(t)
		hits := r.det.Scan(text)
		if len(hits) != 1 || hits[0].Len() != len(text) {
			t.Errorf("%q was expected as one hit over the whole text, got %d hits", text, len(hits))
			continue
		}
		mid := r.forwardOnce(text)
		if left := r.det.Scan(mid); len(left) > 0 {
			t.Errorf("the forward pass leaves a value the detector reports again, kind %s", left[0].Kind)
		}
		if out := lab.Back(mid, r.tab); out != text {
			t.Errorf("round trip changed the text\n in: %q\n out: %q", text, out)
		}
	}
}

// What the layer makes of a fingerprint line is recorded rather than asserted:
// the round trip closes, so the user sees his line again; the model does not.
func TestProps_FingerprintShapedHexRun(t *testing.T) {
	for _, n := range []int{16, 20, 32} {
		text := hexGroups(n, 2)
		r := patternRig(t)
		mid := r.forwardOnce(text)

		kept := 0
		for _, g := range strings.Split(text, ":") {
			if strings.Contains(mid, g) {
				kept++
			}
		}
		t.Logf("%d groups of two digits: %d hits, %d groups left as they were, %d bytes in and %d out, round trip closes: %v",
			n, len(r.det.Scan(text)), kept, len(text), len(mid), lab.Back(mid, r.tab) == text)
	}
}
