package props

// Properties of the stream hold-back. Holdback decides how much of a fragment
// has to wait for the next one; what it promises is a range, a bound against
// the longest pseudonym of the table, and that it never cuts through a rune.
// stream.go is package main and out of reach, so the probe goes to
// mapping.Restorer, where the mechanism lives.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// holdbackSeeds is the corpus: whole pseudonyms, prefixes of them, the
// characters that decide a boundary, and multi-byte text around them. The
// shapes are assembled from their prefixes rather than written out, so
// nothing on the way to disk can turn one into something else.
func holdbackSeeds() []string {
	hex12 := strings.Repeat("ab", 6)
	host := "h-" + hex12
	domain := "d-" + hex12 + ".invalid"
	seeds := []string{
		"",
		" ",
		"abc",
		"ende ohne alles",
		"\xff\xfe",
		lab.V4(100, 64, 0, 1),
		lab.MAC(0x02, 0xab, 0xab, 0xab, 0xab, 0xab),
	}
	for _, p := range []string{host, domain} {
		seeds = append(seeds,
			p,
			p+" ",
			p+"x",
			"text "+p,
			"text "+p[:len(p)/2],
			p+p,
			"weiß "+p+" 漢字",
			p+"\n",
		)
	}
	return seeds
}

// The range, the bound and the rune boundary, over whatever the fuzzer sends.
//
// What is deliberately not asserted is that the emitted part has nothing
// pending of its own. It does not hold, and it does not have to: a walk that
// the bytes behind the cut decided reaches the end of the shortened text
// undecided once those bytes are gone. The stream never asks again about what
// it has emitted, so the case cannot arise there.
func FuzzPropsHoldbackBounds(f *testing.F) {
	for _, seed := range holdbackSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInput {
			return
		}
		tab, _ := fillTable(t)
		r := tab.Restorer()

		h := r.Holdback(text)
		if h < 0 || h > len(text) {
			t.Fatalf("Holdback(%q) = %d, outside 0..%d", text, h, len(text))
		}
		// The bound of MaxPseudonymLen holds for a text without pseudonyms
		// back to back; a random text may glue two, and then the run is
		// held whole. TestProps_HoldbackOverTableValues asserts the bound
		// over texts that cannot.

		head, tail := text[:len(text)-h], text[len(text)-h:]
		if utf8.ValidString(text) && (!utf8.ValidString(head) || !utf8.ValidString(tail)) {
			t.Errorf("Holdback(%q) = %d cut through a rune\n head: %q\n tail: %q", text, h, head, tail)
		}
		// The tail begins where a pseudonym could begin, so it is never a
		// tail of pure filler: something in the table starts with its first
		// byte.
		if h > 0 && r.Holdback(tail) != len(tail) {
			t.Errorf("the tail %q of %q is not pending on its own", tail, text)
		}
	})
}

// The same promises over the pseudonyms of a real table, so the corpus covers
// the shapes the generator actually produces even without -fuzz.
func TestProps_HoldbackOverTableValues(t *testing.T) {
	tab, ps := fillTable(t)
	r := tab.Restorer()
	var texts []string
	for _, p := range ps {
		texts = append(texts, p, p+"x", p+" ", "text "+p, p[:len(p)/2], "weiß "+p+" 漢字")
	}
	for _, text := range texts {
		h := r.Holdback(text)
		if h < 0 || h > len(text) {
			t.Errorf("Holdback(%q) = %d, outside 0..%d", text, h, len(text))
			continue
		}
		if max := tab.MaxPseudonymLen(); h > max {
			t.Errorf("Holdback(%q) = %d, above MaxPseudonymLen = %d", text, h, max)
		}
		if head := text[:len(text)-h]; !utf8.ValidString(head) {
			t.Errorf("Holdback(%q) = %d cut through a rune, emitted %q", text, h, head)
		}
	}
}
