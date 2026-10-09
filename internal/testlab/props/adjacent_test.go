package props

// Two matches that touch. The term layer delimits a literal against letters
// and digits, so a value whose edges are punctuation may stand directly
// against the next one: "[K1][K2]" is two hits with nothing between them. The
// forward pass writes two pseudonyms into that gap, and they do have letters
// and digits at their edges, so the second one continues the first as one
// token. The return pass restores a pseudonym only where it stands on its
// own, and refused such a run; it now takes a pseudonym that directly
// follows another as the plugin's own output and restores the run whole.
//
// The fuzzer found the shape in FuzzPropsRoundTripAnyTerm; the corpus entry
// under testdata holds its own counterexample. This file is the readable one.

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// Two codes in brackets, written back to back the way a table cell or a log
// line does.
func TestProps_TouchingTermsGlueTheirPseudonyms(t *testing.T) {
	terms := []detect.Term{
		{Value: "[K1]", Kind: detect.KindPathSegment},
		{Value: "[K2]", Kind: detect.KindPathSegment},
	}
	texts := []string{
		"[K1][K2]",
		"[K1][K1]",
		"zeile [K1][K2] ende",
	}
	for _, text := range texts {
		gen := lab.Gen()
		tab := mapping.NewTable(gen)
		r := &rig{
			gen: gen,
			tab: tab,
			det: detect.NewComposite(tab.Knows, lab.Terms(t, terms...)),
		}
		mid := r.forwardOnce(text)
		if mid == text {
			t.Errorf("the term layer did not match %q", text)
			continue
		}
		if out := lab.Back(mid, r.tab); out != text {
			t.Errorf("two touching pseudonyms do not both come back\n in:  %q\n mid: %q\n out: %q", text, mid, out)
		}
	}
}

// The counter-probe: one character between the two codes is enough, and both
// come back.
func TestProps_SeparatedTermsBothComeBack(t *testing.T) {
	terms := []detect.Term{
		{Value: "[K1]", Kind: detect.KindPathSegment},
		{Value: "[K2]", Kind: detect.KindPathSegment},
	}
	for _, text := range []string{"[K1] [K2]", "[K1],[K2]", "[K1]\n[K2]"} {
		gen := lab.Gen()
		tab := mapping.NewTable(gen)
		r := &rig{
			gen: gen,
			tab: tab,
			det: detect.NewComposite(tab.Knows, lab.Terms(t, terms...)),
		}
		mid := r.forwardOnce(text)
		if out := lab.Back(mid, r.tab); out != text {
			t.Errorf("round trip changed the text\n in:  %q\n mid: %q\n out: %q", text, mid, out)
		}
	}
}
