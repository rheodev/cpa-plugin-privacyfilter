package basics

// The minimal form of the hold-back finding: a complete pseudonym at the end
// of a chunk, followed by a word character in the next one.

import (
	"testing"
)

func TestHoldback_CompletePseudonymAtChunkEnd(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	alias := ps[0]

	for _, next := range []string{"x", "1", "_", "h", alias} {
		text := alias + next
		whole, _ := r.Restore(text, false)
		streamed := streamRestore(t, []string{alias, next}, r)
		if streamed != whole {
			t.Errorf("chunk ends right after a pseudonym, next chunk starts with %q:\n streamed %q\n   whole %q",
				next, streamed, whole)
		}
	}
}

// The counterpart that must keep working: a delimiter in the next chunk means
// the pseudonym really did stand alone, so both ways must replace it.
func TestHoldback_DelimiterInNextChunk(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	alias := ps[0]

	for _, next := range []string{" ", ".", ",", ")", "\n", ""} {
		text := alias + next
		whole, _ := r.Restore(text, false)
		streamed := streamRestore(t, []string{alias, next}, r)
		if streamed != whole {
			t.Errorf("delimiter %q in the next chunk:\n streamed %q\n   whole %q", next, streamed, whole)
		}
		if whole == text {
			t.Errorf("pseudonym followed by delimiter %q was not restored at all: %q", next, whole)
		}
	}
}
