package basics

// Unicode probes: normalisation, case folding and text that must survive
// untouched.

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Text in which nothing is to be replaced must come out byte for byte the
// same, whatever normalisation form it is written in.
func TestUnicode_TextWithoutMatchesIsUntouched(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	texts := []string{
		"Der Prüfbericht für Köln",
		"Der Prüfbericht für Köln", // same words, decomposed
		"Ünïcödé mit Emoji 😀 und ZWJ 👨‍👩‍👧",
		"gemischt: Müller und Müller nebeneinander",
	}
	for _, text := range texts {
		tab := newTable(t)
		if got := forward(text, d, tab); got != text {
			t.Errorf("text without matches was changed:\n got %q\nwant %q", got, text)
		}
	}
}

// A term entered precomposed, an occurrence written decomposed: the round
// trip must return the occurrence exactly as it was written, or the plugin
// silently rewrites the user's text.
func TestUnicode_DecomposedOccurrenceRoundTrip(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "Müller", Kind: detect.KindPerson})
	text := "Herr Müller ruft an" // decomposed
	tab := newTable(t)
	mid := forward(text, d, tab)
	got := back(mid, tab)
	switch {
	case got == text:
		t.Logf("decomposed occurrence returns unchanged")
	case got == "Herr Müller ruft an":
		t.Errorf("the round trip rewrote the spelling: %q became %q", text, got)
	default:
		t.Errorf("unexpected round trip result: %q", got)
	}
}

// German sharp s has no single-character upper case. A term matched with
// IgnoreCase does not see the SS spelling, which is how a name can slip past
// the list in an all-caps line.
func TestUnicode_SharpSCaseFolding(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "Straßburger", Kind: detect.KindPerson, IgnoreCase: true})
	for _, text := range []string{
		"Herr Straßburger",
		"Herr STRASSBURGER",
		"Herr straßburger",
	} {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if mid == text {
			t.Logf("NOT replaced: %q", text)
		} else {
			t.Logf("replaced: %q", text)
		}
	}
}

// A term that appears inside a longer word must not be replaced when word
// boundaries are on, and the surrounding word must survive intact.
func TestTerms_WordBoundaryWithUnicodeNeighbours(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "lan", Kind: detect.KindHost})
	cases := map[string]bool{ // text -> should be replaced
		"lan":       true,
		"plan":      false,
		"Planung":   false,
		"lan-party": true,
		"über-lan":  true,
		"lanÜber":   false,
		"lan_extra": true, // underscore is a boundary since 8436b9e
		"zeus.lan":  true,
		"élan":      false,
	}
	for text, wantReplaced := range cases {
		tab := newTable(t)
		mid := forward(text, d, tab)
		gotReplaced := mid != text
		if gotReplaced != wantReplaced {
			t.Errorf("%q: replaced = %v, want %v (got %q)", text, gotReplaced, wantReplaced, mid)
		}
		if got := back(mid, tab); got != text {
			t.Errorf("round trip of %q: got %q", text, got)
		}
	}
}
