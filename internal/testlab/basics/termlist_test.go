package basics

// The term list is the part a user edits by hand, so it is the part that
// arrives malformed. The loader itself lives in package main and cannot be
// imported here; what these tests show is what the detector does with a term
// once it has been loaded in a damaged shape, and how much of the original
// stays visible when that happens.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Short and common terms replace far more than intended. Nothing here is a
// defect of the code; it is what a user needs to be warned about.
func TestTerm_ShortAndCommonValues(t *testing.T) {
	cases := []struct {
		term string
		text string
	}{
		{"a", "das Paket a-b-c liegt im Archiv"},
		{"Neu", "Neuer Neubau in Neustadt, Neu angelegt"},
		{"Berg", "Bergsteiger am Berg, Bergbahn"},
		{"Muster", "Musterfirma, Muster, Mustermann"},
		{"IT", "IT-Abteilung, damit, IT"},
	}
	for _, c := range cases {
		d := newTerms(t, detect.Term{Value: c.term, Kind: detect.KindPerson})
		tab := newTable(t)
		mid := forward(c.text, d, tab)
		t.Logf("term %-8q %q\n   -> %q", c.term, c.text, mid)
		if got := back(mid, tab); got != c.text {
			t.Errorf("term %q broke the round trip:\n  in %q\n out %q", c.term, c.text, got)
		}
	}
}

// One term is a prefix of another. The longer match has to win, or the tail
// of the longer value is left in the text.
func TestTerm_PrefixRelation(t *testing.T) {
	d := newTerms(t,
		detect.Term{Value: "zeus", Kind: detect.KindHost},
		detect.Term{Value: "zeus.lan", Kind: detect.KindHost},
		detect.Term{Value: "zeus.lan.internal", Kind: detect.KindHost},
	)
	for _, text := range []string{"zeus", "zeus.lan", "zeus.lan.internal", "ssh zeus.lan.internal -p 22"} {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if strings.Contains(mid, "zeus") {
			t.Errorf("a longer term was cut short: %q -> %q", text, mid)
		}
		if got := back(mid, tab); got != text {
			t.Errorf("round trip:\n  in %q\n out %q", text, got)
		}
		t.Logf("%-28q -> %q", text, mid)
	}
}

// Degenerate entries must not hang the scanner or eat the text.
func TestTerm_EmptyAndWhitespace(t *testing.T) {
	for _, val := range []string{"", " ", "\t", "\n", "  \t "} {
		d, err := detect.NewTerms(detect.TermsConfig{
			WordBoundary: true,
			Terms:        []detect.Term{{Value: val, Kind: detect.KindPerson}},
		})
		if err != nil {
			t.Logf("term %q rejected at construction: %v", val, err)
			continue
		}
		tab := newTable(t)
		text := "ein gewöhnlicher Satz mit Leerzeichen"
		mid := forward(text, d, tab)
		if mid != text {
			t.Errorf("term %q rewrote ordinary text: %q", val, mid)
		} else {
			t.Logf("term %q accepted, no effect on the text", val)
		}
	}
}
