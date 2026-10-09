package basics

// Round-trip and boundary probes against the plugin's building blocks.
// Written outside the repository on purpose: nothing here touches the clone.
//
// The forward direction is rebuilt here the way the interceptor does it:
// scan, then splice pseudonyms in from the back, since Merge guarantees
// disjoint matches in ascending order.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

func newTable(t *testing.T) *mapping.Table {
	t.Helper()
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	return mapping.NewTable(gen)
}

func newTerms(t *testing.T, terms ...detect.Term) detect.Detector {
	t.Helper()
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: terms})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	return d
}

// forward mirrors the interceptor's outbound replacement.
func forward(text string, d detect.Detector, tab *mapping.Table) string {
	ms := d.Scan(text)
	var b strings.Builder
	last := 0
	for _, m := range ms {
		if m.Start < last {
			continue // defensive: overlapping matches would corrupt the splice
		}
		b.WriteString(text[last:m.Start])
		b.WriteString(tab.Lookup(m.Kind, m.Value))
		last = m.End
	}
	b.WriteString(text[last:])
	return b.String()
}

func back(text string, tab *mapping.Table) string {
	out, _ := tab.Restorer().Restore(text, false)
	return out
}

// A value must survive the full circle unchanged, whatever surrounds it.
func TestRoundTrip_SurroundingCharacters(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	surroundings := []string{
		"ssh zeus.lan",
		"ssh zeus.lan.",
		"(zeus.lan)",
		"\"zeus.lan\"",
		"'zeus.lan',",
		"zeus.lan:22",
		"[zeus.lan]",
		"<zeus.lan>",
		"ping zeus.lan; echo done",
		"zeus.lan\nzeus.lan\n",
		"—zeus.lan—",
		"zeus.lan/path",
		"http://zeus.lan/x?y=1",
		"zeus.lan, zeus.lan and zeus.lan",
	}
	for _, text := range surroundings {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if strings.Contains(mid, "zeus.lan") {
			t.Errorf("forward(%q) = %q: original survived", text, mid)
		}
		if got := back(mid, tab); got != text {
			t.Errorf("round trip of %q: got %q via %q", text, got, mid)
		}
	}
}

// Two passes over already pseudonymized text must change nothing. The
// comment on Match.excluded states this as a design goal.
func TestForward_SecondPassIsNoOp(t *testing.T) {
	d := newTerms(t,
		detect.Term{Value: "zeus.lan", Kind: detect.KindHost},
		detect.Term{Value: "Bertha Schmitt", Kind: detect.KindPerson},
	)
	tab := newTable(t)
	text := "Bertha Schmitt meldet zeus.lan als offline."
	once := forward(text, d, tab)
	twice := forward(once, d, tab)
	if once != twice {
		t.Errorf("second pass changed the text:\n first: %q\nsecond: %q", once, twice)
	}
	if got := back(twice, tab); got != text {
		t.Errorf("round trip after two passes: got %q, want %q", got, text)
	}
}

// Restoring twice must be the same as restoring once.
func TestRestore_Idempotent(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	tab := newTable(t)
	mid := forward("ssh zeus.lan", d, tab)
	one := back(mid, tab)
	two := back(one, tab)
	if one != two {
		t.Errorf("restore not idempotent: %q then %q", one, two)
	}
}

// A term that is a substring of a longer term must not break the longer one.
func TestRoundTrip_OverlappingTerms(t *testing.T) {
	d := newTerms(t,
		detect.Term{Value: "zeus", Kind: detect.KindHost},
		detect.Term{Value: "zeus.lan", Kind: detect.KindHost},
		detect.Term{Value: "zeus.lan.example", Kind: detect.KindHost},
	)
	for _, text := range []string{
		"zeus",
		"zeus.lan",
		"zeus.lan.example",
		"zeus and zeus.lan and zeus.lan.example",
	} {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if got := back(mid, tab); got != text {
			t.Errorf("round trip of %q: got %q via %q", text, got, mid)
		}
	}
}

// A literal term containing regex metacharacters must be treated literally.
func TestRoundTrip_RegexMetacharactersAreLiteral(t *testing.T) {
	values := []string{"a.b*c", "kunde(x)", "srv[01]", "a+b", "back\\slash", "q?uery", "^anchor$"}
	for _, v := range values {
		d := newTerms(t, detect.Term{Value: v, Kind: detect.KindPathSegment})
		tab := newTable(t)
		text := "vor " + v + " nach"
		mid := forward(text, d, tab)
		if strings.Contains(mid, v) {
			t.Errorf("term %q not replaced: %q", v, mid)
		}
		if got := back(mid, tab); got != text {
			t.Errorf("round trip of %q: got %q via %q", text, got, mid)
		}
	}
}

// Precomposed and decomposed spellings of the same name are different byte
// sequences. A term entered in one form does not match the other; the point
// of this test is to record which behaviour the plugin actually has.
func TestUnicode_NormalisationForms(t *testing.T) {
	const precomposed = "Müller" // U+00FC
	const decomposed = "Müller" // u + combining diaeresis
	d := newTerms(t, detect.Term{Value: precomposed, Kind: detect.KindPerson})

	tab := newTable(t)
	if mid := forward("Herr "+precomposed+" ruft an", d, tab); strings.Contains(mid, precomposed) {
		t.Errorf("precomposed form not replaced: %q", mid)
	}

	tab2 := newTable(t)
	mid := forward("Herr "+decomposed+" ruft an", d, tab2)
	if strings.Contains(mid, decomposed) {
		t.Logf("decomposed form IS replaced - normalisation happens somewhere")
	} else {
		t.Logf("decomposed form is NOT replaced - a name in NFD leaks past the term list")
	}
}

// The restorer must leave a token alone that merely looks like a pseudonym.
func TestRestore_UnknownShapePassesThrough(t *testing.T) {
	tab := newTable(t)
	tab.Lookup(detect.KindHost, "zeus.lan") // one real entry, so the table is not empty
	for _, text := range []string{
		"h-0123456789ab",
		"d-0123456789ab.invalid",
		"u-0123456789ab@d-0123456789ab.invalid",
		"f-0123456789ab.md",
	} {
		if got := back(text, tab); got != text {
			t.Errorf("Restore(%q) = %q, want unchanged", text, got)
		}
	}
}

// A person pseudonym is an ordinary name. If the model writes that name on
// its own account, the restorer cannot tell the difference and will turn it
// into someone else's name. This test documents the exposure.
func TestPerson_PseudonymCollidesWithOrdinaryText(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "Bertha Schmitt", Kind: detect.KindPerson})
	tab := newTable(t)
	mid := forward("Bertha Schmitt ruft an", d, tab)
	alias := strings.TrimSuffix(strings.TrimPrefix(mid, ""), " ruft an")
	if alias == "" {
		t.Fatalf("could not extract the alias from %q", mid)
	}
	// The model answers with a sentence of its own that happens to use the
	// very name the generator handed out.
	answer := "Ich habe " + alias + " nicht erreicht."
	restored := back(answer, tab)
	if strings.Contains(restored, "Bertha Schmitt") {
		t.Logf("EXPOSURE: an unrelated mention of %q was rewritten to the real name: %q", alias, restored)
	}
}
