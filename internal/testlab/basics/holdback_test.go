package basics

// Probes for the streaming hold-back. stream.go itself is package main and
// cannot be imported, but the mechanism lives in mapping.Tail and is
// reachable from outside: push every fragment, deliver what comes back,
// flush when the block ends.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
)

func streamRestore(t *testing.T, chunks []string, r mapping.Restorer) string {
	t.Helper()
	var out strings.Builder
	tail := mapping.NewTail(r)
	for _, c := range chunks {
		emit, _ := tail.Push(c, false)
		if !utf8.ValidString(emit) {
			t.Errorf("hold-back split a UTF-8 sequence: emitted %q", emit)
		}
		out.WriteString(emit)
	}
	rest, _ := tail.Flush(false)
	out.WriteString(rest)
	return out.String()
}

// tableWithValues fills a table with several kinds and returns the aliases in
// the order the values were entered.
func tableWithValues(t *testing.T) (*mapping.Table, []string) {
	t.Helper()
	tab := newTable(t)
	vals := []struct {
		k detect.Kind
		v string
	}{
		{detect.KindHost, "zeus.lan"},
		{detect.KindHost, "hera.lan"},
		{detect.KindHost, "ares.lan"},
		{detect.KindPerson, "Bertha Schmitt"},
		{detect.KindEmail, "b.schmitt@beispiel.example"},
		{detect.KindDomain, "beispiel.example"},
		{detect.KindPathSegment, "kunde-x"},
		{detect.KindUUID, "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
	}
	var ps []string
	for _, v := range vals {
		p := tab.Lookup(v.k, v.v)
		if p == "" {
			t.Fatalf("empty pseudonym for %s %q", v.k, v.v)
		}
		ps = append(ps, p)
	}
	return tab, ps
}

// An encoded space between two directory pseudonyms, the way a Markdown
// link to a directory with a space in its name goes out, comes back whole
// wherever the stream cuts it, inside the "%20" included: the edge the
// tail remembers reaches back over the escape.
func TestHoldback_EncodedSpaceBetweenPseudonyms(t *testing.T) {
	tab := newTable(t)
	a := tab.Lookup(detect.KindPathSegment, "Kunden")
	b := tab.Lookup(detect.KindPathSegment, "Akten")
	text := "[x](../" + a + "%20" + b + "/notes.md)"
	want := "[x](../Kunden%20Akten/notes.md)"
	for cut := 1; cut < len(text); cut++ {
		if got := streamRestore(t, []string{text[:cut], text[cut:]}, tab.Restorer()); got != want {
			t.Errorf("cut at %d: %q, want %q", cut, got, want)
		}
	}
}

// Splitting anywhere must not change the result. This is the property the
// hold-back exists for. The cuts fall on rune boundaries, because every
// delta of an upstream is a JSON string of its own and never carries half a
// character; a cut inside a rune would measure the probe, not the plugin.
func TestHoldback_SplitAtEveryPosition(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()

	// Aliases back to back, so the tail of one can start another, and with
	// ordinary text around them.
	texts := []string{
		strings.Join(ps, ""),
		strings.Join(ps, " "),
		"Host " + ps[0] + ps[1] + " und " + ps[2] + ".",
		ps[3] + " schrieb an " + ps[4] + " über " + ps[5] + "/" + ps[6],
		"Ende mit einem vollständigen Wert: " + ps[7],
	}

	for _, text := range texts {
		want, _ := r.Restore(text, false)
		for i := 1; i < len(text); i++ {
			if !utf8.RuneStart(text[i]) {
				continue
			}
			got := streamRestore(t, []string{text[:i], text[i:]}, r)
			if got != want {
				t.Fatalf("split at %d of %q:\n got %q\nwant %q", i, text, got, want)
			}
		}
	}
}

// Three chunks, byte by byte, over a shorter text: the same property under
// more fragmentation.
func TestHoldback_ByteByByte(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	text := "a" + ps[0] + "b" + ps[1] + "c"
	want, _ := r.Restore(text, false)

	chunks := make([]string, 0, len(text))
	for i := 0; i < len(text); i++ {
		chunks = append(chunks, text[i:i+1])
	}
	if got := streamRestore(t, chunks, r); got != want {
		t.Errorf("byte-by-byte:\n got %q\nwant %q", got, want)
	}
}

// The hold-back must be bounded: it may never grow with the length of the
// text, or a stream would stall.
func TestHoldback_BoundedByLongestPseudonym(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	max := tab.MaxPseudonymLen()

	long := strings.Repeat("x", 5000) + " " + ps[0][:len(ps[0])-1]
	if h := r.Holdback(long); h >= max {
		t.Errorf("Holdback on a 5000 byte text = %d, must be below MaxPseudonymLen %d", h, max)
	}
	if h := r.Holdback(strings.Repeat("x", 5000) + " " + ps[0]); h > max {
		t.Errorf("Holdback behind a complete pseudonym = %d, must not exceed MaxPseudonymLen %d", h, max)
	}
	if h := r.Holdback(strings.Repeat("y", 5000)); h != 0 {
		t.Errorf("Holdback on text without any prefix = %d, want 0", h)
	}
}

// Multi-byte characters immediately before the hold-back window are where a
// naive byte count cuts a rune in half.
func TestHoldback_NeverSplitsRunes(t *testing.T) {
	tab, ps := tableWithValues(t)
	r := tab.Restorer()
	for _, tail := range []string{"", "ü", "äöü", "😀", "München"} {
		text := "Text " + tail + ps[0][:len(ps[0])-2]
		h := r.Holdback(text)
		emit := text[:len(text)-h]
		if !utf8.ValidString(emit) {
			t.Errorf("tail %q: emitted %q is not valid UTF-8", tail, emit)
		}
	}
}
