package main

// Shared fixture for the stream probes: one table filled the way the forward
// pass leaves it, and the yardstick every streamed run is measured against,
// namely the same text restored in one piece.

import (
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// fixture fills a table with several kinds and returns it together with the
// pseudonyms in the order the values went in. The table is complete before
// the first Restorer call, as the forward pass leaves it.
func fixture(t *testing.T) (*mapping.Table, []string) {
	t.Helper()
	tab := lab.Table()
	vals := []struct {
		k detect.Kind
		v string
	}{
		{detect.KindHost, "zeus.lan"},
		{detect.KindHost, "hera.lan"},
		// Assembled from pieces so no name in this file can be mistaken for
		// a pseudonym of the session it is written in.
		{detect.KindPerson, "Bert" + "ha Schmitt"},
		{detect.KindPathSegment, "kunde-x"},
		{detect.KindIPv4, lab.V4(192, 168, 17, 4)},
		{detect.KindMAC, lab.MAC(0xa4, 0xbb, 0x6d, 0x11, 0x22, 0x33)},
	}
	ps := make([]string, 0, len(vals))
	for _, v := range vals {
		p := tab.Lookup(v.k, v.v)
		if p == "" {
			t.Fatalf("empty pseudonym for kind %s", v.k)
		}
		ps = append(ps, p)
	}
	return tab, ps
}

// whole restores a text in one piece. Whatever the stream delivers has to
// equal this, whichever way the upstream cut the text.
func whole(r mapping.Restorer, text string) string {
	out, _ := r.Restore(text, false)
	return out
}

// splitSafe cuts s into pieces of about n bytes, always at a rune boundary.
// An upstream never splits a character across two deltas, because every
// fragment is a JSON string of its own, so a test that did would measure the
// test harness rather than the plugin.
func splitSafe(s string, n int) []string {
	var out []string
	for len(s) > 0 {
		i := n
		if i > len(s) {
			i = len(s)
		}
		for i < len(s) && !utf8.RuneStart(s[i]) {
			i++
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}

// deltaChunks turns a text into one chunk per fragment of about size bytes.
func deltaChunks(index int, text string, size int) [][]byte {
	pieces := splitSafe(text, size)
	out := make([][]byte, 0, len(pieces))
	for _, p := range pieces {
		out = append(out, evTextDelta(index, p))
	}
	return out
}
