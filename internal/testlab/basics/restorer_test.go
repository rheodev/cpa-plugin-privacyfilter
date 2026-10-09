package basics

// Restorer() is a live handle: a row added after the first restore is seen
// by the next one, because the table belongs to the conversation and grows
// with every request while earlier answers may still be streaming. These
// tests hold that in place.

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// The production order: fill everything, then restore.
func TestRestorer_FillThenRestore(t *testing.T) {
	tab := newTable(t)
	values := []string{"one.lan", "two.lan", "three.lan", "four.lan"}
	var pseudos []string
	for _, v := range values {
		pseudos = append(pseudos, tab.Lookup(detect.KindHost, v))
	}
	for i, p := range pseudos {
		if got := back(p, tab); got != values[i] {
			t.Errorf("%q did not restore to %q, got %q", p, values[i], got)
		}
	}
	joined := pseudos[0] + " talks to " + pseudos[3]
	if got := back(joined, tab); got != "one.lan talks to four.lan" {
		t.Errorf("mixed text: %q", got)
	}
}

// An entry added after the first restore is seen by the next one.
func TestRestorer_LaterEntriesAreSeen(t *testing.T) {
	tab := newTable(t)
	first := tab.Lookup(detect.KindHost, "one.lan")
	if got := back(first, tab); got != "one.lan" {
		t.Fatalf("the first entry was not restored: %q", got)
	}
	second := tab.Lookup(detect.KindHost, "two.lan")
	if second == first {
		t.Fatalf("both values produced the same pseudonym %q", first)
	}
	if got := back(second, tab); got != "two.lan" {
		t.Fatalf("an entry added after the first restore stays a pseudonym: %q", got)
	}
}

// A restorer handle taken before the forward pass sees what the pass adds,
// which is the same property seen from the stream side: the stream state
// takes its handle at the header call and restores rows the next request
// of the conversation adds while it runs.
func TestRestorer_HandleTakenEarly(t *testing.T) {
	tab := newTable(t)
	r := tab.Restorer()
	if n := r.Holdback("text ending in h-0"); n != 0 {
		t.Fatalf("an empty table holds back %d bytes", n)
	}
	p := tab.Lookup(detect.KindHost, "alpha.lan")
	out, changed := r.Restore(p, false)
	if !changed || out != "alpha.lan" {
		t.Fatalf("the early handle does not see the later entry: %q", out)
	}
	if n := r.Holdback("text ending in " + p[:6]); n != 6 {
		t.Fatalf("Holdback = %d, want the six bytes of the prefix", n)
	}
}
