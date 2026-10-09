package basics

// Two questions of identity. First: person pseudonyms come from a fixed list
// of names, and a list is finite - what happens when a text carries more
// people than the list has names? A collision would map two people onto one
// name, and the return pass would put the wrong person back. Second: the salt
// comes from the session id, with the hash of the conversation head as the
// fallback. If that hash moves between requests, the same value gets two
// pseudonyms in one conversation.

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// More people than the name list holds.
func TestIdentity_PersonNameCollisions(t *testing.T) {
	t.Logf("the name pool holds %d names", len(pseudo.Names))
	g := gen(t)
	tab := mapping.NewTable(g)
	seen := make(map[string]string)
	n := len(pseudo.Names) * 2
	var collisions int
	for i := 0; i < n; i++ {
		person := fmt.Sprintf("Person Nummer %d", i)
		alias := tab.Lookup(detect.KindPerson, person)
		if prev, ok := seen[alias]; ok {
			collisions++
			if collisions < 4 {
				t.Errorf("%q and %q share the pseudonym %q", prev, person, alias)
			}
			continue
		}
		seen[alias] = person
	}
	t.Logf("%d people, %d distinct pseudonyms, %d collisions", n, len(seen), collisions)

	// Whatever the pool does, the table must stay a bijection: every
	// pseudonym resolves to the person it was made for.
	for alias, person := range seen {
		if got := back(alias, tab); got != person {
			t.Errorf("%q resolved to %q, not to %q", alias, got, person)
			break
		}
	}
}

// A name that is itself in the term list must not be handed out as a
// pseudonym, or the forward pass would replace its own output.
func TestIdentity_RenderersExcludingNames(t *testing.T) {
	excluded := []string{pseudo.Names[0], pseudo.Names[1]}
	rend, dropped := pseudo.RenderersExcludingNames(excluded)
	t.Logf("excluding %v dropped %v", excluded, dropped)
	g := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), rend)
	tab := mapping.NewTable(g)
	for i := 0; i < 200; i++ {
		alias := tab.Lookup(detect.KindPerson, fmt.Sprintf("Person %d", i))
		for _, ex := range excluded {
			if strings.EqualFold(alias, ex) || strings.Contains(alias, ex) {
				t.Fatalf("the excluded name %q was handed out as %q", ex, alias)
			}
		}
	}
}

// The salt has to be the same for every request of one conversation.
func TestIdentity_SessionSource(t *testing.T) {
	body := []byte(`{"model":"claude-opus-5","system":"gleich","messages":[{"role":"user","content":"eins"}]}`)
	later := []byte(`{"model":"claude-opus-5","system":"gleich","messages":[{"role":"user","content":"eins"},{"role":"assistant","content":"zwei"},{"role":"user","content":"drei"}]}`)

	h := http.Header{}
	h.Set(pseudo.SessionHeader, "session-abc")
	a := pseudo.IdentifySession(h, body)
	b := pseudo.IdentifySession(h, later)
	t.Logf("with header: %q/%v and %q/%v", a.ID, a.Source, b.ID, b.Source)
	if a.ID != b.ID {
		t.Errorf("the header did not decide: %q vs %q", a.ID, b.ID)
	}

	// Without the header the head hash has to carry the conversation, so it
	// must not move when the conversation grows.
	c := pseudo.IdentifySession(http.Header{}, body)
	d := pseudo.IdentifySession(http.Header{}, later)
	t.Logf("without header: %q/%v and %q/%v", c.ID, c.Source, d.ID, d.Source)
	if c.ID != d.ID {
		t.Errorf("the fallback moved as the conversation grew: %q vs %q", c.ID, d.ID)
		t.Logf("   -> the same value would get a second pseudonym mid-conversation")
	}
	if c.ID == a.ID {
		t.Errorf("header and fallback produced the same id, the source is not distinguishable")
	}

	// A different conversation must be a different session.
	other := []byte(`{"model":"claude-opus-5","system":"anders","messages":[{"role":"user","content":"eins"}]}`)
	if e := pseudo.IdentifySession(http.Header{}, other); e.ID == c.ID {
		t.Errorf("two conversations share a session id: %q", e.ID)
	}
	t.Logf("head hash of a short body: %q", pseudo.HeadHash(body))
}

// Hold-back must not cut a multi-byte character in half: the emitted part is
// encoded as a JSON string, and invalid UTF-8 becomes a replacement
// character there.
func TestIdentity_HoldbackKeepsCharactersWhole(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")
	r := tab.Restorer()

	texts := []string{
		"Grüße aus München",
		"ein Emoji 🎉 mittendrin",
		"gemischt: äöü 🎉 " + alias,
		"Text vor dem Ersatzwert " + alias[:5],
		"漢字とかな",
	}
	for _, text := range texts {
		h := r.Holdback(text)
		if h < 0 || h > len(text) {
			t.Errorf("%q: hold-back %d is out of range", text, h)
			continue
		}
		emit := text[:len(text)-h]
		if !utf8.ValidString(emit) {
			t.Errorf("%q: the emitted part is not valid UTF-8 (held back %d): %q", text, h, emit)
		}
		if !utf8.ValidString(text[len(text)-h:]) {
			t.Errorf("%q: the held back part is not valid UTF-8: %q", text, text[len(text)-h:])
		}
	}
}
