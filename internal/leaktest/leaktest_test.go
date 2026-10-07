// Package leaktest composes the public contracts of detect, pseudo, mapping
// and payload into the forward pass and checks the properties the plan
// demands of it: no corpus value leaves, the result is deterministic, a
// second pass changes nothing, the salt is stable within a conversation and
// differs between two, and denied fields are untouched. The interceptor in
// package main is expected to compose the packages exactly this way; this
// test is the reference for that wiring.
package leaktest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

type pipeline struct {
	det   detect.Detector
	gen   *pseudo.Generator
	table *mapping.Table
	out   []byte
}

// store keeps one table per conversation across the forward passes of this
// package, as the plugin's store does.
var store = mapping.NewStore(mapping.StoreConfig{})

// forward runs the complete forward pass for one request body.
func forward(t *testing.T, headers http.Header, body []byte) pipeline {
	t.Helper()
	session := pseudo.IdentifySession(headers, body)
	gen := pseudo.NewGenerator(fixtures.Secret, pseudo.DeriveSalt(fixtures.Secret, session.ID), nil)
	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}

	terms, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: fixtures.DetectTerms()})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	patterns, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true, MAC: true, Email: true, IBAN: true, UUID: true, HexID: true, Fingerprint: true, Serial: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	// The shipped rule set, so this reference wiring is as strict as the
	// plugin's own; filter.New("", filter.Config{}) would fall back to a smaller built-in set.
	f, err := filter.New("../../rules/gitleaks.toml", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New: %v", err)
	}
	// The strongest setting: file names are replaced too, so the fixture's
	// file name must not survive either.
	paths, err := detect.NewPaths(detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	if err != nil {
		t.Fatalf("NewPaths: %v", err)
	}
	table := store.Open(session.ID, gen)
	det := detect.NewComposite(table.Knows, terms, patterns, detect.NewPackyme(f, detect.PackymeConfig{IPv4: true, IPv6: true, Email: true}), paths)

	out, _, err := payload.Walk(body, payload.WalkOptions{}, func(p payload.Path, text string) (string, bool) {
		matches := det.Scan(text)
		if len(matches) == 0 {
			return text, false
		}
		var b strings.Builder
		prev := 0
		for _, m := range matches {
			b.WriteString(text[prev:m.Start])
			b.WriteString(table.Lookup(m.Kind, m.Value))
			prev = m.End
		}
		b.WriteString(text[prev:])
		return b.String(), true
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return pipeline{det: det, gen: gen, table: table, out: out}
}

func request(t *testing.T, session string) []byte {
	t.Helper()
	b, err := json.Marshal(fixtures.Request(session))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// visitedStrings returns every string of body that the deny list lets the
// forward pass see, decoded. Denied fields (thinking blocks, ids, signatures)
// are passed through by contract; a corpus value there is not a leak of the
// forward pass but a property of the fixture.
func visitedStrings(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	if _, _, err := payload.Walk(body, payload.WalkOptions{}, func(_ payload.Path, v string) (string, bool) {
		out = append(out, v)
		return v, false
	}); err != nil {
		t.Fatalf("Walk over output: %v", err)
	}
	return out
}

// containsTerm applies the same rule the term layer applies: a plain
// substring for exact terms, a case-insensitive whole word for IgnoreCase
// terms, so "Markusplatz" does not count as the person "markus".
func containsTerm(hay string, term fixtures.Term) bool {
	if !term.IgnoreCase {
		return strings.Contains(hay, term.Value)
	}
	h := strings.ToLower(hay)
	n := strings.ToLower(term.Value)
	for off := 0; off <= len(h); {
		i := strings.Index(h[off:], n)
		if i < 0 {
			return false
		}
		s, e := off+i, off+i+len(n)
		before, _ := utf8.DecodeLastRuneInString(h[:s])
		after, _ := utf8.DecodeRuneInString(h[e:])
		if (s == 0 || !isWordRune(before)) && (e == len(h) || !isWordRune(after)) {
			return true
		}
		off = s + 1
	}
	return false
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// TestNoCorpusValueLeaks is the leak test of the plan: no value of the
// corpus may appear in any string of the outgoing body that the forward pass
// is allowed to rewrite.
func TestNoCorpusValueLeaks(t *testing.T) {
	body := request(t, fixtures.SessionA)
	p := forward(t, nil, body)
	strs := visitedStrings(t, p.out)
	if len(strs) < 6 {
		t.Fatalf("only %d visited strings in output, fixture or deny list broken", len(strs))
	}
	for _, term := range fixtures.All() {
		for _, s := range strs {
			if containsTerm(s, term) {
				t.Errorf("%s %q leaked in %q", term.Kind, term.Value, s)
				break
			}
		}
	}
	// Person, hosts and addresses inside the system prompt and tool
	// description must be gone too; those fields the original never saw.
	for _, s := range []string{"Markus Wendler", "athene.lan", "10.13.0.0/16", "helios-nas-01"} {
		if bytes.Contains(p.out, []byte(s)) {
			t.Errorf("%q survived in system prompt or tool description", s)
		}
	}
	if !json.Valid(p.out) {
		t.Fatal("output is not valid JSON")
	}
}

// TestDeniedFieldsUntouched: thinking blocks, signature, ids, tool names,
// metadata and the benign text come out byte for byte.
func TestDeniedFieldsUntouched(t *testing.T) {
	req := fixtures.Request(fixtures.SessionA)
	thinking := req["messages"].([]any)[1].(map[string]any)["content"].([]any)[0].(map[string]any)["thinking"].(string)
	if !strings.Contains(thinking, "10.13.7.42") {
		t.Fatal("fixture thinking block must carry an address to prove it is passed through")
	}
	thinkingJSON, _ := json.Marshal(thinking)
	p := forward(t, nil, request(t, fixtures.SessionA))
	for _, s := range []string{
		`"thinking":` + string(thinkingJSON),
		`"signature":"` + fixtures.ThinkingSignature + `"`,
		`"id":"` + fixtures.ToolUseID + `"`,
		`"tool_use_id":"` + fixtures.ToolUseID + `"`,
		`"name":"Bash"`,
		`"user_id":"` + fixtures.UserIDFor(fixtures.SessionA) + `"`,
		`"model":"claude-fable-5-1"`,
	} {
		if !bytes.Contains(p.out, []byte(s)) {
			t.Errorf("denied field changed or lost: %s", s)
		}
	}
	benign, _ := json.Marshal(fixtures.Benign)
	if !bytes.Contains(p.out, benign) {
		t.Errorf("benign text changed:\n%s", p.out)
	}
}

// TestDeterministic: the same body twice gives byte-identical output.
func TestDeterministic(t *testing.T) {
	body := request(t, fixtures.SessionA)
	a := forward(t, nil, body)
	b := forward(t, nil, body)
	if !bytes.Equal(a.out, b.out) {
		t.Fatal("two forward passes over the same body differ")
	}
}

// TestIdempotent: running the forward pass over its own output changes
// nothing; the pseudonyms of the conversation's table are excluded from
// detection, and the second pass adds no row.
func TestIdempotent(t *testing.T) {
	first := forward(t, nil, request(t, fixtures.SessionA))
	rows := first.table.Len()
	second := forward(t, nil, first.out)
	if !bytes.Equal(first.out, second.out) {
		t.Fatal("forward pass over its own output is not a no-op")
	}
	if second.table != first.table {
		t.Fatal("the second pass of the conversation got another table")
	}
	if second.table.Len() != rows {
		t.Fatalf("second pass grew the table from %d to %d entries", rows, second.table.Len())
	}
}

// TestSaltStableWithinConversation: a later turn of the same conversation
// maps the same values to the same pseudonyms, via header and via
// metadata.user_id; a different conversation maps them differently.
func TestSaltStableWithinConversation(t *testing.T) {
	turn1 := forward(t, nil, request(t, fixtures.SessionA))
	later := fixtures.Request(fixtures.SessionA)
	later["messages"] = append(later["messages"].([]any), map[string]any{"role": "user", "content": "und jetzt helios-nas-01 neu starten"})
	laterBody, _ := json.Marshal(later)
	turn2 := forward(t, nil, laterBody)
	for _, e := range turn1.table.Entries() {
		if got := turn2.table.Lookup(e.Kind, e.Original); got != e.Pseudonym {
			t.Errorf("%s %q: %q in turn 1, %q in turn 2", e.Kind, e.Original, e.Pseudonym, got)
		}
	}

	h := http.Header{}
	h.Set(pseudo.SessionHeader, fixtures.SessionA)
	viaHeader := forward(t, h, request(t, ""))
	for _, e := range turn1.table.Entries() {
		if got := viaHeader.table.Lookup(e.Kind, e.Original); got != e.Pseudonym {
			t.Errorf("%s %q: header session gives %q, metadata session gave %q", e.Kind, e.Original, got, e.Pseudonym)
		}
	}

	other := forward(t, nil, request(t, fixtures.SessionB))
	same := 0
	for _, e := range turn1.table.Entries() {
		if other.table.Lookup(e.Kind, e.Original) == e.Pseudonym {
			same++
		}
	}
	if same != 0 {
		t.Fatalf("%d pseudonyms identical across two conversations", same)
	}
}

// TestFallbackSaltStable: without any session identifier, the head hash
// keeps the salt stable across turns and changes it when the first user
// message changes.
func TestFallbackSaltStable(t *testing.T) {
	a := forward(t, nil, request(t, ""))
	later := fixtures.Request("")
	later["messages"] = append(later["messages"].([]any), map[string]any{"role": "assistant", "content": "ok"})
	laterBody, _ := json.Marshal(later)
	b := forward(t, nil, laterBody)
	for _, e := range a.table.Entries() {
		if got := b.table.Lookup(e.Kind, e.Original); got != e.Pseudonym {
			t.Errorf("%s %q changed across turns under the fallback salt", e.Kind, e.Original)
		}
	}
	other := fixtures.Request("")
	other["messages"].([]any)[0] = map[string]any{"role": "user", "content": "Ganz anderes Gespräch über athene.lan"}
	otherBody, _ := json.Marshal(other)
	c := forward(t, nil, otherBody)
	if a.table.Lookup(detect.KindHost, "athene.lan") == c.table.Lookup(detect.KindHost, "athene.lan") {
		t.Fatal("fallback salt identical for different conversation heads")
	}
}

// TestRoundTrip: every pseudonym in the output maps back to its original,
// and restoring the output yields the visited strings of the input.
func TestRoundTrip(t *testing.T) {
	body := request(t, fixtures.SessionA)
	p := forward(t, nil, body)
	r := mapping.NewRestorer(p.table)
	restored, changed := r.Restore(string(p.out), true)
	if !changed {
		t.Fatal("Restore reported no change on a pseudonymized body")
	}
	var want, got map[string]any
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(restored), &got); err != nil {
		t.Fatalf("restored body is not JSON: %v", err)
	}
	wb, _ := json.Marshal(want)
	gb, _ := json.Marshal(got)
	if !bytes.Equal(wb, gb) {
		t.Fatalf("round trip differs\nwant %s\ngot  %s", wb, gb)
	}
}

// TestLargeBody: a body near the 32 MiB limit passes within the time
// budget of a normal test run.
func TestLargeBody(t *testing.T) {
	if testing.Short() {
		t.Skip("large body")
	}
	req := fixtures.Request(fixtures.SessionA)
	var msgs []any
	filler := strings.Repeat(fixtures.Prose+" ", 64)
	for len(msgs) < 700 { // about 700 * 46 KiB ~= 31 MiB
		msgs = append(msgs, map[string]any{"role": "user", "content": filler}, map[string]any{"role": "assistant", "content": "ok"})
	}
	req["messages"] = msgs
	body, _ := json.Marshal(req)
	if len(body) > 32<<20 {
		t.Fatalf("test body too large: %d", len(body))
	}
	p := forward(t, nil, body)
	if bytes.Contains(p.out, []byte("athene.lan")) {
		t.Fatal("leak in large body")
	}
}
