package config

// The term list is the part of the configuration a user edits by hand, so it
// is the part that arrives malformed. NewTerms is the only place that can
// refuse an entry before it is in service; whatever it lets through runs.

import (
	"strings"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// A term carries exactly one of Value and Regex, and neither shape passes.
func TestConfig_TermShapeRefused(t *testing.T) {
	cases := []struct {
		name string
		term detect.Term
	}{
		{"neither value nor regex", detect.Term{Kind: detect.KindHost}},
		{"both value and regex", detect.Term{Value: hostName(1), Regex: hostName(1), Kind: detect.KindHost}},
	}
	for _, c := range cases {
		_, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: []detect.Term{c.term}})
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		t.Logf("%s: %v", c.name, err)
	}
}

// Every expression Go itself refuses aborts the build, and the report names
// the position and quotes the expression.
func TestConfig_BrokenRegexRefused(t *testing.T) {
	broken := []string{
		"(",
		"*",
		"a**",
		"[z-a]",
		"a{2,1}",
		`\1`,
		"(?i",
	}
	for _, expr := range broken {
		_, err := detect.NewTerms(detect.TermsConfig{
			WordBoundary: true,
			Terms: []detect.Term{
				{Value: hostName(1), Kind: detect.KindHost},
				{Regex: expr, Kind: detect.KindHost},
			},
		})
		if err == nil {
			t.Errorf("regex %q was accepted", expr)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, expr) {
			t.Errorf("regex %q: the report does not quote the expression: %q", expr, msg)
		}
		if !strings.Contains(msg, "1") {
			t.Errorf("regex %q: the report does not name the position: %q", expr, msg)
		}
		t.Logf("%q: %v", expr, err)
	}
}

// An expression that matches the empty string is accepted. Merge drops the
// zero-width hits, so nothing is spliced into the text, but the entry is
// dead and neither the build nor the log says so.
func TestConfig_RegexMatchingTheEmptyString(t *testing.T) {
	text := "ssh " + hostName(7) + " -- df -h"
	for _, expr := range []string{"q*", "(?:)", "^", "$", `\b`, "(?:zzz)?"} {
		d := lab.Terms(t, detect.Term{Regex: expr, Kind: detect.KindHost})
		ms := d.Scan(text)
		for _, m := range ms {
			if m.Start >= m.End {
				t.Errorf("regex %q produced a zero-width match at %d", expr, m.Start)
			}
		}
		if got := lab.Forward(text, d, lab.Table()); got != text {
			t.Errorf("regex %q changed the text: %q", expr, got)
		}
		t.Logf("regex %q: %d matches, the entry has no effect", expr, len(ms))
	}
}

// An expression that matches everything is accepted as readily. The whole
// text becomes one pseudonym, and nothing at build time asks whether that
// was meant.
func TestConfig_RegexMatchingEverything(t *testing.T) {
	text := "ssh " + hostName(8) + " -- df -h"
	d := lab.Terms(t, detect.Term{Regex: "(?s).+", Kind: detect.KindHost})
	got := lab.Forward(text, d, lab.Table())
	if got == text {
		t.Fatalf("the expression matched nothing: %q", got)
	}
	t.Logf("%q\n   -> %q", text, got)
}

// RE2 has no backtracking. The expressions that stall a backtracking engine
// run in linear time here, so an unlucky entry of the term list cannot turn
// the forward path into a halt.
func TestConfig_RegexBacktracking(t *testing.T) {
	subject := strings.Repeat("a", 64) + strings.Repeat("x", 64) + "!"
	for _, expr := range []string{`(a+)+$`, `(a|a)*$`, `(x+x+)+y`, `(a*)*b`, `(a|aa)+$`} {
		d := lab.Terms(t, detect.Term{Regex: expr, Kind: detect.KindSecret})
		start := time.Now()
		ms := d.Scan(subject)
		took := time.Since(start)
		if took > 2*time.Second {
			t.Errorf("regex %q took %v over %d bytes", expr, took, len(subject))
		}
		t.Logf("%q over %d bytes: %v, %d hits", expr, len(subject), took, len(ms))
	}
}

// The same value under two kinds. Both entries build, one hit is reported,
// and it carries the kind of the entry that comes first; the second entry is
// dead. Nothing in the build says so.
func TestConfig_SameValueTwoKinds(t *testing.T) {
	value := hostName(11)
	text := "ssh " + value
	for _, o := range []struct{ first, second detect.Kind }{
		{detect.KindHost, detect.KindPerson},
		{detect.KindPerson, detect.KindHost},
	} {
		d := lab.Terms(t,
			detect.Term{Value: value, Kind: o.first},
			detect.Term{Value: value, Kind: o.second},
		)
		ms := d.Scan(text)
		if len(ms) != 1 {
			t.Fatalf("want one hit, got %d", len(ms))
		}
		if ms[0].Kind != o.first {
			t.Errorf("want the kind of the first entry %q, got %q", string(o.first), string(ms[0].Kind))
		}
		t.Logf("entries %q and %q over the same value: reported as %q",
			string(o.first), string(o.second), string(ms[0].Kind))
	}
}

// The same value once exact and once case insensitive lands in two different
// automatons. Which of the two entries wins is then not a question of their
// order in the file. It must at least be the same answer on every build.
func TestConfig_SameValueExactAndFolded(t *testing.T) {
	value := hostName(12)
	text := "ssh " + value
	kinds := make(map[detect.Kind]int)
	for i := 0; i < 20; i++ {
		d := lab.Terms(t,
			detect.Term{Value: value, Kind: detect.KindPerson, IgnoreCase: true},
			detect.Term{Value: value, Kind: detect.KindHost},
		)
		ms := d.Scan(text)
		if len(ms) != 1 {
			t.Fatalf("want one hit, got %d", len(ms))
		}
		kinds[ms[0].Kind]++
	}
	if len(kinds) != 1 {
		t.Errorf("the reported kind is not stable across builds: %v", kinds)
	}
	for k := range kinds {
		t.Logf("first entry person with ignore_case, second entry host: reported as %q", string(k))
	}
}

// What NewTerms accepts without a word. None of these entries is refused and
// none produces a warning; the effect shows only in the text.
func TestConfig_WhatTheTermConstructorLetsThrough(t *testing.T) {
	text := "ssh " + hostName(21) + " ; 2 x 3 = 6"
	cases := []struct {
		name string
		term detect.Term
	}{
		{"white space only", detect.Term{Value: " ", Kind: detect.KindHost}},
		{"a single dot", detect.Term{Value: ".", Kind: detect.KindHost}},
		{"a single letter", detect.Term{Value: "x", Kind: detect.KindHost}},
		{"a value with a trailing newline", detect.Term{Value: hostName(21) + "\n", Kind: detect.KindHost}},
		{"a value that is not utf-8", detect.Term{Value: string([]byte{0xff, 0xfe}), Kind: detect.KindHost}},
		{"a value with a nul byte", detect.Term{Value: string([]byte{0x00}), Kind: detect.KindHost}},
		{"ignore_case on a regex, where it has no effect", detect.Term{Regex: "ZZZ", Kind: detect.KindHost, IgnoreCase: true}},
		{"two capture groups of the same name", detect.Term{Regex: "(?P<n>a)(?P<n>b)", Kind: detect.KindHost}},
	}
	for _, c := range cases {
		d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: []detect.Term{c.term}})
		if err != nil {
			t.Logf("%s: refused: %v", c.name, err)
			continue
		}
		got := lab.Forward(text, d, lab.Table())
		t.Logf("%s: accepted, text %s", c.name, changed(text, got))
	}
}

// A term whose value already has the shape of a pseudonym could never be
// replaced, because the composite excludes that shape from detection. The
// constructor takes it; the check for it sits in the wiring in main.go.
func TestConfig_TermInPseudonymShape(t *testing.T) {
	value := lab.Gen().Pseudonym(detect.KindHost, hostName(51), 0)
	if _, err := detect.NewTerms(detect.TermsConfig{
		WordBoundary: true,
		Terms:        []detect.Term{{Value: value, Kind: detect.KindHost}},
	}); err != nil {
		t.Logf("refused: %v", err)
		return
	}
	t.Logf("a term of the shape %q is accepted here; main.go refuses it at registration", value)
}
