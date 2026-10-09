// Package lab holds the shared helpers for the test packages beside it. Each
// area of the test lab lives in its own package and imports this one, so two
// authors working at the same time cannot collide over a helper name or a
// duplicate test function.
//
// The forward direction is rebuilt here the way the interceptor does it:
// scan, then splice pseudonyms in, since Merge guarantees disjoint matches in
// ascending order. The return direction is the table's own restorer.
package lab

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// Secret is the test key. It is not a credential of anything.
const Secret = "test-secret-not-a-real-one-32-by"

// Salt is the fixed salt, so pseudonyms are reproducible across runs.
const Salt = "test-salt"

// Gen returns a generator over the test key.
func Gen() *pseudo.Generator {
	return pseudo.NewGenerator([]byte(Secret), []byte(Salt), pseudo.DefaultRenderers())
}

// GenFor returns a generator for a named session, for tests that need two.
func GenFor(session string) *pseudo.Generator {
	return pseudo.NewGenerator([]byte(Secret), pseudo.DeriveSalt([]byte(Secret), session), pseudo.DefaultRenderers())
}

// Table returns an empty mapping table over the test generator.
func Table() *mapping.Table { return mapping.NewTable(Gen()) }

// Terms builds a literal detector with word boundaries, the way the plugin
// configures the term layer.
func Terms(t *testing.T, terms ...detect.Term) detect.Detector {
	t.Helper()
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: terms})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	return d
}

// Host is shorthand for a single host term.
func Host(t *testing.T, value string) detect.Detector {
	t.Helper()
	return Terms(t, detect.Term{Value: value, Kind: detect.KindHost})
}

// Patterns builds the structural detector. Every class is a switch and every
// switch defaults to off, so pass the ones the test needs.
func Patterns(t *testing.T, cfg detect.PatternsConfig) detect.Detector {
	t.Helper()
	d, err := detect.NewPatterns(cfg)
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	return d
}

// Paths builds the path layer.
func Paths(t *testing.T, cfg detect.PathsConfig) detect.Detector {
	t.Helper()
	d, err := detect.NewPaths(cfg)
	if err != nil {
		t.Fatalf("NewPaths: %v", err)
	}
	return d
}

// Forward replaces every match with its pseudonym, as the outbound path does.
func Forward(text string, d detect.Detector, tab *mapping.Table) string {
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

// Back restores with the table's live restorer; rows added later are seen
// by later calls.
func Back(text string, tab *mapping.Table) string {
	out, _ := tab.Restorer().Restore(text, false)
	return out
}

// V4 assembles an address from numbers. Every file in this tree passes
// through the running filter on its way to disk, so an address written as a
// literal may arrive as something else; one built at run time cannot.
func V4(a, b, c, d int) string { return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d) }

// MAC assembles a hardware address from numbers, for the same reason.
func MAC(o ...int) string {
	parts := make([]string, len(o))
	for i, v := range o {
		parts[i] = fmt.Sprintf("%02x", v&0xff)
	}
	return strings.Join(parts, ":")
}

// ReplaceValue is a payload visitor that replaces one value wherever the walk
// offers it, for tests of the JSON layer that do not need a real detector.
func ReplaceValue(needle, with string) func(p []string, v string) (string, bool) {
	return func(_ []string, v string) (string, bool) {
		if strings.Contains(v, needle) {
			return strings.ReplaceAll(v, needle, with), true
		}
		return v, false
	}
}
