package config

// A term list grows. The literal entries become one automaton and cost the
// same whatever their number; the expressions are applied one after the
// other and cost the number of entries on every scan. These tests measure
// both, so the size at which a list stops being free is a number and not a
// guess.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// scaleText builds a text of n lines, each carrying one term of the list.
func scaleText(lines, stride int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		fmt.Fprintf(&b, "line %d: ssh %s and nothing else on it\n", i, hostName(i*stride))
	}
	return b.String()
}

// Ten thousand literals is a plausible list for a company that keeps its host
// names and its customers in one file.
func TestConfig_TenThousandLiteralTerms(t *testing.T) {
	const n = 10000
	terms := make([]detect.Term, 0, n)
	for i := 0; i < n; i++ {
		terms = append(terms, detect.Term{Value: hostName(i), Kind: detect.KindHost})
	}
	start := time.Now()
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: terms})
	built := time.Since(start)
	if err != nil {
		t.Fatalf("NewTerms over %d terms: %v", n, err)
	}
	const lines = 2000
	text := scaleText(lines, 5)
	start = time.Now()
	ms := d.Scan(text)
	scanned := time.Since(start)
	t.Logf("%d literal terms: build %v, scan of %d bytes %v, %d hits", n, built, len(text), scanned, len(ms))
	if len(ms) != lines {
		t.Errorf("want %d hits, got %d", lines, len(ms))
	}
	if built > 10*time.Second {
		t.Errorf("building %d terms took %v", n, built)
	}
	if scanned > 2*time.Second {
		t.Errorf("scanning %d bytes took %v", len(text), scanned)
	}
}

// The build time of the literal list against its length. The automaton is
// built once at registration, so this is a cost the user pays on a reload,
// not on a request.
func TestConfig_LiteralTermsBuildTime(t *testing.T) {
	for _, n := range []int{100, 1000, 10000} {
		terms := make([]detect.Term, 0, n)
		for i := 0; i < n; i++ {
			terms = append(terms, detect.Term{Value: hostName(i), Kind: detect.KindHost})
		}
		start := time.Now()
		if _, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: terms}); err != nil {
			t.Fatalf("%d terms: %v", n, err)
		}
		t.Logf("%5d literal terms: build %v", n, time.Since(start))
	}
}

// The same list once as literals and once as expressions that mean exactly
// the same. The scan is what separates them: one automaton against one pass
// per entry.
func TestConfig_ManyRegexTermsCostPerScan(t *testing.T) {
	const n = 1000
	lit := make([]detect.Term, 0, n)
	rex := make([]detect.Term, 0, n)
	for i := 0; i < n; i++ {
		lit = append(lit, detect.Term{Value: hostName(i), Kind: detect.KindHost})
		rex = append(rex, detect.Term{Regex: regexp.QuoteMeta(hostName(i)), Kind: detect.KindHost})
	}
	text := scaleText(1000, 1)

	start := time.Now()
	dl, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: lit})
	builtLit := time.Since(start)
	if err != nil {
		t.Fatalf("literal list: %v", err)
	}
	start = time.Now()
	dr, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: rex})
	builtRex := time.Since(start)
	if err != nil {
		t.Fatalf("expression list: %v", err)
	}

	start = time.Now()
	msLit := dl.Scan(text)
	scanLit := time.Since(start)
	start = time.Now()
	msRex := dr.Scan(text)
	scanRex := time.Since(start)

	if len(msLit) != len(msRex) {
		t.Errorf("the two lists disagree: %d literal hits against %d expression hits", len(msLit), len(msRex))
	}
	t.Logf("%d entries over %d bytes", n, len(text))
	t.Logf("literals:    build %v, scan %v, %d hits", builtLit, scanLit, len(msLit))
	t.Logf("expressions: build %v, scan %v, %d hits", builtRex, scanRex, len(msRex))
	if scanLit > 0 {
		t.Logf("the expression list costs %.0f times the scan of the literal list", float64(scanRex)/float64(scanLit))
	}
	perTermPerKB := float64(scanRex.Microseconds()) / (float64(n) * float64(len(text)) / 1024)
	t.Logf("one expression costs %.2f microseconds per kilobyte of body", perTermPerKB)
	t.Logf("a body of one megabyte would cost %.0f milliseconds against 100 expressions and %.1f seconds against 10000",
		perTermPerKB*100*1024/1000, perTermPerKB*10000*1024/1e6)
	if scanRex > 30*time.Second {
		t.Errorf("scanning %d bytes against %d expressions took %v", len(text), n, scanRex)
	}
}
