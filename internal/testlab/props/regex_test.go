package props

// The boundary rules of the two directions. A literal of the maintained list
// is only matched when it stands on its own, and the plugin wires the term
// layer with WordBoundary set, so a literal is always delimited where it is
// replaced. A regular expression once stated its own boundaries and was
// exempt from that check, while the return pass restores a pseudonym only
// where it stands on its own; where the two rules did not meet, the forward
// pass wrote a pseudonym the return pass never took back. The rule now holds
// for expressions as for literals.

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// regexRig builds a rig over a single regular expression term.
func regexRig(t *testing.T, expr string, kind detect.Kind) *rig {
	t.Helper()
	gen := lab.Gen()
	tab := mapping.NewTable(gen)
	return &rig{
		gen: gen,
		tab: tab,
		det: detect.NewComposite(tab.Knows,
			lab.Terms(t, detect.Term{Regex: expr, Kind: kind})),
	}
}

// A regular expression term that would match inside a longer token is not
// applied there: the word boundary rule of the list holds for expressions
// as for literals, so the forward pass never writes a pseudonym the return
// pass would refuse to take back.
func TestProps_RegexTermInsideAToken(t *testing.T) {
	cases := []struct {
		name string
		expr string
		text string
	}{
		{"letter behind the match", `kunde-[0-9]+`, "kunde-42x"},
		{"letter in front of the match", `kunde-[0-9]+`, "xkunde-42"},
		{"inside an identifier", `EMP[0-9]{3}`, "REF_EMP123ABC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := regexRig(t, c.expr, detect.KindPathSegment)
			mid := r.forwardOnce(c.text)
			if mid != c.text {
				t.Errorf("the regex matched inside the token %q and left %q", c.text, mid)
			}
			checkRoundTrip(t, r, c.text, mid)
		})
	}
}

// The counter-probe: the same expression where the match is delimited comes
// back unchanged, so the cause is the boundary and not the expression.
func TestProps_RegexTermDelimitedRoundTrips(t *testing.T) {
	texts := []string{
		"kunde-42",
		"ticket kunde-42 offen",
		"/mnt/kunde-42/notes.md",
		"kunde-42_backup",
		"(kunde-42)",
	}
	for _, text := range texts {
		r := regexRig(t, `kunde-[0-9]+`, detect.KindPathSegment)
		mid := r.forwardOnce(text)
		if mid == text {
			t.Errorf("the regex did not match %q", text)
			continue
		}
		if out := lab.Back(mid, r.tab); out != text {
			t.Errorf("round trip changed the text\n in:  %q\n mid: %q\n out: %q", text, mid, out)
		}
	}
}

// The property behind the two probes: for every regular expression the fuzzer
// writes and every text it runs it over, the circle has to close.
func FuzzPropsRoundTripRegexTerm(f *testing.F) {
	f.Add(`kunde-[0-9]+`, "kunde-42 und kunde-42x")
	f.Add(`[a-z]+\.home\.lan`, "ssh knoten.home.lan")
	f.Add(`A-[0-9]{4}`, "grep A-1234 log")
	f.Add(`(?i)zeus`, "ZEUS und zeus und Zeusx")
	f.Add(`\d+`, "port 8080")
	f.Fuzz(func(t *testing.T, expr, text string) {
		if expr == "" || len(expr) > 64 || len(text) > maxFuzzInput {
			return
		}
		if !utf8.ValidString(expr) || strings.Contains(expr, "(?P") {
			return
		}
		det, err := detect.NewTerms(detect.TermsConfig{
			WordBoundary: true,
			Terms:        []detect.Term{{Regex: expr, Kind: detect.KindPathSegment}},
		})
		if err != nil {
			return // not a valid expression; the configuration layer rejects it
		}
		gen := lab.Gen()
		tab := mapping.NewTable(gen)
		r := &rig{gen: gen, tab: tab, det: detect.NewComposite(tab.Knows, det)}
		mid := r.forwardOnce(text)
		checkRoundTrip(t, r, text, mid)
	})
}
