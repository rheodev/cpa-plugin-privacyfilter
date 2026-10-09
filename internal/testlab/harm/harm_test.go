// Package harm examines what a wrong replacement does on the user's side.
//
// The return path writes originals into text that the client then executes,
// parses or writes to disk. The pseudonym is always one harmless token of
// letters, digits and a dash; the original is whatever the term list holds.
// Everything in this package follows from that asymmetry: the model writes a
// line around a token it has every reason to consider safe, and the user
// receives a line built around a value the model never saw.
//
// The tests separate two outcomes, because they cost the user different
// things. A mutilation that fails loudly - a patch that no longer applies, a
// regular expression that no longer compiles - costs a retry and is visible
// while it happens. A mutilation that succeeds at something else - a command
// line that gained a second command, a configuration value a comment
// character swallowed, a file written one directory higher than intended -
// costs more, because nothing reports it.
//
// Where a value only reaches an original through one particular door, the
// test says which door. A term literal comes from terms.txt or from the
// terms block of config.yaml; the first is read line by line and can carry
// no newline, the second can. A regex term compiles with regexp.Compile and
// therefore matches across lines whenever it is written to.
package harm

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// abs joins segments into an absolute path at run time. Every file of this
// tree passes through the running filter on its way to disk, and a path
// written as one literal can arrive as another one; assembled from bare
// words it cannot.
func abs(parts ...string) string { return "/" + strings.Join(parts, "/") }

// bs is a single backslash, and quote a single double quote, both built from
// their code points for the same reason abs exists.
var (
	bs    = string(rune(92))
	quote = string(rune(34))
)

// literal fills a fresh table with one literal term and returns the table,
// the pseudonym and the detector that finds the term. The table is complete
// before the first restore, which is what Restorer requires.
func literal(t *testing.T, kind detect.Kind, value string) (*mapping.Table, string, detect.Detector) {
	t.Helper()
	d := lab.Terms(t, detect.Term{Value: value, Kind: kind})
	tab := lab.Table()
	return tab, tab.Lookup(kind, value), d
}

// expression is the same for a term written as a regular expression, which
// is the only door through which an original reaches a newline.
func expression(t *testing.T, kind detect.Kind, re, value string) (*mapping.Table, string, detect.Detector) {
	t.Helper()
	d, err := detect.NewTerms(detect.TermsConfig{
		WordBoundary: true,
		Terms:        []detect.Term{{Regex: re, Kind: kind}},
	})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	tab := lab.Table()
	return tab, tab.Lookup(kind, value), d
}

// shown runs the forward pass over what the user has and returns what the
// model sees. It fails the test when the original survived, because every
// test here reasons about the return path and needs the forward pass to have
// done its work first.
func shown(t *testing.T, text string, d detect.Detector, tab *mapping.Table, original string) string {
	t.Helper()
	out := lab.Forward(text, d, tab)
	if strings.Contains(out, original) {
		t.Fatalf("the forward pass did not replace %q in %q", original, text)
	}
	return out
}

// newSpecials returns the characters of set that the restored line carries
// and the line the model wrote did not. It is the measure every
// configuration test uses: the model chose its quoting for a token without
// any of them, and the user's parser sees a line with them.
func newSpecials(modelLine, userLine, set string) string {
	var out []string
	for _, r := range set {
		c := string(r)
		if strings.Contains(userLine, c) && !strings.Contains(modelLine, c) {
			out = append(out, c)
		}
	}
	return strings.Join(out, " ")
}

// lines counts the lines of a fragment, so a test can say that one line
// became two.
func lines(s string) int { return strings.Count(s, "\n") + 1 }
