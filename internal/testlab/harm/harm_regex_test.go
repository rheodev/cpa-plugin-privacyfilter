package harm

// Search patterns the model builds around a pseudonym. A pseudonym is
// letters, digits and a dash, so it is its own regular expression and the
// model has no reason to escape it. The original is not: a dot, a plus, a
// pair of parentheses, a bracket or a bar all mean something in a pattern,
// and the search the user runs is then a different search from the one the
// model wrote.
//
// The patterns are compiled with regexp, which is RE2. A grep -E or a sed
// reads POSIX syntax, and the two differ in corners; they agree on every
// character used here, and where they do not the comment says so.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// A pattern built around a pseudonym is a literal search. After restoring it
// is a literal search only when the original carries no metacharacter, and
// the two ways it fails are not equally visible: a pattern that no longer
// compiles stops the tool, a pattern that compiles and matches something
// else does not.
func TestHarm_OriginalInsideAPatternTheModelBuilt(t *testing.T) {
	skipOpenFinding(t)
	cases := []struct {
		name string
		// value is the term as the user configured it.
		value string
		// witness is a string that is not the value and that the restored
		// pattern must not match. Empty when the case cannot produce one.
		witness string
	}{
		{"host name with a dot", "zeus.lan", "zeusxlan"},
		{"brackets around a suffix", "kunde (nord)", "kunde nord"},
		{"a plus in a tariff", "tarif+", "tarif"},
		{"a bar between two names", "Kunde|Nord", "Nord"},
		{"a character class", "raum [4]", "raum 4"},
		{"a backslash in a path", "C:" + bs + "projekte", ""},
		{"nothing special", "Sean O'Connor", ""},
	}
	for _, c := range cases {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, c.value)

		// What the model writes: the pseudonym as a pattern, unescaped,
		// because as a pseudonym that is exactly right.
		modelPattern := aliasValue
		if _, err := regexp.Compile(modelPattern); err != nil {
			t.Fatalf("%s: the pseudonym is not a pattern: %v", c.name, err)
		}
		userPattern := lab.Back(modelPattern, tab)

		re, err := regexp.Compile(userPattern)
		if err != nil {
			t.Logf("%-26s does not compile any more: %v", c.name, err)
			continue
		}
		literalSearch := userPattern == regexp.QuoteMeta(c.value)
		hitsItself := re.MatchString(c.value)
		var falseHit string
		if c.witness != "" && re.MatchString(c.witness) {
			falseHit = c.witness
		}
		t.Logf("%-26s pattern %q literal=%v matches its own value=%v", c.name, userPattern, literalSearch, hitsItself)

		if !hitsItself {
			t.Errorf("%s: the search the user runs no longer finds %q", c.name, c.value)
		}
		if falseHit != "" {
			t.Errorf("%s: the search also finds %q, which is not the value", c.name, falseHit)
		}
	}
}

// sedFields counts the fields of a substitution command, splitting on the
// unescaped delimiter. A well formed s command has four: the s, the pattern,
// the replacement and the flags.
func sedFields(cmd, delim string) int {
	n := 1
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != delim[0] {
			continue
		}
		if i > 0 && cmd[i-1] == bs[0] {
			continue
		}
		n++
	}
	return n
}

// The rename that a model reaches for when a value has to change everywhere:
// sed with the new value in the replacement half. Three characters are
// structure there and in no other place - the delimiter, the ampersand that
// stands for the whole match, and a backslash before a digit that stands for
// a group. The user sees a command that looks like the one the model wrote.
func TestHarm_OriginalInsideASedReplacement(t *testing.T) {
	skipOpenFinding(t)
	cases := []struct {
		name  string
		value string
		// broken says the command no longer parses, which the shell reports.
		broken bool
	}{
		{"slash in a two level name", "Kunden/Meier", true},
		{"ampersand in a company", "Meier & Sohn", false},
		{"backslash and a digit", "Raum" + bs + "1", false},
		{"nothing special", "Meier GmbH", false},
	}
	for _, c := range cases {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, c.value)

		model := "s/OLD/" + aliasValue + "/g"
		if n := sedFields(model, "/"); n != 4 {
			t.Fatalf("%s: the model's own command is malformed, %d fields", c.name, n)
		}
		user := lab.Back(model, tab)
		fields := sedFields(user, "/")

		replacement := strings.TrimSuffix(strings.TrimPrefix(user, "s/OLD/"), "/g")
		usesMatch := strings.Contains(replacement, "&")
		usesGroup := regexp.MustCompile(bs + bs + "[0-9]").MatchString(replacement)
		t.Logf("%-26s command %q fields=%d whole-match=%v group=%v", c.name, user, fields, usesMatch, usesGroup)

		if c.broken {
			if fields == 4 {
				t.Errorf("%s: expected the command to fall apart, it did not: %q", c.name, user)
			}
			continue
		}
		if fields != 4 {
			t.Errorf("%s: the command no longer parses: %q", c.name, user)
		}
		switch {
		case usesMatch:
			t.Errorf("%s: sed writes the matched text where the value carries an ampersand, so the file receives %q and not %q",
				c.name, strings.ReplaceAll(replacement, "&", "OLD"), c.value)
		case usesGroup:
			t.Errorf("%s: sed writes a captured group where the value carries a backslash and a digit, so the file receives neither %q nor an error",
				c.name, c.value)
		}
	}
}

// The control on the other side: a pattern the model wrote around a
// pseudonym and a value with nothing special in it comes back as the literal
// search it was, and a pseudonym that the model did escape with QuoteMeta
// comes back escaped in the same places, because the escape characters are
// not part of the pseudonym and the restorer never touches them.
func TestHarm_QuotedPatternSurvives(t *testing.T) {
	const value = "kundenprojekt"
	tab := lab.Table()
	aliasValue := tab.Lookup(detect.KindPathSegment, value)

	quotedPattern := regexp.QuoteMeta(aliasValue)
	user := lab.Back(quotedPattern, tab)
	re, err := regexp.Compile(user)
	if err != nil {
		t.Fatalf("the quoted pattern no longer compiles: %v", err)
	}
	if !re.MatchString(value) {
		t.Errorf("the quoted pattern no longer finds %q: %q", value, user)
	}
	if user != regexp.QuoteMeta(value) {
		t.Logf("the escaping moved: %q against %q", user, regexp.QuoteMeta(value))
	}
}
