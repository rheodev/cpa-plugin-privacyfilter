package harm

// What lands on disk, and what the user reads before it does. A writing
// tool takes a path and a content from the model's answer, and both have
// been through the return pass. The path is
// the sharper of the two: a value that is one segment for the model can be
// two for the file system, and then the file is written somewhere the model
// never named.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// segments counts the segments of an absolute path.
func segments(p string) int { return strings.Count(p, "/") }

// A term value with a slash in it is one token for the term layer, one
// pseudonym for the model and two directories for the file system. The model
// writes a path with four segments, the user gets one with five, and the
// file is created a level deeper than the answer says. Nothing reports it:
// the write succeeds, at the wrong place.
//
// The door is ordinary. A two level customer directory put into terms.txt as
// one entry is a natural thing to write, and nothing at load time says it is
// not one segment.
func TestHarm_SlashInOriginalMovesTheFile(t *testing.T) {
	skipOpenFinding(t)
	cases := []struct{ name, value string }{
		{"two level customer", "Kunden/Meier"},
		{"a step upwards", ".." + "/" + "Meier"},
	}
	for _, c := range cases {
		tab, aliasValue, d := literal(t, detect.KindPathSegment, c.value)

		onDisk := abs("srv", c.value, "report.md")
		view := shown(t, onDisk, d, tab, c.value)
		if !strings.Contains(view, aliasValue) {
			t.Fatalf("%s: the model would not see the pseudonym: %q", c.name, view)
		}

		// The model repeats the path it was shown, as a writing tool wants it.
		user := lab.Back(view, tab)
		t.Logf("%-20s model writes %q\n   file lands at %q", c.name, view, user)
		if segments(user) != segments(view) {
			t.Errorf("%s: the model named a path of %d segments, the file is written to one of %d: %q",
				c.name, segments(view), segments(user), user)
		}
	}
}

// The pseudonym of a file name keeps the extension of the original, and the
// extension is whatever stands after the last dot, up to fifteen characters
// of letters, digits, underscore and dash. When the identifying part of a
// name sits there - and in a name such as bericht.Meier-GmbH it does - the
// pseudonym carries it out of the machine unchanged. The contract says the
// extension is kept; that it can be the confidential half of the name is not
// part of any decision written down.
func TestHarm_FileNamePseudonymCarriesTheSuffix(t *testing.T) {
	cases := []struct{ name, value, secret string }{
		{"customer in the suffix", "bericht.Meier-GmbH", "Meier-GmbH"},
		{"project number", "export.P2026_4711", "P2026_4711"},
		{"ordinary extension", "bericht.pdf", ""},
	}
	for _, c := range cases {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindFileName, c.value)
		t.Logf("%-24s %q -> %q", c.name, c.value, aliasValue)
		if c.secret == "" {
			continue
		}
		if strings.Contains(aliasValue, c.secret) {
			t.Errorf("%s: the pseudonym %q carries %q out of the machine", c.name, aliasValue, c.secret)
		}
	}
}

// Which shapes around a pseudonym the return pass resolves. The rule is in
// the Restorer contract: letters and digits continue a token, everything
// else delimits. This test only measures it, because a documented rule is
// not a fault; what it measures is how much of a generated name has to be
// unlike a letter for the name on disk to be the user's own.
func TestHarm_PseudonymGluedIntoAName(t *testing.T) {
	const value = "kundenprojekt"
	tab := lab.Table()
	aliasValue := tab.Lookup(detect.KindPathSegment, value)

	shapes := map[string]string{
		"dash before":       "backup-" + aliasValue + ".tar",
		"underscore before": "backup_" + aliasValue + ".tar",
		"dot before":        "backup." + aliasValue + ".tar",
		"slash before":      abs("srv", aliasValue, "report.md"),
		"letter before":     "backup" + aliasValue + ".tar",
		"digit before":      "2026" + aliasValue + ".tar",
		"letter after":      aliasValue + "backup.tar",
		"digit after":       aliasValue + "2.tar",
	}
	for name, text := range shapes {
		got := lab.Back(text, tab)
		if strings.Contains(got, aliasValue) {
			t.Logf("%-18s stays a pseudonym on disk: %q", name, got)
			continue
		}
		t.Logf("%-18s resolved: %q", name, got)
	}
}

// renderCR models what a terminal shows for a line that carries carriage
// returns: the cursor goes back to column zero and what follows overwrites
// what is there. It is the reason a line can read differently from the bytes
// it is made of.
func renderCR(line string) string {
	screen := []rune{}
	col := 0
	for _, r := range line {
		if r == '\r' {
			col = 0
			continue
		}
		if col < len(screen) {
			screen[col] = r
		} else {
			screen = append(screen, r)
		}
		col++
	}
	return string(screen)
}

// A carriage return inside an original separates what the user reads from
// what the shell receives. The model writes a command around a pseudonym,
// the restorer puts a value with a control character in its place, and the
// line printed for approval shows the tail of the value written over its
// head. The user approves a command he has not seen. The same door as the
// newline: a regex term, or a double quoted scalar in the terms block of
// config.yaml, both of which carry a control character where terms.txt
// cannot.
func TestHarm_CarriageReturnHidesWhatRuns(t *testing.T) {
	skipOpenFinding(t)
	value := "q3-2026" + string(rune(13)) + "rm -rf tmp"
	tab, aliasValue, d := expression(t, detect.KindPathSegment, "q3-2026"+string(rune(13))+"rm -rf tmp", value)

	if view := lab.Forward("--tag "+value, d, tab); !strings.Contains(view, aliasValue) {
		t.Fatalf("the forward pass did not replace the value: %q", view)
	}

	model := "backup --tag " + aliasValue
	user := lab.Back(model, tab)
	seen := renderCR(user)
	t.Logf("model wrote  %q\nshell gets   %q\nuser reads   %q", model, user, seen)

	if seen != user {
		t.Errorf("the line printed for approval reads %q while the shell receives %q", seen, user)
	}
}

// A newline in an original inside a comment of a script the model writes.
// Quoting is the answer to the metacharacters already on record, and it is
// no answer here: a comment has no quoting, so the second line of the
// original is an ordinary command line in the file that is about to run.
func TestHarm_NewlineInAComment(t *testing.T) {
	skipOpenFinding(t)
	const value = "Meier GmbH\nrm -rf tmp"
	tab, aliasValue, d := expression(t, detect.KindPerson, "Meier GmbH\nrm -rf tmp", value)

	file := "#!/bin/sh\n# Kunde: Meier GmbH\nrm -rf tmp\n"
	if view := lab.Forward(file, d, tab); !strings.Contains(view, aliasValue) {
		t.Fatalf("the forward pass did not replace the value: %q", view)
	}

	model := "#!/bin/sh\n# Kunde: " + aliasValue + "\necho done\n"
	user := lab.Back(model, tab)
	t.Logf("model wrote:\n%s\nuser stores:\n%s", model, user)

	var commented, executable int
	for _, ln := range strings.Split(strings.TrimSuffix(user, "\n"), "\n") {
		switch {
		case strings.HasPrefix(ln, "#"):
			commented++
		case strings.TrimSpace(ln) == "":
		default:
			executable++
		}
	}
	t.Logf("comment lines %d, executable lines %d", commented, executable)
	if executable != 1 {
		t.Errorf("the model wrote one executable line, the file has %d; the comment leaked its second line", executable)
	}
}
