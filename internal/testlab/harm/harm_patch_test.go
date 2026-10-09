package harm

// The two ways a coding client turns the model's answer into a change on
// disk: a unified diff handed to git apply or patch, and an old_string that
// an editing tool matches against the file. Both are byte-exact by nature,
// and both are written by the model around a pseudonym.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// checkHunk reads a single-hunk unified diff and reports whether the line
// counts in its header match the lines that follow. It is what git apply
// verifies before it touches anything: a body line without one of the four
// prefix characters is not part of the hunk, and counts that disagree with
// the header are refused.
func checkHunk(diff string) (bool, string) {
	body := strings.Split(diff, "\n")
	if n := len(body); n > 0 && body[n-1] == "" {
		body = body[:n-1] // the diff's own trailing newline
	}
	var wantOld, wantNew, gotOld, gotNew int
	inHunk := false
	for _, ln := range body {
		if strings.HasPrefix(ln, "@@") {
			var a, b, c, d int
			if _, err := fmt.Sscanf(ln, "@@ -%d,%d +%d,%d @@", &a, &b, &c, &d); err != nil {
				return false, "hunk header not parsable: " + ln
			}
			wantOld, wantNew = b, d
			inHunk = true
			continue
		}
		if !inHunk {
			continue
		}
		if ln == "" {
			return false, "empty line inside the hunk, not even a context marker"
		}
		switch ln[0] {
		case ' ':
			gotOld++
			gotNew++
		case '-':
			gotOld++
		case '+':
			gotNew++
		case bs[0]:
			// "\ No newline at end of file"
		default:
			return false, fmt.Sprintf("line without a diff prefix: %q", ln)
		}
	}
	if gotOld != wantOld || gotNew != wantNew {
		return false, fmt.Sprintf("header says -%d +%d, body has -%d +%d", wantOld, wantNew, gotOld, gotNew)
	}
	return true, ""
}

// A patch counts lines, not characters. An original that is longer or
// shorter than its pseudonym therefore costs nothing, and this is the
// control that says so before the next test takes the other case.
func TestHarm_PatchSurvivesALengthChange(t *testing.T) {
	const owner = "kundenprojekt-nord-gmbh"
	tab, aliasOwner, d := literal(t, detect.KindPathSegment, owner)

	file := "service:\n  owner: " + owner + "\n  port: 5432\n"
	view := shown(t, file, d, tab, owner)
	if !strings.Contains(view, aliasOwner) {
		t.Fatalf("the model would not see the pseudonym: %q", view)
	}

	diff := "" +
		"--- a/service.yaml\n" +
		"+++ b/service.yaml\n" +
		"@@ -1,3 +1,3 @@\n" +
		" service:\n" +
		"   owner: " + aliasOwner + "\n" +
		"-  port: 5432\n" +
		"+  port: 6432\n"
	got := lab.Back(diff, tab)
	if ok, why := checkHunk(got); !ok {
		t.Errorf("the patch no longer applies: %s\n%s", why, got)
	}
	t.Logf("original %d bytes, pseudonym %d bytes, hunk unaffected", len(owner), len(aliasOwner))
}

// A newline inside an original is the case the patch cannot absorb. One line
// in the text the model saw becomes two in the text the user receives, the
// second one carries no diff prefix, and the hunk header counts a line that
// is no longer where it says. The door is a regex term: terms.txt is read
// line by line and cannot hold a newline, a regular expression matches
// across lines as soon as one is written into it.
func TestHarm_NewlineInOriginalBreaksTheHunk(t *testing.T) {
	skipOpenFinding(t)
	const value = "Meier GmbH\nBahnhofstrasse 1"
	tab, aliasOwner, d := expression(t, detect.KindPerson, value, value)

	file := "owner: Meier GmbH\nBahnhofstrasse 1\nport: 5432\n"
	view := shown(t, file, d, tab, value)
	if n := lines(view); n != 3 {
		t.Fatalf("the model sees %d lines, expected the two-line value collapsed into one: %q", n, view)
	}

	// What the model writes, counting the lines it was shown.
	diff := "" +
		"--- a/owner.txt\n" +
		"+++ b/owner.txt\n" +
		"@@ -1,2 +1,2 @@\n" +
		" owner: " + aliasOwner + "\n" +
		"-port: 5432\n" +
		"+port: 6432\n"
	if ok, why := checkHunk(diff); !ok {
		t.Fatalf("the test built a diff that is already wrong: %s", why)
	}

	got := lab.Back(diff, tab)
	t.Logf("what the user receives:\n%s", got)
	ok, why := checkHunk(got)
	if ok {
		t.Errorf("expected the restored hunk to be broken, it is not:\n%s", got)
		return
	}
	t.Errorf("the patch does not apply after restoring: %s", why)
}

// The same newline in an editing tool's old_string, and here it costs
// nothing. The fragment the model quotes restores to exactly the bytes the
// file holds, line break included, because the return pass is the inverse of
// the forward pass over that fragment. The patch case above breaks not
// because the value changed but because a diff counts lines around it.
func TestHarm_NewlineInOriginalStillMatchesTheOldString(t *testing.T) {
	const value = "Meier GmbH\nBahnhofstrasse 1"
	tab, aliasOwner, d := expression(t, detect.KindPerson, value, value)

	file := "owner: Meier GmbH\nBahnhofstrasse 1\nport: 5432\n"
	view := shown(t, file, d, tab, value)

	oldString := "owner: " + aliasOwner
	if !strings.Contains(view, oldString) {
		t.Fatalf("the fragment is not part of what the model sees: %q", view)
	}
	restored := lab.Back(oldString, tab)
	if strings.Contains(file, restored) {
		t.Logf("the restored fragment still matches the file: %q", restored)
		return
	}
	t.Errorf("the edit misses the file:\n  model quoted %q\n  user searches %q", oldString, restored)
}

// Two kinds over the same word give two pseudonyms, and the return pass maps
// both onto the same original. The forward direction is injective, the
// return direction is not, so a fragment that is unique in the text the
// model reads need not be unique in the file the user edits, and an editing
// tool that insists on a unique old_string refuses or, worse, takes the
// first occurrence.
//
// The test stays green because the property is shown here on a table filled
// by hand, and no configuration was found that fills a real table this way
// in one request: the layers are ranked, so every position gets exactly one
// kind, and a value listed twice with two kinds is still one match. It is
// recorded because the ranking is the only thing that prevents it, and the
// overlap of two layers of different length is on the open list.
func TestHarm_TwoPseudonymsCollapseToOneOriginal(t *testing.T) {
	const value = "Meier"
	tab := lab.Table()
	asPerson := tab.Lookup(detect.KindPerson, value)
	asSegment := tab.Lookup(detect.KindPathSegment, value)
	if asPerson == asSegment {
		t.Fatalf("the two kinds share a pseudonym, the premise of this test is gone: %q", asPerson)
	}

	// What the model reads: the name once in prose, once as a directory.
	view := "Ansprechpartner " + asPerson + " betreut " + abs("mnt", "kunden", asSegment, "daten") + "."
	if strings.Count(view, asPerson) != 1 {
		t.Fatalf("the premise needs a unique occurrence, got %d", strings.Count(view, asPerson))
	}
	restored := lab.Back(view, tab)
	t.Logf("model reads: %s\nuser gets:   %s", view, restored)

	if n := strings.Count(restored, value); n != 2 {
		t.Fatalf("expected the original twice after restoring, got %d in %q", n, restored)
	}
	t.Logf("old_string %q was unique for the model and matches two places in the user's text", asPerson)
}
