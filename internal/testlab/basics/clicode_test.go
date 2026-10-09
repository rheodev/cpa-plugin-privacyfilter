package basics

// Shapes that occur in a coding session rather than in prose. Three of them
// are byte-exact by nature: a patch has to apply afterwards, an old_string
// has to match the file, a compiler message points at a column. The fourth
// is the model's own writing habit - it does not always repeat a pseudonym
// character for character, and whatever it changes cannot be restored.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// A unified diff is applied byte for byte. Hunk headers, the leading space of
// a context line and the empty context line are the parts most easily lost.
func TestCC_UnifiedDiffRoundTrip(t *testing.T) {
	d := newTerms(t,
		detect.Term{Value: "zeus.lan", Kind: detect.KindHost},
		detect.Term{Value: "hera.lan", Kind: detect.KindHost},
	)
	tab := newTable(t)
	diff := "" +
		"--- a/config/hosts.yaml\n" +
		"+++ b/config/hosts.yaml\n" +
		"@@ -1,6 +1,6 @@\n" +
		" upstream:\n" +
		"-  host: hera.lan\n" +
		"+  host: zeus.lan\n" +
		"   port: 5432\n" +
		" \n" +
		" # trailing comment\n"
	mid := forward(diff, d, tab)
	if strings.Contains(mid, "zeus.lan") || strings.Contains(mid, "hera.lan") {
		t.Errorf("an original survived in the diff:\n%s", mid)
	}
	got := back(mid, tab)
	if got != diff {
		t.Errorf("the patch would no longer apply:\n--- want ---\n%q\n--- got ---\n%q", diff, got)
	}
}

// The model quotes a fragment of the file back as old_string. The fragment is
// restored on its own, without the surrounding text, so the token rule at its
// edges decides whether the edit still matches the file.
func TestCC_FragmentAsOldString(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	tab := newTable(t)
	file := "upstream:\n  host: zeus.lan\n  port: 5432\n"
	shown := forward(file, d, tab)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")

	fragments := map[string]string{
		"line with newline": "  host: " + alias + "\n",
		"line without":      "  host: " + alias,
		"alias alone":       alias,
		"alias and colon":   alias + ":5432",
		"alias in quotes":   `"` + alias + `"`,
		"two lines":         "  host: " + alias + "\n  port: 5432",
	}
	for name, frag := range fragments {
		if !strings.Contains(shown, strings.TrimSuffix(strings.TrimSpace(frag), ":5432")) &&
			name != "alias and colon" && name != "alias in quotes" {
			t.Fatalf("%s: the fragment is not part of what the model sees", name)
		}
		restored := back(frag, tab)
		want := strings.ReplaceAll(frag, alias, "zeus.lan")
		if restored != want {
			t.Errorf("%s: the edit would not match the file\n want %q\n  got %q", name, want, restored)
		}
	}

	// The model shortens the alias, as it does in tables and summaries. The
	// remainder cannot be restored and reaches the user as a pseudonym.
	cut := alias[:len(alias)-3]
	if got := back("  host: "+cut, tab); strings.Contains(got, cut) {
		t.Logf("a shortened alias stays a pseudonym: %q", got)
	}
}

// Compiler messages and stack traces carry a path, a line and a column. The
// numbers must not move, and the path must come back.
func TestCC_CompilerMessageShapes(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "kundenprojekt", Kind: detect.KindPathSegment})
	lines := []string{
		"/home/admin/kundenprojekt/main.go:42:13: undefined: foo",
		"\t/home/admin/kundenprojekt/internal/db/pool.go:118 +0x1a5",
		"  File \"/srv/kundenprojekt/app.py\", line 77, in handler",
		"kundenprojekt/main.go:9:2: imported and not used: \"os\"",
		"go: module lookup disabled by GOFLAGS=-mod=vendor in kundenprojekt",
	}
	for _, line := range lines {
		tab := newTable(t)
		mid := forward(line, d, tab)
		if strings.Contains(mid, "kundenprojekt") {
			t.Errorf("original survived: %q -> %q", line, mid)
		}
		if got := back(mid, tab); got != line {
			t.Errorf("round trip changed the message:\n  in %q\n out %q", line, got)
		}
	}
}

// Whatever the model writes around a pseudonym must not stop the restorer,
// and whatever it does to the pseudonym itself will.
func TestCC_PseudonymAsTheModelWritesIt(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	tab := newTable(t)
	_ = forward("zeus.lan", d, tab)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")

	surroundings := map[string]string{
		"backticks":     "`" + alias + "`",
		"bold":          "**" + alias + "**",
		"heading":       "## " + alias,
		"list item":     "- " + alias + ": running",
		"markdown link": "[status](https://" + alias + "/health)",
		"parenthesis":   "(" + alias + ")",
		"sentence end":  "Der Dienst läuft auf " + alias + ".",
		"table cell":    "| " + alias + " | up |",
		"json value":    `{"host":"` + alias + `"}`,
		"end of text":   "auf " + alias,
	}
	for name, text := range surroundings {
		if got := back(text, tab); strings.Contains(got, alias) {
			t.Errorf("%s: the pseudonym was not restored: %q", name, got)
		}
	}

	// Case is ignored on the return pass, which is a convenience: the model
	// writes host names in capitals in headings. It also widens the surface,
	// see TestCC_PersonPseudonymIgnoresCase.
	if got := back(strings.ToUpper(alias), tab); got != "zeus.lan" {
		t.Errorf("a pseudonym in capitals was not restored: %q", got)
	}

	mangled := map[string]string{
		"line break":     alias[:6] + "\n" + alias[6:],
		"space inserted": alias[:6] + " " + alias[6:],
		"shortened":      alias[:len(alias)-2] + "…",
	}
	for name, text := range mangled {
		got := back(text, tab)
		t.Logf("%-14s %q -> %q", name, text, got)
		if got != text {
			t.Errorf("%s: unexpectedly restored, check the rule: %q", name, got)
		}
	}
}

// A person pseudonym is an ordinary name, and case is ignored on the return
// pass. Both together mean an everyday lower-case word can be rewritten into
// a real person's name.
func TestCC_PersonPseudonymIgnoresCase(t *testing.T) {
	d := newTerms(t, detect.Term{Value: "Ingrid Muster", Kind: detect.KindPerson})
	tab := newTable(t)
	_ = forward("Ingrid Muster", d, tab)
	alias := tab.Lookup(detect.KindPerson, "Ingrid Muster")
	t.Logf("person pseudonym: %q", alias)

	for _, form := range []string{alias, strings.ToUpper(alias), strings.ToLower(alias)} {
		text := "Der Satz nennt " + form + " beiläufig."
		got := back(text, tab)
		t.Logf("%-24q -> %q", form, got)
		if strings.Contains(got, "Ingrid Muster") && form != alias {
			t.Logf("   -> a differently cased word became the real name")
		}
	}
}
