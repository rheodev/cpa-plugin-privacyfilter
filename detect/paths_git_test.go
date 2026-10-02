package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// A bare path inside quotes may carry a space, in its file name or in a
// directory behind the first: ` M "kunde-x/epub/Kunden und Akten.epub"` is
// how git status prints such a path. The shape is judged on the whole of
// the quoted text, so the extension at its end counts although a space
// stands in front of it. The first segment has to be free of spaces, which
// keeps the first word of a commit message, `"fix kunde-x/x.go"`, a word;
// a quoted top-level directory with a space in its name is read from its
// first slashed word on, the limit the README names.
func TestPaths_QuotedBarePathWithASpace(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	cases := map[string]string{
		` M "kunde-x/epub/Kunden und Akten.epub"`:          "path_segment:kunde-x path_segment:epub",
		` M "kunde-x/site/Kunden Akten/Bericht final.pdf"`: "path_segment:kunde-x path_segment:site path_segment:Kunden path_segment:Akten",
		`'kunde-x/Kunden Akten/notiz.md'`:                  "path_segment:kunde-x path_segment:Kunden path_segment:Akten",
		"`kunde-x/Kunden Akten/`":                          "path_segment:kunde-x path_segment:Kunden path_segment:Akten",
		`{"file_path": "kunde-x/Kunden Akten/x.md"}`:       "path_segment:kunde-x path_segment:Kunden path_segment:Akten",
		`"kunde-x/Kunden Akten/a.md" "kunde-x/b c/d.md"`:   "path_segment:kunde-x path_segment:Kunden path_segment:Akten path_segment:kunde-x path_segment:b path_segment:c",
		`"kunde-x/x.go: fix the test"`:                     "path_segment:kunde-x",                    // a file name ends the path
		`"kunde-x/Kunden Akten"`:                           "",                                        // the bare directory path, quoted or not
		`"fix kunde-x/x.go"`:                               "path_segment:kunde-x",                    // the first word is a word
		`"Kunden und Akten/kunde-x/x.go"`:                  "path_segment:Akten path_segment:kunde-x", // the limit
		`"kunde-x/Kunden Akten/notiz.md`:                   "path_segment:Akten",                      // no closing quote on the line
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
	// The words of the file name belong to the file name.
	all := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	text := ` M "kunde-x/epub/Kunden und Akten.epub"`
	got := all.Scan(text)
	assertDisjointSorted(t, text, got)
	if want := "path_segment:kunde-x path_segment:epub filename:Kunden filename:und filename:Akten.epub"; values(got) != want {
		t.Fatalf("AllFilenames: Scan(%q) = %q, want %q", text, values(got), want)
	}
}

// The marker of a diff line, the "+" or "-" at the start of a line, is a
// boundary and not part of the path behind it. git diff prints an added or
// a removed line that holds a path as "+/home/alice/kunde/x.go" or
// "-kunde-x/build/"; the marker is a segment character, so without the rule
// the anchored path was not recognised at all, and the bare one began with
// "+kunde-x" and got a pseudonym of its own, the marker gone from the
// model's view. A flag, a flattened working directory and the "---" of a
// diff header carry no path behind their first character and stay what
// they were; a marker in front of a flattened name is a marker.
func TestPaths_DiffMarkerIsABoundary(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	diff := "+" + j("home", "alice", "kunde-x", "x.go") + "\n" +
		"-" + j("home", "alice", "kunde-x", "y.go") + "\n" +
		" " + j("home", "alice", "kunde-x", "z.go") + "\n" +
		"+~/" + r("kunde-x", "w.go") + "\n" +
		"-../" + r("kunde-x", "v.go") + "\n" +
		"+" + r("kunde-x", "build", "") + "\n" +
		"-" + r("kunde-x", "u.go") + "\n" +
		"+# see " + r("kunde-x", "t.go") + " for the rest\n"
	got := d.Scan(diff)
	assertDisjointSorted(t, diff, got)
	want := strings.TrimSpace(strings.Repeat("path_segment:alice path_segment:kunde-x ", 3) + strings.Repeat("path_segment:kunde-x ", 5))
	if values(got) != want {
		t.Fatalf("Scan(%q) =\n%s\nwant\n%s", diff, values(got), want)
	}
	for _, m := range got {
		if m.Value[0] == '+' || m.Value[0] == '-' {
			t.Errorf("the marker went into the segment %q", m.Value)
		}
	}
	flat := strings.Join([]string{"", "home", "alice", "kunde-x"}, "-")
	cases := map[string]string{
		flat + "\n-" + flat + "\n+" + flat + "\n":                                  strings.TrimSpace(strings.Repeat("path_segment:"+flat+" ", 3)),
		"--- a/" + r("kunde-x", "x.go") + "\n+++ b/" + r("kunde-x", "x.go") + "\n": "",
		"@@ -24,3 +24,9 @@\n": "",
		"-la\n--no-verify\n-home -home-x\n-rw-r--r-- 1 alice alice 0 Oct  2 x\n": "",
		"+1 for " + r("kunde-x", "x.go"):                                         "path_segment:kunde-x",
		"+\n-\n+":                                                                "",
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
}
