package basics

// What git prints and what the model writes back: a status with a quoted
// path, a diff with its markers. Both are read in a tool result and
// repeated in a patch or a command, and both have to come back as they
// went.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// git status quotes a path with a space in it. The bare path inside the
// quotes is read whole, its directories get the same pseudonyms as in the
// unquoted line below it, the file name stays, and the status comes back
// as it was.
func TestPath_QuotedBarePathInGitStatus(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	tab := newTable(t)
	status := ` M "kunde-x/epub/Kunden und Akten.epub"` + "\n M " + strings.Join([]string{"kunde-x", "epub", "README.md"}, "/") + "\n"
	mid := forward(status, d, tab)
	kunde, epub := tab.Lookup(detect.KindPathSegment, "kunde-x"), tab.Lookup(detect.KindPathSegment, "epub")
	want := ` M "` + kunde + "/" + epub + `/Kunden und Akten.epub"` + "\n M " + kunde + "/" + epub + "/README.md\n"
	if mid != want {
		t.Fatalf("forward(%q) = %q, want %q", status, mid, want)
	}
	if got := back(mid, tab); got != status {
		t.Errorf("round trip:\n  in %q\n out %q", status, got)
	}
	// The model names the file in a command, quoted or escaped, and the
	// client gets the real path either way.
	for _, text := range []string{
		`cat "` + kunde + "/" + epub + `/Kunden und Akten.epub"`,
		"cat " + kunde + "/" + epub + `/Kunden\ und\ Akten.epub`,
	} {
		if got := back(text, tab); !strings.Contains(got, "cat ") || !strings.Contains(got, "kunde-x/epub/Kunden") {
			t.Errorf("the model's command:\n  in %q\n out %q", text, got)
		}
	}
}
