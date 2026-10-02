package basics

// The path layer takes a path apart at its slashes. Two questions decide
// whether a session stays workable: which ordinary directory names survive,
// and whether every shape of a path - relative, home-anchored, with a line
// number, inside a URL - comes back the way it went out. A replaced build
// directory is not a leak, but it makes every command the model writes fail.

import (
	"sort"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func newPaths(t *testing.T, cfg detect.PathsConfig) detect.Detector {
	t.Helper()
	d, err := detect.NewPaths(cfg)
	if err != nil {
		t.Fatalf("NewPaths: %v", err)
	}
	return d
}

// Which of the directory names every developer has does the preserve list
// know? Each one it does not know becomes a pseudonym, and a command built
// around it fails.
func TestPath_OrdinaryDevelopmentDirectories(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	segments := []string{
		"src", "lib", "bin", "test", "tests", "docs", "build", "dist",
		"cmd", "internal", "pkg", "vendor", "node_modules", "target",
		"detect", "payload", "mapping", "tools", "scripts", "config",
		"assets", "public", "static", "migrations", "fixtures", "examples",
		"main.go", "README.md", "go.mod", "Makefile",
	}
	var replaced []string
	for _, seg := range segments {
		tab := newTable(t)
		path := "/home/user/project/" + seg
		mid := forward(path, d, tab)
		if strings.Contains(mid, "/"+seg) {
			continue
		}
		replaced = append(replaced, seg)
	}
	t.Logf("%d of %d segments replaced: %s", len(replaced), len(segments), strings.Join(replaced, " "))
	if len(replaced) > len(segments)/2 {
		t.Logf("   -> with replace_unknown a source tree is largely unreadable to the model,")
		t.Logf("      and every path the model writes back has to survive the return pass intact")
	}
}

// Every shape a path takes on a terminal has to come back byte for byte.
func TestPath_ShapesRoundTrip(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	flat := strings.Join([]string{"", "home", "admin", "kunde-x"}, "-")
	paths := []string{
		"/home/admin/kunde/report.pdf",
		"./relative/kunde/file.txt",
		"../../kunde/data",
		"~/kunde/notes.md",
		"/home/admin/kunde/",
		"/home//admin///kunde",
		"kunde/sub/deep/file.go:42:13",
		"file:///home/admin/kunde/x.html",
		"https://example.test/home/admin/kunde/x",
		`C:\Users\admin\kunde\report.pdf`,
		"/mnt/backup/kunde-2026-09-06.tar.gz",
		"/home/admin/kunde/file with spaces.txt",
		"/home/admin/kunde/.hidden",
		"/home/admin/kunde/über.txt",
		"$HOME/kunde/bin",
		"kunde/",
		".config/kunde/bin",
		flat,
		strings.Join([]string{"projects", flat}, "/"),
		strings.Join([]string{flat, "abc.jsonl"}, "/"),
		"[README](../Kunden%20Akten/README-dockerSandbox.md)",
		"Input/Output.md",
		"'/home/admin/kunde/x'",
	}
	for _, p := range paths {
		tab := newTable(t)
		mid := forward(p, d, tab)
		got := back(mid, tab)
		if got != p {
			t.Errorf("round trip changed the path:\n  in %q\n out %q\n via %q", p, got, mid)
			continue
		}
		t.Logf("%-46q -> %s", p, mid)
	}
}

// A Markdown link writes a directory with a space in its name as
// "Kunden%20Akten". The forward pass divides the segment at the encoded
// space and leaves the "%20" standing between two pseudonyms, so the model
// sees that there is a space to decode. Both ways the model can write the
// path back restore: the link quoted as it was, and the path with the space
// decoded, which is the one it puts into a tool call. A segment replaced
// whole hid the encoding, and the model wrote "%20" into a file system
// path, where no such directory exists; seen live on the link of a README.
// The same directory listed with a real space gets the same pseudonyms, so
// the model can tell that the link and the listing name one directory.
func TestPath_EncodedSpaceInALink(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	tab := newTable(t)
	link := "[README](../Kunden%20Akten/README-dockerSandbox.md)"
	mid := forward(link, d, tab)
	kunden, akten := tab.Lookup(detect.KindPathSegment, "Kunden"), tab.Lookup(detect.KindPathSegment, "Akten")
	if want := "[README](../" + kunden + "%20" + akten + "/README-dockerSandbox.md)"; mid != want {
		t.Fatalf("forward(%q) = %q, want %q", link, mid, want)
	}
	if got := back(mid, tab); got != link {
		t.Errorf("the link quoted as it was:\n  in %q\n out %q", link, got)
	}
	decoded := strings.ReplaceAll(mid, "%20", " ")
	if got, want := back(decoded, tab), strings.ReplaceAll(link, "%20", " "); got != want {
		t.Errorf("the path with the space decoded:\n  in %q\n out %q\nwant %q", decoded, got, want)
	}
	listed := "/home/" + strings.Join([]string{"alice", "Kunden Akten", "README-dockerSandbox.md"}, "/")
	if got := forward(listed, d, tab); !strings.Contains(got, kunden+" "+akten) {
		t.Errorf("the listing with a real space: %q, want the same two pseudonyms around the space", got)
	}
}

// The rule the project settled on: file names stay readable, directories do
// not, and a term inside a file name is still found by the term layer.
func TestPath_FileNamesStayReadable(t *testing.T) {
	paths := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	terms := newTerms(t, detect.Term{Value: "kunde", Kind: detect.KindPathSegment})
	comp := detect.NewComposite(nil, terms, paths)

	cases := map[string]string{
		"plain file":        "/home/admin/projekt/main.go",
		"term in file name": "/home/admin/projekt/kunde-report.pdf",
		"term as directory": "/home/admin/kunde/report.pdf",
		"no extension":      "/home/admin/projekt/Makefile",
		"dotfile":           "/home/admin/projekt/.gitignore",
		"double extension":  "/home/admin/projekt/archiv.tar.gz",
	}
	for name, p := range cases {
		tab := newTable(t)
		mid := forward(p, comp, tab)
		if got := back(mid, tab); got != p {
			t.Errorf("%s: round trip:\n  in %q\n out %q", name, p, got)
		}
		t.Logf("%-18s %-44q -> %s", name, p, mid)
	}
}

// With replace_unknown off, only what the term list knows is replaced. That
// is the setting a user starts with, and it must not touch anything else.
func TestPath_WithoutReplaceUnknown(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{Known: map[string]bool{"kunde": true}})
	cases := map[string]bool{
		"/home/admin/kunde/report.pdf":   true,
		"/home/admin/projekt/report.pdf": false,
		"/usr/local/bin/tool":            false,
		"/etc/systemd/system/x.service":  false,
	}
	for p, wantChange := range cases {
		tab := newTable(t)
		mid := forward(p, d, tab)
		changed := mid != p
		if changed != wantChange {
			t.Errorf("%q: changed=%v, expected %v (%q)", p, changed, wantChange, mid)
		}
		if got := back(mid, tab); got != p {
			t.Errorf("round trip: %q -> %q", p, got)
		}
	}
}

// The path layer is the safety net for the directory a user forgot to put in
// the term list. A net has to hold in every shape a path is written in, and
// these are the shapes it lets through.
func TestPath_NetGapsForUnknownDirectories(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	const secret = "kundenakte"
	shapes := map[string]string{
		"absolute":            "/home/admin/" + secret + "/x.txt",
		"dot slash":           "./" + secret + "/x.txt",
		"bare relative":       secret + "/sub/x.txt",
		"variable anchored":   "$HOME/" + secret + "/x.txt",
		"tilde":               "~/" + secret + "/x.txt",
		"windows":             `C:\Users\admin\` + secret + `\x.txt`,
		"windows unc":         `\\server\share\` + secret + `\x.txt`,
		"file url":            "file:///home/admin/" + secret + "/x.txt",
		"http url":            "https://example.test/" + secret + "/x",
		"inside a word":       "backup-" + secret + "-2026.tar",
		"as a bare word":      "das Verzeichnis " + secret + " liegt daneben",
		"with drive relative": "d:" + secret + `\x.txt`,
		"trailing slash":      secret + "/",
		"dot start":           ".config/" + secret + "/bin",
		"bare directory":      secret + "/sub",
		"diff header":         "a/" + secret + "/x.go",
		"flattened":           "-home-user-" + secret,
		"flattened in a path": "projects/-home-user-" + secret,
	}
	var gaps []string
	for name, text := range shapes {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if strings.Contains(mid, secret) {
			gaps = append(gaps, name)
			t.Logf("%-24s left visible: %s", name, text)
			continue
		}
		t.Logf("%-24s caught:       %s -> %s", name, text, mid)
		if got := back(mid, tab); got != text {
			t.Errorf("%s: round trip: %q -> %q", name, text, got)
		}
	}
	sort.Strings(gaps)
	// The edge of the net as the README states it: a bare directory path
	// without a file or a closing slash, the a/ of a diff header, Windows,
	// URLs, and a name that is not a path at all. Every other shape is
	// caught, and a change here is a change of the README.
	want := []string{"as a bare word", "bare directory", "diff header", "file url", "http url",
		"inside a word", "windows", "windows unc", "with drive relative"}
	if strings.Join(gaps, ",") != strings.Join(want, ",") {
		t.Errorf("the edge of the net moved:\n got %v\nwant %v", gaps, want)
	}
	t.Logf("the net does not cover: %s", strings.Join(gaps, ", "))
	t.Logf("   -> a directory in the term list is caught by the term layer regardless;")
	t.Logf("      the gaps matter only for the directory nobody listed")
}

// A segment that already looks like a pseudonym must not be replaced again,
// or the second pass buries the first.
func TestPath_SegmentAlreadyShapedLikeAPseudonym(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	tab := newTable(t)
	comp := detect.NewComposite(tab.Knows, d)

	once := forward("/home/admin/kunde/report.pdf", comp, tab)
	twice := forward(once, comp, tab)
	if twice != once {
		t.Errorf("a second pass replaced again:\n once %q\ntwice %q", once, twice)
	}
}
