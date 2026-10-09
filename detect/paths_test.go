package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func newPaths(t *testing.T, cfg detect.PathsConfig) detect.Detector {
	t.Helper()
	d, err := detect.NewPaths(cfg)
	if err != nil || d == nil {
		t.Fatalf("NewPaths: %v", err)
	}
	return d
}

// values renders matches as kind:value for comparison.
func values(ms []detect.Match) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, string(m.Kind)+":"+m.Value)
	}
	return strings.Join(parts, " ")
}

func TestPaths_SegmentsOfAbsolutePath(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	text := "Der Code liegt in /home/mwendler/Projekte/kunde-x/src/main.go, die Doku in /home/mwendler/Projekte/kunde-x/README.md."
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	want := "path_segment:mwendler path_segment:Projekte path_segment:kunde-x filename:main.go " +
		"path_segment:mwendler path_segment:Projekte path_segment:kunde-x filename:README.md"
	if values(got) != want {
		t.Fatalf("Scan =\n%s\nwant\n%s", values(got), want)
	}
	// The sentence's full stop is not part of the file name.
	if last := got[len(got)-1]; text[last.End:] != "." {
		t.Fatalf("trailing dot swallowed: %q", text[last.Start:])
	}
}

func TestPaths_PreservedAndSkipped(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true, Preserve: []string{"Container"}})
	cases := map[string]string{
		"/mnt/part4/Container/cliproxyapi/config.yaml": "path_segment:part4 path_segment:cliproxyapi filename:config.yaml",
		"/etc/systemd/system/x.service":                "filename:x.service",
		"/proc/1234/status":                            "",
		"~/.config/nvim/init.lua":                      "path_segment:nvim filename:init.lua",
		"../kunde-x/./build/out":                       "path_segment:kunde-x",
		"/usr/local/bin":                               "",
		"/":                                            "",
		"/kunde-x/":                                    "path_segment:kunde-x",
		"cd /srv/nuc && ls":                            "path_segment:nuc",
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
}

// j joins bare segments into an absolute path at run time. The test source
// holds no slash path on purpose: a path in the source would be rewritten
// by the very plugin under test when the file travels through it.
func j(segs ...string) string { return "/" + strings.Join(segs, "/") }

// The ordinary names of a system stay: well-known files under etc, the
// device nodes, the tool directories. What names the owner, the customer
// or the machine is still reported, a unit name included, because a unit
// is often named after what it serves.
func TestPaths_OrdinaryNamesStay(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	untouched := []string{
		j("etc", "hosts"), j("etc", "hostname"), j("etc", "resolv.conf"), j("etc", "ssh", "sshd_config"),
		j("etc", "ssh", "ssh_host_ed25519_key.pub"), j("etc", "NetworkManager", "system-connections"),
		j("etc", "wireguard"), j("etc", "nginx", "sites-enabled"), j("etc", "docker", "daemon.json"),
		j("etc", "apt", "sources.list.d"), j("etc", "letsencrypt", "live"), j("etc", "cron.d"),
		j("var", "log", "journal"), j("var", "log", "syslog"), j("var", "lib", "docker", "containers"),
		j("dev", "sda1"), j("dev", "nvme0n1p2"), j("dev", "dm-0"), j("dev", "mapper"), j("dev", "disk", "by-id"),
		j("dev", "null"), j("dev", "ttyUSB0"), j("sys", "class", "net", "eth0", "address"),
		j("sys", "class", "net", "wlp3s0"), j("proc", "1234", "status"), j("proc", "cpuinfo"),
		j("usr", "lib", "python3", "dist-packages"), j("usr", "lib", "systemd", "system"),
		j("usr", "lib", "modules"), j("boot", "grub", "grub.cfg"), j("boot", "efi", "EFI"),
		j("run", "systemd", "resolve"), "~/" + strings.Join([]string{".ssh", "known_hosts"}, "/"), "~/" + strings.Join([]string{".config", "systemd", "user"}, "/"),
		j("opt", "containerd", "bin"), j("var", "www", "html"),
	}
	for _, path := range untouched {
		if got := d.Scan("see " + path + " now"); len(got) != 0 {
			t.Errorf("Scan(%q) = %q, want nothing", path, values(got))
		}
	}
	reported := map[string]string{
		j("home", "alice", "kunde-x"):                         "path_segment:alice path_segment:kunde-x",
		j("etc", "nginx", "sites-enabled", "kunde-x.conf"):    "filename:kunde-x.conf",
		j("etc", "wireguard", "wg0.conf"):                     "filename:wg0.conf",
		j("var", "log", "nginx", "kunde-x.log"):               "filename:kunde-x.log",
		j("mnt", "nas01", "fotos"):                            "path_segment:nas01 path_segment:fotos",
		j("opt", "myapp", "kunde-x", "config.yaml"):           "path_segment:myapp path_segment:kunde-x filename:config.yaml",
		j("etc", "systemd", "system", "backup-nas01.service"): "filename:backup-nas01.service",
		j("dev", "disk", "by-label", "nas01-data"):            "path_segment:nas01-data",
	}
	for text, want := range reported {
		if got := values(d.Scan(text)); got != want {
			t.Errorf("Scan(%q) = %q, want %q", text, got, want)
		}
	}
}

func TestPaths_ProseAndURLsUntouched(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	for _, text := range []string{
		"and/or, km/h, TCP/IP, 1/2 und 3/4",
		"https://example.com/kunde-x/docs",
		"file:///home/mwendler/x",
		"a//b",
		"Version 1.2/rc1",
		"nichts zu tun",
	} {
		if got := d.Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %q, want nothing", text, values(got))
		}
	}
	// The path after a URL's query is still prose, but a path after a
	// space is a path.
	if got := d.Scan("siehe https://example.com/x und /home/mwendler"); values(got) != "path_segment:mwendler" {
		t.Errorf("mixed = %q", values(got))
	}
}

// TestPaths_FilenamesLeftToTerms: by default the layer reports directories
// only. A file name stays as it is, whatever it is called, and a customer's
// name inside a file name is the term layer's business: it runs first, hits
// at the word boundary, and the composite keeps that hit.
func TestPaths_FilenamesLeftToTerms(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	cases := map[string]string{
		j("home", "mwendler", "Projekte", "kunde-x", "src", "main.go"): "path_segment:mwendler path_segment:Projekte path_segment:kunde-x",
		j("home", "mwendler", "Projekte", "kunde-x", "README.md"):      "path_segment:mwendler path_segment:Projekte path_segment:kunde-x",
		j("opt", "myapp", "kunde-x", "config.yaml"):                    "path_segment:myapp path_segment:kunde-x",
		j("etc", "nginx", "sites-enabled", "kunde-x.conf"):             "",
		j("home", "mwendler", "Projekte", "kunde-x", "Makefile"):       "path_segment:mwendler path_segment:Projekte path_segment:kunde-x",
		j("home", "mwendler", "media-files"):                           "path_segment:mwendler path_segment:media-files", // no extension: a directory
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}

	// With the term layer in front, the customer's name is found inside the
	// file name, as the term's own kind, while the ordinary file name and
	// the ordinary directory stay.
	terms, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: []detect.Term{
		{Value: "kunde-x", Kind: detect.KindPathSegment},
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := detect.NewComposite(nil, terms, d)
	text := j("home", "mwendler", "docs", "kunde-x-vertrag.pdf") + " and " + j("home", "mwendler", "docs", "README.md")
	got := c.Scan(text)
	assertDisjointSorted(t, text, got)
	if want := "path_segment:mwendler path_segment:kunde-x path_segment:mwendler"; values(got) != want {
		t.Fatalf("composite Scan = %q, want %q", values(got), want)
	}
}

func TestPaths_KnownOnly(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: false, Known: map[string]bool{"kunde-x": true}})
	got := d.Scan("/home/mwendler/Projekte/kunde-x/src/main.go")
	if values(got) != "path_segment:kunde-x" {
		t.Fatalf("Scan = %q, want only the known segment", values(got))
	}
}

func TestPaths_UnicodeSegments(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	text := "in /home/mwendler/Bücher/Übersicht.txt steht es"
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	if values(got) != "path_segment:mwendler path_segment:Bücher filename:Übersicht.txt" {
		t.Fatalf("Scan = %q", values(got))
	}
}

// r joins bare segments into a relative path at run time, for the same
// reason as j; a trailing empty segment gives the closing slash.
func r(segs ...string) string { return strings.Join(segs, "/") }

// A bare token is a path when its shape says so: an extension at the end,
// a slash at the end, a hidden directory in front, a shell variable in
// front, or a working directory flattened into one name. Prose with a
// slash, module paths, media types, git refs, package scopes, sed
// expressions, diff headers and flags are not, and neither is the bare
// directory path "kunde/sub", which no rule can tell from "km/h".
func TestPaths_BareShapes(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	flat := strings.Join([]string{"", "home", "mwendler", "kunde-x"}, "-")
	flatTmp := strings.Join([]string{"", "tmp", "claude-1234", "kunde-x", "sub"}, "-")
	caught := map[string]string{
		r("kunde-x", "vertrag.pdf"):                         "path_segment:kunde-x",
		r("internal", "kunde-x", "paths_test.go") + ":12:5": "path_segment:kunde-x",
		"modified:   " + r("kunde-x", "main.go"):            "path_segment:kunde-x",
		r("kunde-x", ""):                                    "path_segment:kunde-x",
		"ls " + r("kunde-x", "") + " && pwd":                "path_segment:kunde-x",
		r(".config", "kunde-x", "bin"):                      "path_segment:kunde-x",
		"$HOME/" + r("kunde-x", "bin"):                      "path_segment:kunde-x",
		"$my_dir/" + r("kunde-x", "bin"):                    "path_segment:kunde-x",
		flat:                                                "path_segment:" + flat,
		"ls -la " + flat:                                    "path_segment:" + flat,
		r("projects", flat):                                 "path_segment:projects path_segment:" + flat,
		r(flat, "abc.jsonl"):                                "path_segment:" + flat,
		r(flat, "0b3f9c2e"):                                 "path_segment:" + flat + " path_segment:0b3f9c2e",
		r("projects", flat, "0b3f9c2e"):                     "path_segment:projects path_segment:" + flat + " path_segment:0b3f9c2e",
		flatTmp:                                             "path_segment:" + flatTmp,
		"[doc](" + r("kunde-x", "README.md") + ")":          "path_segment:kunde-x",
		"siehe " + r("kunde-x", "notes.md") + ".":           "path_segment:kunde-x",
		"--out=" + r("kunde-x", "a.txt"):                    "path_segment:kunde-x",
		r("Input", "Output.md"):                             "path_segment:Input", // the price of the extension rule
	}
	for text, want := range caught {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
	untouched := []string{
		"and/or, km/h, TCP/IP, Client/Server, Ja/Nein, I/O, w/o",
		"application/json, text/html, image/svg+xml, application/vnd.ms-excel",
		"origin/main, feature/kunde-x, refs/heads/main",
		"github.com/rheodev/x/y.go, golang.org/x/net",
		"@scope/pkg/index.js",
		"sed 's/kunde-x/y/g' and y/abc/xyz/",
		"--- a/kunde-x/x.go",
		"24/09/2026, 1/2, 3/4.",
		r("kunde-x", "sub"), // the bare directory path: the edge that stays
		"a//b, x.y/z.txt, ..foo/x, .../x",
		"-la -rf -fno-omit-frame-pointer -Wno-unused-but-set-variable",
		"-var-file=x.tfvars --no-verify -home -home-x",
		"$HOME und $5/hour und US$100/month",
		"Version 1.2/rc1",
	}
	for _, text := range untouched {
		if got := d.Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %q, want nothing", text, values(got))
		}
	}
}

// An encoded space divides a segment into words: a Markdown link writes a
// directory with a space in its name as "Kunden%20Akten", and each word is
// reported on its own with the "%20" left standing between them, so the
// model sees the encoded space and can decode it. The words of a file name
// belong to the file name: left alone by default, replaced one by one with
// AllFilenames, the extension on the last. Empty words, at the edges of a
// segment or between two escapes, are not reported.
func TestPaths_EncodedSpaceDividesASegment(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	link := "[README](../Kunden%20Akten/README-dockerSandbox.md)"
	got := d.Scan(link)
	assertDisjointSorted(t, link, got)
	if want := "path_segment:Kunden path_segment:Akten"; values(got) != want {
		t.Fatalf("Scan(%q) = %q, want %q", link, values(got), want)
	}
	if between := link[got[0].End:got[1].Start]; between != "%20" {
		t.Fatalf("between the two words stands %q, want the encoded space", between)
	}
	cases := map[string]string{
		j("home", "alice", "Kunden%20Akten", "notes.md"): "path_segment:alice path_segment:Kunden path_segment:Akten",
		j("home", "alice", "Kunden%20Akten%20Meier", ""): "path_segment:alice path_segment:Kunden path_segment:Akten path_segment:Meier",
		j("home", "alice", "%20Kunden%20", "x.txt"):      "path_segment:alice path_segment:Kunden",
		j("home", "alice", "src%20tree"):                 "path_segment:alice path_segment:tree", // src is preserved, tree is not
		j("home", "alice", "Kunden%20Bericht.md"):        "path_segment:alice",                   // a file name, both words of it
		"Kunden%20Akten": "", // no slash, no path
		"%20":            "",
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
	all := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	text := j("home", "alice", "Kunden%20Bericht.md")
	got = all.Scan(text)
	assertDisjointSorted(t, text, got)
	if want := "path_segment:alice filename:Kunden filename:Bericht.md"; values(got) != want {
		t.Fatalf("AllFilenames: Scan(%q) = %q, want %q", text, values(got), want)
	}
}

// A real space inside a directory name. A shell writes it in quotes or
// behind a backslash, a tool argument holds the path and nothing else, and
// all three forms are read as one path: each word of the name gets a
// pseudonym of its own, and the space, the backslash, the ampersand stay
// between them. Where nothing says the name goes on, the space ends the
// path as it always did, so prose behind a path is prose; the middle word
// of a bare three-word name is the limit, and a slashed word of prose right
// behind a bare path is the price.
func TestPaths_SpaceInsideADirectoryName(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	const name = "path_segment:alice path_segment:Kunden path_segment:Akten path_segment:Berichte"
	cases := map[string]string{
		// Quoted: the path runs to the closing quote on the line.
		`cd "/home/alice/Kunden Akten/Berichte"`:         name,
		`cd '/home/alice/Kunden Akten/Berichte'`:         name,
		"ls `/home/alice/Kunden Akten/Berichte`":         name,
		`"/home/alice/Müller & Söhne/Berichte"`:          "path_segment:alice path_segment:Müller path_segment:Söhne path_segment:Berichte",
		`"/home/alice/Akten (2023)/notiz.md"`:            "path_segment:alice path_segment:Akten",
		`-v "/home/alice/Kunden Akten:/Ablage"`:          "path_segment:alice path_segment:Kunden path_segment:Akten path_segment:Ablage",
		`{"file_path": "/home/alice/Kunden Akten/x.md"}`: "path_segment:alice path_segment:Kunden path_segment:Akten",
		`"$HOME/Kunden Akten"`:                           "path_segment:Kunden path_segment:Akten",
		`"${HOME}/Kunden Akten"`:                         "path_segment:Kunden path_segment:Akten",
		`"/home/alice/x.go: fix the test"`:               "path_segment:alice",                // a file name ends the path
		`"/home/alice/x.go:"`:                            "path_segment:alice",                // and the colon is not part of it
		`"/home/alice/x?a=b c"`:                          "path_segment:alice path_segment:x", // the query ends it
		`"/home/alice/Kunden Akten`:                      "path_segment:alice path_segment:Kunden",
		`"/home/alice/a b" "/home/alice/c d"`:            "path_segment:alice path_segment:a path_segment:b path_segment:alice path_segment:c path_segment:d",
		"\"/home/alice/Kunden\nAkten/x\"":                "path_segment:alice path_segment:Kunden",
		// Escaped: the shell's own spelling of a space in a name.
		`cd /home/alice/Kunden\ Akten/Berichte`: name,
		`cd /home/alice/Kunden\ `:               "path_segment:alice path_segment:Kunden",
		// Bare: the word behind the space carries a slash of its own.
		`/home/alice/Kunden Akten/Berichte`:          name,
		`/home/alice/Kunden Akten/Berichte/notiz.md`: name,
		`/home/alice/Kunden und Akten/Berichte`:      "path_segment:alice path_segment:Kunden", // the limit
		`cp /home/alice/a.txt backup/x`:              "path_segment:alice",
		`mv /home/alice/a /home/alice/b`:             "path_segment:alice path_segment:a path_segment:alice path_segment:b",
		`/home/alice/x und https://example.com/y`:    "path_segment:alice path_segment:x",
		`/home/alice/x. Dann/oder`:                   "path_segment:alice path_segment:x",
		`/home/alice/x ./y/z`:                        "path_segment:alice path_segment:x path_segment:y path_segment:z",
		`/home/alice/x TCP/IP`:                       "path_segment:alice path_segment:x path_segment:TCP path_segment:IP", // the price
	}
	for text, want := range cases {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
	// What stands between the words stays: the space, the escaped space.
	for text, between := range map[string]string{
		`cd "/home/alice/Kunden Akten/Berichte"`: " ",
		`cd /home/alice/Kunden\ Akten/Berichte`:  `\ `,
		`/home/alice/Kunden Akten/Berichte`:      " ",
	} {
		got := d.Scan(text)
		if len(got) != 4 || text[got[1].End:got[2].Start] != between {
			t.Errorf("Scan(%q): between Kunden and Akten stands %q, want %q", text, text[got[1].End:got[2].Start], between)
		}
	}
	// The words of a file name with a space belong to the file name.
	all := newPaths(t, detect.PathsConfig{ReplaceUnknown: true, AllFilenames: true})
	text := `"/home/alice/Kunden Akten/Bericht final.md"`
	got := all.Scan(text)
	assertDisjointSorted(t, text, got)
	if want := "path_segment:alice path_segment:Kunden path_segment:Akten filename:Bericht filename:final.md"; values(got) != want {
		t.Fatalf("AllFilenames: Scan(%q) = %q, want %q", text, values(got), want)
	}
	if got := d.Scan(text); values(got) != "path_segment:alice path_segment:Kunden path_segment:Akten" {
		t.Fatalf("Scan(%q) = %q, want the file name left alone", text, values(got))
	}
}

// The slash of a tag is not a path: "</p>" is markup, and so are
// "</div></section>" and the self-closing "<br/>" and "<input disabled/>",
// whose slash would otherwise pass as the trailing slash of a directory.
// A path in an attribute value and the input redirection of the shell,
// "done </home/x/list.txt", keep their slash: the one has a quote in
// front, the other more than one segment behind the "<".
func TestPaths_ClosingTagIsNotAPath(t *testing.T) {
	d := newPaths(t, detect.PathsConfig{ReplaceUnknown: true})
	for _, text := range []string{
		"<p>Text</p>",
		"</div>",
		"<h3>Titel</h3>",
		"</section></article>",
		"<br/> <br /> <img src=x/> <input disabled/> <img src=foo/>",
		"<my-component></my-component>",
		"<ul>\n  <li>eins</li>\n</ul>",
	} {
		if got := d.Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %q, want nothing", text, values(got))
		}
	}
	caught := map[string]string{
		`<a href="/kunde-x/seite.html">`: "path_segment:kunde-x",
		"done </home/kunde-x/list.txt":   "path_segment:kunde-x",
		"<pre>/home/kunde-x/</pre>":      "path_segment:kunde-x",
		"<code>kunde-x/notes.md</code>":  "path_segment:kunde-x",
	}
	for text, want := range caught {
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if values(got) != want {
			t.Errorf("Scan(%q) = %q, want %q", text, values(got), want)
		}
	}
}
