package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseTermsFile_Forms(t *testing.T) {
	in := strings.Join([]string{
		"# maintained list",
		"",
		"p14.local",
		"p14 host   # short name",
		"markus person ignore_case",
		"wendler.de domain",
		`{regex: "[a-z0-9-]+\\.home\\.lan", kind: host}`,
		`{value: "Max Muster", kind: person, ignore_case: true}`,
		`{value: "10.13.0.0/16", kind: cidr}   # comment after yaml`,
		"  ",
	}, "\n")
	got, err := parseTermsFile(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseTermsFile: %v", err)
	}
	want := []TermEntry{
		{Value: "p14.local", Kind: "host"},
		{Value: "p14", Kind: "host"},
		{Value: "markus", Kind: "person", IgnoreCase: true},
		{Value: "wendler.de", Kind: "domain"},
		{Regex: `[a-z0-9-]+\.home\.lan`, Kind: "host"},
		{Value: "Max Muster", Kind: "person", IgnoreCase: true},
		{Value: "10.13.0.0/16", Kind: "cidr"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTermsFile =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseTermsFile_Errors(t *testing.T) {
	for _, in := range []string{
		"p14 host extra",
		"p14 host person",
		"{value: p14, kinds: host}",
		"{value: p14, kind: host",
		"p14 host ignore_case ignore_case",
	} {
		if _, err := parseTermsFile(strings.NewReader(in)); err == nil {
			t.Errorf("parseTermsFile(%q) accepted", in)
		} else if !strings.Contains(err.Error(), "line 1") {
			t.Errorf("parseTermsFile(%q) error %q does not name the line", in, err)
		} else if strings.Contains(err.Error(), "p14") {
			// The message reaches the log and, since the blocking state,
			// the client. It names the line, never what is on it.
			t.Errorf("parseTermsFile(%q) error %q quotes the line", in, err)
		}
	}
}

func TestMergeTerms_DedupKeepsFirst(t *testing.T) {
	inline := []TermEntry{{Value: "p14", Kind: "host"}, {Value: "markus", Kind: "person", IgnoreCase: true}}
	file := []TermEntry{{Value: "p14", Kind: "host"}, {Value: "p14", Kind: "person"}, {Value: "nuc", Kind: "host"}}
	got := mergeTerms(inline, file)
	want := []TermEntry{inline[0], inline[1], file[1], file[2]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeTerms = %+v, want %+v", got, want)
	}
}

func TestResolveTermsFilePath(t *testing.T) {
	if got := resolveTermsFilePath("/plugins", ""); got != "" {
		t.Fatalf("empty -> %q", got)
	}
	if got := resolveTermsFilePath("/plugins", "terms.txt"); got != filepath.Join("/plugins", "terms.txt") {
		t.Fatalf("relative -> %q", got)
	}
	if got := resolveTermsFilePath("/plugins", "/etc/terms.txt"); got != "/etc/terms.txt" {
		t.Fatalf("absolute -> %q", got)
	}
}

func TestLoadTermsFile_MissingAndInvalid(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadTermsFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatal("missing file accepted")
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("ok host\nbroken host extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadTermsFile(bad)
	if err == nil || !strings.Contains(err.Error(), "line 2") || !strings.Contains(err.Error(), bad) {
		t.Fatalf("loadTermsFile error = %v, want path and line 2", err)
	}
}

// TestPseudonymize_TermsFileMerged builds the plugin with an inline term and
// a term file and checks that both are applied and that a broken file refuses
// registration.
func TestPseudonymize_TermsFileMerged(t *testing.T) {
	dir := t.TempDir()
	termsPath := filepath.Join(dir, "terms.txt")
	if err := os.WriteFile(termsPath, []byte("# hosts\np14.local\np14 host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newPseudoPlugin(t, map[string]any{
		"terms":      []any{map[string]any{"value": "nuc", "kind": "host"}},
		"terms_file": termsPath,
	})
	if p.termCount != 3 {
		t.Fatalf("termCount = %d, want 3", p.termCount)
	}
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"ssh p14.local; ssh p14; ssh nuc; p140 bleibt"}]}`)
	res, err := p.runForward(nil, nil, body)
	if err != nil {
		t.Fatalf("runForward: %v", err)
	}
	out := string(res.out)
	for _, leaked := range []string{"p14.local", "ssh p14;", "ssh nuc"} {
		if strings.Contains(out, leaked) {
			t.Errorf("%q survived: %s", leaked, out)
		}
	}
	if !strings.Contains(out, "p140 bleibt") {
		t.Errorf("word boundary broken: %s", out)
	}

	if err := os.WriteFile(termsPath, []byte("p14 host extra\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := "mode: pseudonymize\nsalt_secret_path: " + filepath.Join(dir, "s.secret") + "\nterms_file: " + termsPath + "\n"
	if err := os.WriteFile(filepath.Join(dir, "s.secret"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin([]byte(cfgYAML), dir, nil)
	assertBlocked(t, plugin, err, "terms_file")
}

// A '#' inside a value belongs to the value. Cutting the line at every '#'
// loaded such a term truncated and left the part behind the '#' unprotected,
// which is the opposite of what the list is for.
func TestParseTermsFile_HashInsideAValue(t *testing.T) {
	in := strings.Join([]string{
		"# a comment on its own line",
		"   # an indented comment",
		"Projekt#42 path_segment",
		"p14.local host   # trailing comment",
		"ticket#7#8 path_segment",
		"#leading path_segment",
	}, "\n")
	got, err := parseTermsFile(strings.NewReader(in))
	if err != nil {
		t.Fatalf("parseTermsFile: %v", err)
	}
	want := []TermEntry{
		{Value: "Projekt#42", Kind: "path_segment"},
		{Value: "p14.local", Kind: "host"},
		{Value: "ticket#7#8", Kind: "path_segment"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTermsFile =\n%+v\nwant\n%+v", got, want)
	}
}

// An editor on Windows writes a byte order mark ahead of the first line.
// TrimSpace does not remove it, so without the cure the first term of the
// list is a different string from the one the user typed and protects
// nothing. The mark is written as its three bytes because the compiler
// rejects the character itself in source.
func TestParseTermsFile_ByteOrderMark(t *testing.T) {
	got, err := parseTermsFile(strings.NewReader("\xef\xbb\xbfp14.local host\np14 host"))
	if err != nil {
		t.Fatalf("parseTermsFile: %v", err)
	}
	want := []TermEntry{
		{Value: "p14.local", Kind: "host"},
		{Value: "p14", Kind: "host"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTermsFile =\n%+v\nwant\n%+v", got, want)
	}
}

// A wrong kind in the term file is reported with the line the user has to
// edit and the vocabulary that is accepted, and a value that carries a
// character with a meaning in a command line or a configuration file is
// counted for the warning at registration.
func TestTermsFile_KindReportNamesTheLine(t *testing.T) {
	dir := t.TempDir()
	termsPath := filepath.Join(dir, "terms.txt")
	if err := os.WriteFile(termsPath, []byte("# hosts\n\np14 host\nnuc hostname\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s.secret"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := "mode: pseudonymize\nsalt_secret_path: " + filepath.Join(dir, "s.secret") + "\nterms_file: " + termsPath + "\n"
	plugin, err := buildPlugin([]byte(cfgYAML), dir, nil)
	assertBlocked(t, plugin, err, "line 4", `"hostname"`, "host, domain", "path_segment")
}

// The characters that are structure somewhere: in a shell, a comment, a
// crontab, a path, a JSON document. Letters of any script are not among
// them, so a Chinese, a Turkish or a German name passes; a network keeps its
// slash, and a regular expression is not judged at all.
func TestTermsFile_UnsafeValues(t *testing.T) {
	unsafe := []string{
		"Meier & Sohn", "Kunden/Meier", "q3%2026", "Projekt#42", "Sean O'Connor",
		"a;b", "a|b", "a`b", "a$b", "a<b", "a>b", `a"b`, "a" + string(rune(92)) + "b",
		"a" + string(rune(9)) + "b", "a" + string(rune(10)) + "b", "a" + string(rune(13)) + "b",
		"a" + string(rune(27)) + "b", "北京#42",
	}
	safe := []string{
		"zeus.lan", "Meier GmbH", "kunde-x", "Müller Söhne", "Straßburger", "a.b*c", "kunde(x)",
		"北京客户", "東京 支店", "Ünal İş", "Ærø Kommune", "Владимир", "Ａｃｍｅ", "客户【42】",
	}
	for _, v := range unsafe {
		if termUnsafe(TermEntry{Value: v, Kind: "path_segment"}) == "" {
			t.Errorf("%q passed", v)
		}
	}
	for _, v := range safe {
		if class := termUnsafe(TermEntry{Value: v, Kind: "person"}); class != "" {
			t.Errorf("%q was refused as %s", v, class)
		}
	}
	if termUnsafe(TermEntry{Value: "10.13.0.0/16", Kind: "cidr"}) != "" {
		t.Error("the slash of a network was counted")
	}
	// Key material and tokens are base64, and base64 has the slash; the
	// secret pseudonym stands where the blob stands, never in a path.
	keyMaterial := "AAAAC3NzaC1lZDI1NTE5AAAAIGQ/x+7l" + strings.Repeat("Ab", 8) + "/o="
	if termUnsafe(TermEntry{Value: keyMaterial, Kind: "secret"}) != "" {
		t.Error("the slash of a secret was counted")
	}
	if termUnsafe(TermEntry{Value: keyMaterial, Kind: "host"}) != "a /" {
		t.Error("the slash of a host was let through")
	}
	// A SHA256 fingerprint is base64 as well, 43 characters after the label.
	fingerprint := "SHA256:" + strings.Repeat("Qz", 14) + "/d-c60d0c82e19f"
	if termUnsafe(TermEntry{Value: fingerprint, Kind: "fingerprint"}) != "" {
		t.Error("the slash of a fingerprint was counted")
	}
	if termUnsafe(TermEntry{Value: "a$b", Kind: "secret"}) != "a shell metacharacter ($)" {
		t.Error("a secret with a dollar sign was let through, or the class is not named")
	}
	if termUnsafe(TermEntry{Regex: `kunde/[0-9]+;`, Kind: "path_segment"}) != "" {
		t.Error("a regular expression was judged")
	}
}

// The loader refuses such a value at start and names the line of the terms
// file, not the value.
func TestTermsFile_UnsafeValueIsRefusedWithTheLine(t *testing.T) {
	dir := t.TempDir()
	termsPath := filepath.Join(dir, "terms.txt")
	file := "# hosts" + string(rune(10)) + string(rune(10)) + "p14 host" + string(rune(10)) + "{value: " + string(rune(34)) + "Meier & Sohn" + string(rune(34)) + ", kind: person}" + string(rune(10))
	if err := os.WriteFile(termsPath, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "s.secret"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := "mode: pseudonymize" + string(rune(10)) + "salt_secret_path: " + filepath.Join(dir, "s.secret") + string(rune(10)) + "terms_file: " + termsPath + string(rune(10))
	plugin, err := buildPlugin([]byte(cfgYAML), dir, nil)
	body := assertBlocked(t, plugin, err, "line 4", "value carries a shell metacharacter (&)")
	if strings.Contains(body, "Meier") {
		t.Errorf("the client message %q quotes the value", body)
	}

	inline := "mode: pseudonymize" + string(rune(10)) + "salt_secret_path: " + filepath.Join(dir, "s.secret") + string(rune(10)) + "terms:" + string(rune(10)) + "  - {value: " + string(rune(34)) + "a;b" + string(rune(34)) + ", kind: host}" + string(rune(10))
	plugin, err = buildPlugin([]byte(inline), dir, nil)
	assertBlocked(t, plugin, err, "terms[0]")
}
