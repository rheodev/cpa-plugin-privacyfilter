package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// TestAudit_RecordsTableAndRestores: with audit.path set, the forward pass
// writes the mapping table, the return path's swaps are counted, and the
// completion writes them out; the file is created with mode 0600.
func TestAudit_RecordsTableAndRestores(t *testing.T) {
	dir := t.TempDir()
	p := newPseudoPlugin(t, map[string]any{"audit": map[string]any{"path": "audit.log"}})
	// newPseudoPlugin's plugin dir is its own temp dir; the relative path
	// must have resolved there.
	if p.audit == nil || filepath.Base(p.audit.path) != "audit.log" || filepath.Dir(p.audit.path) == dir {
		t.Fatalf("audit = %+v, want a log next to the plugin", p.audit)
	}
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-audit", body)
	table, err := p.store.Get("req-audit")
	if err != nil {
		t.Fatal(err)
	}
	host := table.Lookup(detect.KindHost, "athene.lan")

	// A non-streamed response that repeats the host pseudonym twice.
	resp := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ping ` + host + ` und nochmal ` + host + `"}],"model":"claude-fable-5-1"}`)
	out, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: "req-audit", SourceFormat: "claude", Model: "claude-fable-5-1", Body: resp, StatusCode: 200,
	})
	if err != nil || !strings.Contains(string(out.Body), "athene.lan") {
		t.Fatalf("response not restored: %v %s", err, out.Body)
	}
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{
		RequestID: "req-audit", Outcome: pluginapi.RequestCompletionSucceeded, Stream: false,
	}); err != nil {
		t.Fatal(err)
	}

	st, err := os.Stat(p.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("audit file mode = %o, want 600", st.Mode().Perm())
	}
	raw, err := os.ReadFile(p.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"\trequest\treq-audit\tformat=claude\tsession=metadata\t",
		"\tmap\treq-audit\thost\tathene.lan\t" + host + "\n",
		"\tmap\treq-audit\tperson\tMarkus\t",
		"\trestored\treq-audit\t" + host + "\tathene.lan\t2\n",
		"\tcomplete\treq-audit\toutcome=succeeded\tstream=false\trestored_distinct=1\trestored_total=2\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("audit log lacks %q\n%s", want, text)
		}
	}
	// Every table row is in the file, none twice.
	for _, e := range table.Entries() {
		line := "\tmap\treq-audit\t" + string(e.Kind) + "\t" + auditField(e.Original) + "\t" + auditField(e.Pseudonym) + "\n"
		if strings.Count(text, line) != 1 {
			t.Errorf("row %q appears %d times", line, strings.Count(text, line))
		}
	}
}

// TestAudit_RecordsTheSecondPass: the pass in the hook after authentication
// writes a block of its own, headed by a request line with session=bound,
// with the rows it added and none of the first pass's; a second pass that
// adds nothing writes nothing.
func TestAudit_RecordsTheSecondPass(t *testing.T) {
	const injected = "10.77.0.80"
	p := newPseudoPlugin(t, map[string]any{"audit": map[string]any{"path": "audit.log"}})
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-audit", body)
	table := p.tableOf(t, "req-audit")

	quiet := afterAuth(t, p, "req-audit", first.Body)
	if quiet.Body != nil {
		t.Fatalf("the second pass over the first pass's output changed it: %s", quiet.Body)
	}
	between := bytes.Replace(first.Body, []byte(`"max_tokens":4096`), []byte(`"max_tokens":4096,"memory":"reach `+injected+`"`), 1)
	if bytes.Equal(between, first.Body) {
		t.Fatal("the fixture lost the field the test splices after")
	}
	after := afterAuth(t, p, "req-audit", between)
	if after.Body == nil || !table.Has(detect.KindIPv4, injected) {
		t.Fatalf("the second pass did not replace the injected address: %s", after.Body)
	}
	address := table.Lookup(detect.KindIPv4, injected)

	raw, err := os.ReadFile(p.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for line, want := range map[string]int{
		"\trequest\treq-audit\tformat=claude\tsession=metadata\t":     1,
		"\trequest\treq-audit\tformat=claude\tsession=bound\t":        1,
		"\tmap\treq-audit\tipv4\t" + injected + "\t" + address + "\n": 1,
		"\tmap\treq-audit\thost\tathene.lan\t":                        1,
	} {
		if got := strings.Count(text, line); got != want {
			t.Errorf("audit log carries %q %d times, want %d\n%s", line, got, want, text)
		}
	}
	bound := strings.Index(text, "session=bound")
	if bound < 0 || !strings.Contains(text[bound:], "\tmap\treq-audit\tipv4\t"+injected+"\t") {
		t.Errorf("the row of the second pass is not in the second pass's block\n%s", text)
	}
}

// TestAudit_OffByDefaultAndBadPathFails: no audit without a path, and a
// path in a directory that does not exist refuses registration.
func TestAudit_OffByDefaultAndBadPathFails(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	if p.audit != nil {
		t.Fatal("audit is on without audit.path")
	}
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-noaudit", body)
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: "req-noaudit"}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	raw := []byte("mode: pseudonymize\nsalt_secret_path: " + filepath.Join(dir, "pseudonym.secret") + "\naudit:\n  path: " + filepath.Join(dir, "missing", "audit.log") + "\n")
	if err := os.WriteFile(filepath.Join(dir, "pseudonym.secret"), append(append([]byte{}, fixtures.Secret...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin(raw, dir, nil)
	assertBlocked(t, plugin, err, "audit.path")
}

// TestAudit_Rotates: a file above max_bytes is moved to ".1" before the
// next write, so the log never grows without bound.
func TestAudit_Rotates(t *testing.T) {
	dir := t.TempDir()
	a, err := newAuditLog(dir, "audit.log", 64)
	if err != nil {
		t.Fatal(err)
	}
	a.write(strings.Repeat("x", 100) + "\n")
	a.write("second\n")
	if _, err := os.Stat(a.path + ".1"); err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	raw, _ := os.ReadFile(a.path)
	if string(raw) != "second\n" {
		t.Fatalf("current file = %q, want only the second write", raw)
	}
}

// TestAuditField: values that would break the one-line format are quoted,
// ordinary ones are not.
func TestAuditField(t *testing.T) {
	cases := map[string]string{
		"athene.lan":                          "athene.lan",
		"Ingrid Muster":                       "Ingrid Muster",
		"":                                    `""`,
		"a\tb":                                `"a\tb"`,
		"line\nbreak":                         `"line\nbreak"`,
		" padded":                             `" padded"`,
		"/home/d-2c0ede3ad9e6/d-a7f3fe7a7b53": "/home/d-2c0ede3ad9e6/d-a7f3fe7a7b53",
	}
	for in, want := range cases {
		if got := auditField(in); got != want {
			t.Errorf("auditField(%q) = %q, want %q", in, got, want)
		}
	}
}
