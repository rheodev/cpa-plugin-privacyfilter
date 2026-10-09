package payload_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPath_String(t *testing.T) {
	p := payload.Path{"messages", "2", "content", "0", "text"}
	if got := p.String(); got != "messages[2].content[0].text" {
		t.Fatalf("String = %q", got)
	}
	if got := (payload.Path{"system"}).String(); got != "system" {
		t.Fatalf("String = %q", got)
	}
}

func TestWalk_VisitsEverythingExceptDenied(t *testing.T) {
	body := mustJSON(t, fixtures.Request(fixtures.SessionA))
	visited := map[string]string{}
	_, changed, err := payload.Walk(body, payload.WalkOptions{}, func(p payload.Path, v string) (string, bool) {
		visited[p.String()] = v
		return v, false
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if changed {
		t.Fatal("changed must be false when no visitor reported a change")
	}
	mustVisit := []string{
		"system[0].text",
		"tools[0].description",
		"messages[0].content",
		"messages[1].content[1].input.command",
		"messages[2].content[0].content",
		"messages[2].content[1].text",
	}
	for _, p := range mustVisit {
		if _, ok := visited[p]; !ok {
			t.Errorf("path %s not visited; visited: %v", p, keys(visited))
		}
	}
	mustNotVisit := []string{
		"model",
		"metadata.user_id",
		"system[0].type",
		"system[0].cache_control.type",
		"tools[0].name",
		"tools[0].input_schema.type",
		"tools[0].input_schema.properties.command.type",
		"messages[0].role",
		"messages[1].content[0].type",
		"messages[1].content[0].thinking",
		"messages[1].content[0].signature",
		"messages[1].content[1].id",
		"messages[1].content[1].name",
		"messages[2].content[0].tool_use_id",
	}
	for _, p := range mustNotVisit {
		if v, ok := visited[p]; ok {
			t.Errorf("denied path %s visited with %q", p, v)
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestWalk_UnchangedReturnsSameBytes(t *testing.T) {
	body := mustJSON(t, fixtures.Request(fixtures.SessionA))
	out, changed, err := payload.Walk(body, payload.WalkOptions{}, func(p payload.Path, v string) (string, bool) { return v, false })
	if err != nil || changed {
		t.Fatalf("Walk = changed %v, err %v", changed, err)
	}
	if !bytes.Equal(out, body) || len(out) == 0 || &out[0] != &body[0] {
		t.Fatal("unchanged walk must return the input slice itself")
	}
}

func TestWalk_ReplacesAndReserializesStably(t *testing.T) {
	body := mustJSON(t, fixtures.Request(fixtures.SessionA))
	repl := func(p payload.Path, v string) (string, bool) {
		if strings.Contains(v, "athene.lan") {
			return strings.ReplaceAll(v, "athene.lan", "h-0badcafe"), true
		}
		return v, false
	}
	out1, changed, err := payload.Walk(body, payload.WalkOptions{}, repl)
	if err != nil || !changed {
		t.Fatalf("Walk = changed %v, err %v", changed, err)
	}
	if bytes.Contains(out1, []byte("athene.lan")) {
		t.Fatal("replacement did not reach every visited string")
	}
	if !bytes.Contains(out1, []byte(fixtures.ThinkingSignature)) || !bytes.Contains(out1, []byte("ich pinge 10.13.7.42")) {
		t.Fatal("thinking block must be preserved byte for byte")
	}
	if !bytes.Contains(out1, []byte(fixtures.UserIDFor(fixtures.SessionA))) {
		t.Fatal("metadata.user_id must be preserved")
	}
	out2, _, _ := payload.Walk(body, payload.WalkOptions{}, repl)
	if !bytes.Equal(out1, out2) {
		t.Fatal("serialization is not deterministic")
	}
	var parsed map[string]any
	if err := json.Unmarshal(out1, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if bytes.Contains(out1, []byte(`<`)) || bytes.HasSuffix(out1, []byte("\n")) {
		t.Fatal("output must not HTML-escape or end with a newline")
	}
}

func TestWalk_PreservesNumbers(t *testing.T) {
	body := []byte(`{"model":"m","temperature":1.0,"max_tokens":12345678901234567890,"messages":[{"role":"user","content":"x"}]}`)
	out, _, err := payload.Walk(body, payload.WalkOptions{}, func(p payload.Path, v string) (string, bool) { return v + "!", true })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"temperature":1.0`)) || !bytes.Contains(out, []byte(`12345678901234567890`)) {
		t.Fatalf("numbers not preserved as written: %s", out)
	}
}

func TestWalk_Errors(t *testing.T) {
	if _, _, err := payload.Walk([]byte("[1,2]"), payload.WalkOptions{}, nil); err != payload.ErrNotJSON {
		t.Fatalf("array body error = %v, want ErrNotJSON", err)
	}
	if _, _, err := payload.Walk([]byte("nope"), payload.WalkOptions{}, nil); err != payload.ErrNotJSON {
		t.Fatalf("garbage body error = %v, want ErrNotJSON", err)
	}
	big := mustJSON(t, fixtures.Request(""))
	if _, _, err := payload.Walk(big, payload.WalkOptions{MaxBodyBytes: 10}, nil); err != payload.ErrBodyTooLarge {
		t.Fatalf("oversize error = %v, want ErrBodyTooLarge", err)
	}
}

func TestDefaultDeny_Rules(t *testing.T) {
	d := payload.DefaultDeny()
	if d == nil {
		t.Fatal("DefaultDeny returned nil")
	}
	deny := []struct {
		p     payload.Path
		types []string
	}{
		{payload.Path{"model"}, nil},
		{payload.Path{"messages", "0", "role"}, nil},
		{payload.Path{"messages", "1", "content", "0", "thinking"}, []string{"thinking"}},
		{payload.Path{"messages", "1", "content", "0", "signature"}, []string{"thinking"}},
		{payload.Path{"messages", "1", "content", "0", "data"}, []string{"redacted_thinking"}},
		{payload.Path{"messages", "1", "content", "1", "id"}, []string{"tool_use"}},
		{payload.Path{"messages", "1", "content", "1", "name"}, []string{"tool_use"}},
		{payload.Path{"tools", "0", "name"}, nil},
		{payload.Path{"metadata", "user_id"}, nil},
		{payload.Path{"messages", "0", "content", "0", "source", "data"}, []string{"image"}},
		{payload.Path{"system", "0", "cache_control", "type"}, []string{"text"}},
	}
	for _, c := range deny {
		if !d.Denied(c.p, c.types) {
			t.Errorf("Denied(%s) = false, want true", c.p)
		}
	}
	allow := []struct {
		p     payload.Path
		types []string
	}{
		{payload.Path{"system"}, nil},
		{payload.Path{"system", "0", "text"}, []string{"text"}},
		{payload.Path{"tools", "0", "description"}, nil},
		{payload.Path{"messages", "0", "content"}, nil},
		{payload.Path{"messages", "1", "content", "1", "input", "command"}, []string{"tool_use"}},
		{payload.Path{"messages", "1", "content", "1", "input", "name"}, []string{"tool_use"}}, // a "name" argument is not a tool name
		{payload.Path{"messages", "2", "content", "0", "content"}, []string{"tool_result"}},
		{payload.Path{"messages", "2", "content", "0", "content", "0", "text"}, []string{"tool_result", "text"}},
	}
	for _, c := range allow {
		if d.Denied(c.p, c.types) {
			t.Errorf("Denied(%s) = true, want false", c.p)
		}
	}
}
