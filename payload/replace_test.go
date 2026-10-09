package payload_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// restoreHosts stands in for the restorer: h-1 and h-2 become their
// originals, everything else is left alone.
func restoreHosts(_ payload.Path, v string) (string, bool) {
	if !strings.Contains(v, "h-") {
		return v, false
	}
	return strings.NewReplacer("h-1", "athene.lan", "h-2", `nas "1" <x>`).Replace(v), true
}

func TestReplaceStrings_SplicesOnlyValues(t *testing.T) {
	body := []byte("{\"b\": \"x\", \"a\":  {\"t\": \"h-1 und h-2\", \"n\": 1.0},\n \"arr\": [\"h-1\", 2, {\"t\": \"h-2\"}]}")
	out, replaced, err := payload.ReplaceStrings(body, nil, restoreHosts)
	if err != nil || replaced != 3 {
		t.Fatalf("ReplaceStrings = replaced %d, err %v", replaced, err)
	}
	want := "{\"b\": \"x\", \"a\":  {\"t\": \"athene.lan und nas \\\"1\\\" <x>\", \"n\": 1.0},\n \"arr\": [\"athene.lan\", 2, {\"t\": \"nas \\\"1\\\" <x>\"}]}"
	if string(out) != want {
		t.Fatalf("ReplaceStrings =\n%s\nwant\n%s", out, want)
	}
}

// TestReplaceStrings_AppliesDenyList: the return pass uses the same deny
// list as the forward pass, so thinking blocks, ids, signatures and tool
// names stay as they are and every other string is visited, including
// strings in fields the old path list never named.
func TestReplaceStrings_AppliesDenyList(t *testing.T) {
	body := []byte(`{"id":"h-1","type":"message","role":"assistant","model":"claude-fable-5-1","content":[
		{"type":"thinking","thinking":"h-1","signature":"h-1"},
		{"type":"text","text":"Hallo h-1","citations":[{"type":"char_location","cited_text":"h-2","document_title":"h-1"}]},
		{"type":"tool_use","id":"toolu_01","name":"h-1","input":{"command":"ssh h-1","nested":{"host":"h-2"},"count":3,"name":"h-2"}},
		{"type":"server_tool_use","id":"srvtoolu_01","name":"web_search","input":{"query":"h-1"}}
	],"stop_reason":"h-1","usage":{"input_tokens":1,"output_tokens":2}}`)
	var visited []string
	out, replaced, err := payload.ReplaceStrings(body, nil, func(p payload.Path, v string) (string, bool) {
		visited = append(visited, p.String())
		return restoreHosts(p, v)
	})
	if err != nil {
		t.Fatalf("ReplaceStrings: %v", err)
	}
	got := map[string]bool{}
	for _, p := range visited {
		got[p] = true
	}
	for _, want := range []string{
		"content[1].text", "content[1].citations[0].cited_text", "content[1].citations[0].document_title",
		"content[2].input.command", "content[2].input.nested.host", "content[2].input.name",
		"content[3].input.query",
	} {
		if !got[want] {
			t.Errorf("path %s not visited; visited %v", want, visited)
		}
	}
	for _, no := range []string{
		"id", "type", "role", "model", "stop_reason",
		"content[0].thinking", "content[0].signature", "content[0].type",
		"content[2].id", "content[2].name", "content[3].name",
	} {
		if got[no] {
			t.Errorf("path %s must not be visited", no)
		}
	}
	if replaced != 7 {
		t.Errorf("replaced = %d, want 7", replaced)
	}
	for _, keep := range []string{`"id":"h-1"`, `"thinking":"h-1","signature":"h-1"`, `"name":"h-1"`, `"stop_reason":"h-1"`} {
		if !bytes.Contains(out, []byte(keep)) {
			t.Errorf("denied bytes changed: %s missing in\n%s", keep, out)
		}
	}
	if bytes.Contains(out, []byte(`"text":"Hallo h-1"`)) || !bytes.Contains(out, []byte(`"query":"athene.lan"`)) {
		t.Errorf("allowed strings not restored:\n%s", out)
	}
}

func TestReplaceStrings_UnchangedReturnsInput(t *testing.T) {
	body := []byte(`{"a":"x"}`)
	out, replaced, err := payload.ReplaceStrings(body, nil, func(payload.Path, string) (string, bool) { return "", false })
	if err != nil || replaced != 0 || !bytes.Equal(out, body) || &out[0] != &body[0] {
		t.Fatalf("unchanged call must return the input slice: replaced %d err %v", replaced, err)
	}
}

func TestReplaceStrings_Errors(t *testing.T) {
	for _, body := range []string{`[1]`, `not json`, `{"a":`, ``} {
		if _, _, err := payload.ReplaceStrings([]byte(body), nil, func(payload.Path, string) (string, bool) { return "y", true }); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
}

func TestReplaceStrings_DecodesEscapes(t *testing.T) {
	body := []byte(`{"t":"a-b \"q\" \\ h-1"}`)
	var seen string
	out, _, err := payload.ReplaceStrings(body, nil, func(_ payload.Path, v string) (string, bool) {
		seen = v
		return strings.ReplaceAll(v, "h-1", "ok"), true
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen != `a-b "q" \ h-1` {
		t.Fatalf("callback received %q, want the decoded string", seen)
	}
	if string(out) != `{"t":"a-b \"q\" \\ ok"}` {
		t.Fatalf("out = %s", out)
	}
}

// TestReplaceStrings_DuplicateKeys: the byte scanner sees every occurrence
// of a repeated key, so both values are rewritten and the client, whichever
// occurrence its parser keeps, never sees the pseudonym.
func TestReplaceStrings_DuplicateKeys(t *testing.T) {
	body := []byte(`{"content":[{"type":"text","text":"h-1","text":"h-2"}],"content":[{"type":"text","text":"h-1"}]}`)
	out, replaced, err := payload.ReplaceStrings(body, nil, restoreHosts)
	if err != nil || replaced != 3 {
		t.Fatalf("ReplaceStrings = replaced %d, err %v", replaced, err)
	}
	if bytes.Contains(out, []byte("h-1")) || bytes.Contains(out, []byte("h-2")) {
		t.Fatalf("a duplicate key kept its pseudonym: %s", out)
	}
}

// TestReplaceStrings_TypeAfterText: the deny list decides by the enclosing
// block type, and the upstream may put "type" after the string it governs.
func TestReplaceStrings_TypeAfterText(t *testing.T) {
	body := []byte(`{"content":[{"thinking":"h-1","type":"thinking"},{"text":"h-1","type":"text"}]}`)
	out, replaced, err := payload.ReplaceStrings(body, nil, restoreHosts)
	if err != nil || replaced != 1 {
		t.Fatalf("ReplaceStrings = replaced %d, err %v", replaced, err)
	}
	if !bytes.Contains(out, []byte(`"thinking":"h-1"`)) || bytes.Contains(out, []byte(`"text":"h-1"`)) {
		t.Fatalf("type after text not honoured: %s", out)
	}
}
