package payload_test

// Probes for the JSON side: the walk, the deny list and the SSE parser.
// These are the layers that decide what is even offered for replacement, so
// a mistake here is either a leak or a corrupted body.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// visitAll records every path the walk offers and leaves the text alone.
func visitAll(seen *[]string) payload.Visitor {
	return func(p payload.Path, v string) (string, bool) {
		*seen = append(*seen, p.String()+"="+v)
		return v, false
	}
}

func walkPaths(t *testing.T, body string) []string {
	t.Helper()
	var seen []string
	out, changed, err := payload.Walk([]byte(body), payload.WalkOptions{}, visitAll(&seen))
	if err != nil {
		t.Fatalf("Walk(%s): %v", body, err)
	}
	if changed {
		t.Errorf("Walk reported a change although the visitor changed nothing")
	}
	if string(out) != body {
		t.Errorf("unchanged walk did not return the input bytes:\n got %s\nwant %s", out, body)
	}
	return seen
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// A key that literally contains a dot renders to the same dotted path as a
// nested one. If the deny list compares the joined path, a flat key such as
// "metadata.user_id" is silently excluded - and flat dotted keys are
// everyday shapes in configuration objects and tool arguments.
func TestDeny_DottedKeyConfusion(t *testing.T) {
	body := `{"metadata.user_id":"flat-value","metadata":{"user_id":"nested-value"},"other":"plain"}`
	seen := walkPaths(t, body)

	if !contains(seen, "metadata.user_id=nested-value") {
		t.Logf("as designed: the nested metadata.user_id is denied")
	} else {
		t.Errorf("the nested metadata.user_id was offered for replacement: %v", seen)
	}
	if !contains(seen, "metadata.user_id=flat-value") {
		t.Errorf("LEAK: the flat key \"metadata.user_id\" was excluded by a rule meant for the nested path; its value is never pseudonymized. seen=%v", seen)
	}
}

// The same question for a subtree rule.
func TestDeny_DottedKeyConfusionSubtree(t *testing.T) {
	body := `{"messages.content":"flat-value","messages":[{"content":"nested-value","role":"user"}]}`
	seen := walkPaths(t, body)
	if !contains(seen, "messages.content=flat-value") {
		t.Errorf("flat key \"messages.content\" was excluded: %v", seen)
	}
}

// tool_use.name is a tool name and denied; tool_use.input.name is an
// ordinary argument and must be visited. The deny list's own comment says so.
func TestDeny_ToolUseInputName(t *testing.T) {
	body := `{"content":[{"type":"tool_use","id":"tu_1","name":"Bash","input":{"name":"zeus.lan","command":"ssh zeus.lan"}}]}`
	seen := walkPaths(t, body)
	for _, want := range []string{
		"content[0].input.name=zeus.lan",
		"content[0].input.command=ssh zeus.lan",
	} {
		if !contains(seen, want) {
			t.Errorf("not offered: %s\nseen=%v", want, seen)
		}
	}
	if contains(seen, "content[0].name=Bash") {
		t.Errorf("the tool name was offered for replacement: %v", seen)
	}
}

// Escapes must survive a walk that changes nothing, byte for byte.
func TestWalk_ExoticEscapesUnchanged(t *testing.T) {
	bodies := []string{
		`{"a":"\u00fc\u00e4\u00f6"}`,
		`{"a":"\ud83d\ude00"}`,
		`{"a":"\/slash\\back\"quote"}`,
		`{"a":"\b\f\n\r\t"}`,
		`{"a":"\u0000nul"}`,
		`{"a":"line1\nline2"}`,
		`{ "spaced" : "value" , "n" : [ 1 , 2 ] }`,
	}
	for _, body := range bodies {
		walkPaths(t, body)
	}
}

// Numbers are re-serialized by many JSON libraries and silently lose
// precision or notation. They must come back exactly as written.
func TestWalk_NumbersKeepNotation(t *testing.T) {
	bodies := []string{
		`{"a":1e400}`,
		`{"a":-0}`,
		`{"a":123456789012345678901234567890}`,
		`{"a":1.7976931348623157e+308}`,
		`{"a":0.1000000000000000055511151231257827}`,
		`{"a":1E+2,"b":1e-2,"c":-1.5E10}`,
	}
	for _, body := range bodies {
		var seen []string
		out, _, err := payload.Walk([]byte(body), payload.WalkOptions{}, visitAll(&seen))
		if err != nil {
			t.Errorf("Walk(%s): %v", body, err)
			continue
		}
		if string(out) != body {
			t.Errorf("number notation changed:\n got %s\nwant %s", out, body)
		}
	}
}

// A replacement anywhere forces re-serialization. Everything the visitor did
// not touch must still mean the same thing afterwards.
func TestWalk_ReplacementKeepsTheRest(t *testing.T) {
	body := `{"hit":"zeus.lan","esc":"a\"b\\c\u00fc\ud83d\ude00","num":1e400,"deep":{"arr":[1,"zeus.lan",true,null]}}`
	out, changed, err := payload.Walk([]byte(body), payload.WalkOptions{}, func(p payload.Path, v string) (string, bool) {
		if v == "zeus.lan" {
			return "h-0123456789ab", true
		}
		return v, false
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if !changed {
		t.Fatal("Walk reported no change although two values were replaced")
	}
	var got, want map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("result is not valid JSON: %v\n%s", err, out)
	}
	if err := json.Unmarshal([]byte(body), &want); err != nil {
		t.Fatalf("input is not valid JSON: %v", err)
	}
	if string(got["esc"]) != string(want["esc"]) {
		t.Logf("escapes were re-encoded (same meaning):\n got %s\nwant %s", got["esc"], want["esc"])
	}
	if !strings.Contains(string(out), "1e400") && !strings.Contains(string(out), "1E400") {
		t.Errorf("the untouched number lost its notation: %s", out)
	}
}

// Deep nesting must not take the process down.
func TestWalk_DeepNesting(t *testing.T) {
	for _, depth := range []int{100, 1000, 5000} {
		body := `{"a":` + strings.Repeat(`[`, depth) + `"x"` + strings.Repeat(`]`, depth) + `}`
		var seen []string
		_, _, err := payload.Walk([]byte(body), payload.WalkOptions{}, visitAll(&seen))
		t.Logf("depth %d: err=%v, strings seen=%d", depth, err, len(seen))
	}
}

// Bodies that are not the expected shape must produce an error, not a panic
// and not a silently emptied body.
func TestWalk_EdgeBodies(t *testing.T) {
	cases := []string{
		``,
		`{}`,
		`[]`,
		`null`,
		`"just a string"`,
		`{"a":`,
		`{"a":"b"}trailing`,
		"\xef\xbb\xbf{\"a\":\"b\"}", // BOM
	}
	for _, body := range cases {
		var seen []string
		out, changed, err := payload.Walk([]byte(body), payload.WalkOptions{}, visitAll(&seen))
		t.Logf("%-24q -> err=%v changed=%v out=%q", body, err, changed, string(out))
		if err == nil && !changed && string(out) != body {
			t.Errorf("body %q came back different without a reported change: %q", body, out)
		}
	}
}

// The SSE parser has to cope with the wire forms a real server emits.
func TestParseEvents_WireForms(t *testing.T) {
	cases := map[string]string{
		"lf":            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
		"crlf":          "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\r\n\r\n",
		"no space":      "event:content_block_delta\ndata:{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
		"comment first": ": ping\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
		"data only":     "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
	}
	for name, chunk := range cases {
		evs, err := payload.ParseEvents([]byte(chunk))
		if err != nil {
			t.Errorf("%s: ParseEvents: %v", name, err)
			continue
		}
		if len(evs) != 1 {
			t.Errorf("%s: got %d events, want 1", name, len(evs))
			continue
		}
		field, ok := payload.ReplaceableText(evs[0])
		if !ok {
			t.Errorf("%s: no replaceable text found in %q", name, chunk)
			continue
		}
		text, err := payload.GetText(evs[0], field)
		if err != nil || text != "hi" {
			t.Errorf("%s: GetText = %q, %v; want \"hi\"", name, text, err)
		}
	}
}

// Putting a value with quotes and backslashes back into a partial_json
// fragment is double encoding: the fragment is itself JSON inside a JSON
// string. Getting this wrong produces a body the client cannot parse.
func TestSetText_EscapedFragmentSurvivesSpecialCharacters(t *testing.T) {
	originals := []string{
		`Ingrid "Bobby" Müller\`,
		`C:\Users\test`,
		"tab\there",
		"quote\"and\\backslash",
		"emoji 😀",
	}
	for _, orig := range originals {
		inner, err := json.Marshal(map[string]string{"path": orig})
		if err != nil {
			t.Fatal(err)
		}
		frag, err := json.Marshal(string(inner)) // the fragment as a JSON string
		if err != nil {
			t.Fatal(err)
		}
		raw := fmt.Sprintf(`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":%s}}`+"\n\n", frag)
		evs, err := payload.ParseEvents([]byte(raw))
		if err != nil || len(evs) != 1 {
			t.Fatalf("ParseEvents: %v (%d events)", err, len(evs))
		}
		field, ok := payload.ReplaceableText(evs[0])
		if !ok {
			t.Fatalf("no replaceable text for %q", orig)
		}
		text, err := payload.GetText(evs[0], field)
		if err != nil {
			t.Fatalf("GetText: %v", err)
		}
		out, err := payload.SetText(evs[0], field, text)
		if err != nil {
			t.Errorf("SetText for %q: %v", orig, err)
			continue
		}
		evs2, err := payload.ParseEvents(out)
		if err != nil || len(evs2) != 1 {
			t.Errorf("round trip of %q produced unparseable output: %v\n%s", orig, err, out)
			continue
		}
		text2, err := payload.GetText(evs2[0], field)
		if err != nil || text2 != text {
			t.Errorf("fragment changed for %q:\n got %q\nwant %q", orig, text2, text)
		}
	}
}

// ReplaceStrings is the entry point the forward path uses. A replacement
// value that itself contains JSON metacharacters must not break the body.
func TestReplaceStrings_ReplacementWithMetacharacters(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"ping zeus.lan"}]}`)
	for _, repl := range []string{`plain`, `with "quotes"`, `back\slash`, "new\nline", "emoji 😀"} {
		out, n, err := payload.ReplaceStrings(body, payload.DefaultDeny(), func(p payload.Path, v string) (string, bool) {
			if strings.Contains(v, "zeus.lan") {
				return strings.ReplaceAll(v, "zeus.lan", repl), true
			}
			return v, false
		})
		if err != nil {
			t.Errorf("replacement %q: %v", repl, err)
			continue
		}
		if n != 1 {
			t.Errorf("replacement %q: replaced %d strings, want 1", repl, n)
		}
		var parsed map[string]any
		if err := json.Unmarshal(out, &parsed); err != nil {
			t.Errorf("replacement %q produced invalid JSON: %v\n%s", repl, err, out)
		}
	}
}
