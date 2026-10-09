package payload_test

// The deny list decides what the forward pass may touch inside a request
// body. Two promises rest on it: a thinking block is never altered, because
// its signature is bound to the exact text, and identifiers the API needs
// verbatim - tool names, model names, session ids - stay as they are. Both
// are checked here against a body shaped like the real thing.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// A body with everything an Anthropic request carries. The host name sits in
// every field, and only the ones the filter is allowed to touch may change.
func TestDeny_RealisticBodyShape(t *testing.T) {
	body := `{
	  "model": "claude-opus-5",
	  "system": [{"type":"text","text":"Du arbeitest auf zeus.lan."}],
	  "metadata": {"user_id": "zeus.lan-session-7"},
	  "tools": [{"name":"zeus.lan","description":"prüft zeus.lan"}],
	  "messages": [
	    {"role":"user","content":[{"type":"text","text":"was läuft auf zeus.lan?"}]},
	    {"role":"assistant","content":[
	      {"type":"thinking","thinking":"Der Nutzer meint zeus.lan.","signature":"sig-zeus.lan-abc"},
	      {"type":"tool_use","id":"toolu_1","name":"zeus.lan","input":{"host":"zeus.lan"}}
	    ]},
	    {"role":"user","content":[
	      {"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"zeus.lan ist erreichbar"}]}
	    ]}
	  ]
	}`
	out, n, err := payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), replaceHost)
	if err != nil {
		t.Fatalf("ReplaceStrings: %v", err)
	}
	t.Logf("%d values replaced", n)

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("the result is not valid JSON: %v", err)
	}
	s := string(out)

	// Must never change.
	untouched := map[string]string{
		"thinking text":      "Der Nutzer meint zeus.lan.",
		"thinking signature": "sig-zeus.lan-abc",
		"tool name":          `"name":"zeus.lan"`,
		"metadata user_id":   "zeus.lan-session-7",
	}
	for name, want := range untouched {
		if !strings.Contains(s, want) {
			t.Errorf("%s was altered, %q is gone", name, want)
		}
	}
	// Must change.
	mustGo := map[string]string{
		"user text":   "was läuft auf zeus.lan?",
		"system text": "Du arbeitest auf zeus.lan.",
		"tool result": "zeus.lan ist erreichbar",
	}
	for name, gone := range mustGo {
		if strings.Contains(s, gone) {
			t.Errorf("%s went out in the clear: %q", name, gone)
		}
	}
	// The tool description is prose the model reads; whichever way it is
	// decided, it should be decided knowingly.
	if strings.Contains(s, "prüft zeus.lan") {
		t.Logf("the tool description keeps the host name")
	} else {
		t.Logf("the tool description is filtered")
	}
	// tool_use.input is what the model asked for, and it is executed locally.
	if strings.Contains(s, `"host":"zeus.lan"`) {
		t.Logf("tool_use.input keeps the value")
	} else {
		t.Logf("tool_use.input is filtered, so the return pass has to put it back")
	}
}

// A thinking block anywhere in the tree, not only where the fixture puts it.
func TestDeny_ThinkingBlockInEveryPosition(t *testing.T) {
	bodies := map[string]string{
		"top level content": `{"content":[{"type":"thinking","thinking":"zeus.lan","signature":"s"}]}`,
		"nested twice":      `{"messages":[{"content":[{"type":"thinking","thinking":"zeus.lan","signature":"s"}]}]}`,
		"redacted thinking": `{"content":[{"type":"redacted_thinking","data":"zeus.lan"}]}`,
		"beside a sibling":  `{"content":[{"type":"thinking","thinking":"zeus.lan","signature":"s"},{"type":"text","text":"zeus.lan"}]}`,
	}
	for name, body := range bodies {
		out, n, err := payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), replaceHost)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		s := string(out)
		thinkingKept := strings.Contains(s, `"thinking":"zeus.lan"`) || strings.Contains(s, `"data":"zeus.lan"`)
		t.Logf("%-18s replaced=%d thinking kept=%v", name, n, thinkingKept)
		if !thinkingKept {
			t.Errorf("%s: the thinking block was altered: %s", name, s)
		}
		if name == "beside a sibling" && strings.Contains(s, `"text":"zeus.lan"`) {
			t.Errorf("the sibling text block was not filtered: %s", s)
		}
	}
}

// "signature" is denied wherever it appears, not only inside a thinking
// block. Anything a tool returns under that key therefore goes out in the
// clear: a mail footer, a commit signer, a PDF field.
func TestDeny_SignatureOutsideThinking(t *testing.T) {
	cases := map[string]string{
		"mail footer":     `{"messages":[{"content":[{"type":"tool_result","content":[{"type":"text","text":"ok","signature":"Mit freundlichen Grüßen, zeus.lan"}]}]}]}`,
		"commit signer":   `{"messages":[{"content":[{"type":"text","text":"log","signature":"Good signature from zeus.lan"}]}]}`,
		"plain object":    `{"signature":"zeus.lan"}`,
		"inside thinking": `{"content":[{"type":"thinking","thinking":"x","signature":"zeus.lan"}]}`,
	}
	for name, body := range cases {
		out, n, err := payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), replaceHost)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		kept := strings.Contains(string(out), `"signature":"`) && strings.Contains(string(out), "zeus.lan")
		t.Logf("%-16s replaced=%d value kept=%v", name, n, kept)
		if name == "inside thinking" {
			if !kept {
				t.Errorf("the thinking signature must not be touched")
			}
			continue
		}
		if kept {
			t.Errorf("%s: the value under signature left the machine unchanged: %s", name, out)
		}
	}
}

func TestDeny_KeyNamesOutOfPlace(t *testing.T) {
	bodies := map[string]struct {
		body       string
		wantFilter bool
	}{
		"name in message text": {`{"messages":[{"content":[{"type":"text","text":"mein name ist zeus.lan"}]}]}`, true},
		"a key called name":    {`{"messages":[{"content":[{"type":"text","text":"x","name":"zeus.lan"}]}]}`, false},
		"signature elsewhere":  {`{"messages":[{"content":[{"type":"text","text":"zeus.lan","signature":"zeus.lan"}]}]}`, true},
		"user_id outside meta": {`{"messages":[{"content":[{"type":"text","text":"zeus.lan"}]}],"user_id":"zeus.lan"}`, true},
	}
	for name, c := range bodies {
		out, n, err := payload.ReplaceStrings([]byte(c.body), payload.DefaultDeny(), replaceHost)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		t.Logf("%-22s replaced=%d out=%s", name, n, out)
		if c.wantFilter && n == 0 {
			t.Errorf("%s: nothing was filtered", name)
		}
	}
}
