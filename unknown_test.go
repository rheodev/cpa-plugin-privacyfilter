package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// The return path restores what the table knows and counts what still has
// the plugin's shape afterwards: a token the model wrote in the shape
// without a row behind it. Thinking blocks are not looked at, a token glued
// to a word is not a token, and the count is by token.
func TestRestoreResponseBody_CountsUnknownShapes(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-unknown")
	host := table.Lookup(detect.KindHost, "athene.lan")
	stray, strayFile := "d-0123456789ab", "f-fedcba987654"
	body := []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-fable-5-1","content":[` +
		`{"type":"thinking","thinking":"` + stray + ` in thought","signature":"` + fixtures.ThinkingSignature + `"},` +
		`{"type":"text","text":"see ` + host + ` and ` + stray + `/x, ` + stray + ` again, not x` + stray + `"},` +
		`{"type":"tool_use","id":"` + fixtures.ToolUseID + `","name":"Write","input":{"file_path":"/tmp/` + strayFile + `.md"}}]}`)
	out, restored, unknown, err := restoreResponseBody(body, table, p.deny)
	if err != nil {
		t.Fatal(err)
	}
	if restored != 1 || !strings.Contains(string(out), "athene.lan") {
		t.Fatalf("restored = %d, out = %s", restored, out)
	}
	if len(unknown) != 2 || unknown[stray] != 2 || unknown[strayFile] != 1 {
		t.Fatalf("unknown = %v, want %s twice and %s once", unknown, stray, strayFile)
	}
}

// The stream counts on the text it delivers, fragment by fragment. A token
// cut by a fragment boundary is missed: that is the floor the comment on
// streamState.unknown states, and the test pins it so a change is noticed.
// The tokens leave the stream at completion, for the audit log.
func TestStream_CountsUnknownShapes(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-stream-unknown")
	host := table.Lookup(detect.KindHost, "athene.lan")
	stray := "d-0123456789ab"
	r := newStreamRun(t, p, "req-stream-unknown")
	r.feed([]byte(evMessageStart))
	r.feed(evStart(0, "text"))
	r.feed(evTextDelta(0, "see "+host+" and "+stray+" and "))
	r.feed(evTextDelta(0, stray[:7]))
	r.feed(evTextDelta(0, stray[7:]+" and "+stray))
	r.feed(evStop(0))
	r.feed(evMessageStop())
	texts, _, _ := r.delivered()
	if want := "see athene.lan and " + stray + " and " + stray + " and " + stray; texts[0] != want {
		t.Fatalf("delivered %q, want %q", texts[0], want)
	}
	st := p.streams.get("req-stream-unknown")
	if st == nil {
		t.Fatal("no stream state")
	}
	if st.unknown[stray] != 2 {
		t.Fatalf("unknown = %v, want %s twice: the cut token is the one missed", st.unknown, stray)
	}
	if unknown := p.streams.finish("req-stream-unknown", true); unknown[stray] != 2 {
		t.Fatalf("finish returned %v", unknown)
	}
}

// With audit.path set, the tokens go to the file as "unknown" lines with
// their counts: for a whole response when it is restored, for a stream at
// completion and in front of its closing line.
func TestAudit_RecordsUnknownShapes(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"audit": map[string]any{"path": "audit.log"}})
	body, _ := fixtureBody(t, fixtures.SessionA)
	stray := "d-0123456789ab"

	beforeAuth(t, p, "req-a", body)
	resp := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"` + stray + ` and ` + stray + `"}],"model":"claude-fable-5-1"}`)
	if _, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: "req-a", SourceFormat: "claude", Model: "claude-fable-5-1", Body: resp, StatusCode: 200,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{
		RequestID: "req-a", Outcome: pluginapi.RequestCompletionSucceeded, Stream: false,
	}); err != nil {
		t.Fatal(err)
	}

	beforeAuth(t, p, "req-b", body)
	r := newStreamRun(t, p, "req-b")
	r.feed([]byte(evMessageStart))
	r.feed(evStart(0, "text"))
	r.feed(evTextDelta(0, "only "+stray))
	r.feed(evStop(0))
	r.feed(evMessageStop())
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{
		RequestID: "req-b", Outcome: pluginapi.RequestCompletionSucceeded, Stream: true,
	}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p.audit.path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{
		"\tunknown\treq-a\t" + stray + "\t2\n",
		"\tunknown\treq-b\t" + stray + "\t1\n",
	} {
		if strings.Count(text, want) != 1 {
			t.Errorf("audit log has %q %d times, want once\n%s", want, strings.Count(text, want), text)
		}
	}
	if i, j := strings.Index(text, "\tunknown\treq-b\t"), strings.Index(text, "\tcomplete\treq-b\t"); i < 0 || j < 0 || i > j {
		t.Errorf("the unknown line of the stream is not in front of its complete line\n%s", text)
	}
}
