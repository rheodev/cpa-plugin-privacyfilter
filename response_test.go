package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// responseOriginals are the corpus values the upstream response echoes, by
// kind; the tests look their pseudonyms up in the table of the request.
var responseOriginals = map[detect.Kind]string{
	detect.KindHost:   "athene.lan",
	detect.KindIPv4:   "10.13.7.42",
	detect.KindPerson: "markus",
}

// upstreamResponse builds a Messages response the way the upstream would
// answer the pseudonymized request: it echoes the pseudonyms of the stored
// table in a text block and in tool_use arguments, and mentions one in a
// thinking block that must stay as it is. Key order and whitespace are
// deliberately not what encoding/json would produce. The returned map holds
// the pseudonym used for each kind.
func upstreamResponse(t *testing.T, table *mapping.Table) ([]byte, map[detect.Kind]string) {
	t.Helper()
	used := map[detect.Kind]string{}
	for kind, orig := range responseOriginals {
		used[kind] = table.Lookup(kind, orig)
	}
	host, ip, person := used[detect.KindHost], used[detect.KindIPv4], used[detect.KindPerson]
	body := `{"id": "msg_01", "type": "message", "role": "assistant", "model": "claude-fable-5-1",
  "content": [
    {"type": "thinking", "thinking": "` + host + ` hat ` + ip + `", "signature": "` + fixtures.ThinkingSignature + `"},
    {"type": "text", "text": "Ich pinge ` + host + ` (` + ip + `) für ` + person + `, sagt \"ok\" <fertig>"},
    {"type": "tool_use", "id": "` + fixtures.ToolUseID + `", "name": "Bash", "input": {"command": "ssh ` + host + ` && ping ` + ip + `", "count": 1.0}}
  ],
  "stop_reason": "tool_use", "usage": {"input_tokens": 10, "output_tokens": 20}}`
	if !json.Valid([]byte(body)) {
		t.Fatalf("test response is not valid JSON: %s", body)
	}
	return []byte(body), used
}

func interceptResponse(t *testing.T, p *privacyFilterPlugin, requestID, format string, body []byte) pluginapi.ResponseInterceptResponse {
	t.Helper()
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID:    requestID,
		SourceFormat: format,
		Model:        "claude-fable-5-1",
		Body:         body,
		StatusCode:   200,
	})
	if err != nil {
		t.Fatalf("InterceptResponse: %v", err)
	}
	return resp
}

func TestInterceptResponse_RestoresOriginals(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", body)
	table, err := p.store.Get("req-1")
	if err != nil {
		t.Fatal(err)
	}
	upstream, used := upstreamResponse(t, table)

	resp := interceptResponse(t, p, "req-1", "claude", upstream)
	if len(resp.Body) == 0 {
		t.Fatal("expected a restored body")
	}
	out := string(resp.Body)
	if !json.Valid(resp.Body) {
		t.Fatalf("restored body is not valid JSON: %s", out)
	}

	var parsed struct {
		Content []struct {
			Type     string          `json:"type"`
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
			Input    json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		t.Fatal(err)
	}
	originals := responseOriginals
	text := parsed.Content[1].Text
	for kind, orig := range originals {
		if !strings.Contains(text, orig) {
			t.Errorf("text block lacks the original %s %q: %q", kind, orig, text)
		}
		if strings.Contains(text, used[kind]) {
			t.Errorf("text block still carries the pseudonym %q", used[kind])
		}
	}
	if !strings.Contains(text, `sagt "ok" <fertig>`) {
		t.Errorf("quotes or angle brackets damaged: %q", text)
	}
	if !strings.Contains(string(parsed.Content[2].Input), originals[detect.KindHost]) || strings.Contains(string(parsed.Content[2].Input), used[detect.KindHost]) {
		t.Errorf("tool_use input not restored: %s", parsed.Content[2].Input)
	}
	if parsed.Content[0].Thinking != used[detect.KindHost]+" hat "+used[detect.KindIPv4] {
		t.Errorf("thinking block changed: %q", parsed.Content[0].Thinking)
	}
	// Bytes outside the replaced strings survive as they were: the upstream's
	// key order, indentation and the number 1.0.
	for _, s := range []string{`{"id": "msg_01", "type": "message"`, "\n  \"content\": [\n", `"count": 1.0`, `"signature": "` + fixtures.ThinkingSignature + `"`} {
		if !strings.Contains(out, s) {
			t.Errorf("upstream bytes not preserved: %q", s)
		}
	}
}

func TestInterceptResponse_PassThroughCases(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", body)
	table, _ := p.store.Get("req-1")
	upstream, _ := upstreamResponse(t, table)

	cases := map[string]pluginapi.ResponseInterceptRequest{
		"unknown request id": {RequestID: "req-unknown", SourceFormat: "claude", Body: upstream},
		"empty request id":   {RequestID: "", SourceFormat: "claude", Body: upstream},
		"other format":       {RequestID: "req-1", SourceFormat: "openai", Body: upstream},
		"empty body":         {RequestID: "req-1", SourceFormat: "claude", Body: nil},
		"not json":           {RequestID: "req-1", SourceFormat: "claude", Body: []byte("event: nope")},
		"no content":         {RequestID: "req-1", SourceFormat: "claude", Body: []byte(`{"type":"error","error":{"message":"x"}}`)},
	}
	for name, req := range cases {
		resp, err := p.InterceptResponse(context.Background(), req)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if len(resp.Body) != 0 {
			t.Errorf("%s: expected pass-through, got a body", name)
		}
	}

	// A body without pseudonyms is passed through, not re-serialized.
	clean := []byte(`{"id":"msg_02","type":"message","content":[{"type":"text","text":"nichts zu tun"}]}`)
	if resp := interceptResponse(t, p, "req-1", "claude", clean); len(resp.Body) != 0 {
		t.Errorf("clean body was rewritten: %s", resp.Body)
	}
}

// TestCapabilitiesByMode: redact announces only the request interceptor, as
// the original plugin does; pseudonymize adds the return path.
func TestCapabilitiesByMode(t *testing.T) {
	for _, c := range []struct {
		mode       Mode
		returnPath bool
	}{
		{ModeRedact, false},
		{ModePseudonymize, true},
	} {
		caps := capabilitiesFor(newPseudoPlugin(t, map[string]any{"mode": string(c.mode)}))
		if caps.RequestInterceptor == nil {
			t.Fatalf("%s: request interceptor missing", c.mode)
		}
		if (caps.ResponseInterceptor != nil) != c.returnPath || (caps.RequestLifecyclePlugin != nil) != c.returnPath {
			t.Fatalf("%s: response interceptor %v, lifecycle %v, want both %v", c.mode, caps.ResponseInterceptor != nil, caps.RequestLifecyclePlugin != nil, c.returnPath)
		}
	}
}

func TestHandleRequestComplete_ReleasesTable(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", body)
	beforeAuth(t, p, "req-2", body)
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: "req-1", Outcome: pluginapi.RequestCompletionSucceeded}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.Get("req-1"); err == nil {
		t.Fatal("table for req-1 still present after completion")
	}
	if _, err := p.store.Get("req-2"); err != nil {
		t.Fatal("table for req-2 must survive another request's completion")
	}
	for _, id := range []string{"", "never-seen"} {
		if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: id}); err != nil {
			t.Errorf("completion for %q returned %v", id, err)
		}
	}
}

// installABIPlugin makes p the plugin the ABI dispatch routes to for the
// duration of the test.
func installABIPlugin(t *testing.T, p *privacyFilterPlugin) {
	t.Helper()
	privacyFilterABIState.Lock()
	prev, prevRT := privacyFilterABIState.plugin, privacyFilterABIState.runtime
	privacyFilterABIState.plugin = p
	privacyFilterABIState.runtime = p.rt
	privacyFilterABIState.shuttingDown = false
	privacyFilterABIState.Unlock()
	t.Cleanup(func() {
		privacyFilterABIState.Lock()
		privacyFilterABIState.plugin, privacyFilterABIState.runtime = prev, prevRT
		privacyFilterABIState.Unlock()
	})
}

// TestABI_ResponseAndCompletionDispatch: the two method names reach their
// handlers, decode the host's wrapper shape with host_callback_id, and answer
// with an OK envelope. What the handlers do is covered by their own tests.
func TestABI_ResponseAndCompletionDispatch(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	installABIPlugin(t, p)

	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-abi", body)
	table, _ := p.store.Get("req-abi")
	upstream, _ := upstreamResponse(t, table)

	reqJSON, _ := json.Marshal(struct {
		pluginapi.ResponseInterceptRequest
		HostCallbackID string `json:"host_callback_id"`
	}{pluginapi.ResponseInterceptRequest{RequestID: "req-abi", SourceFormat: "claude", Body: upstream, StatusCode: 200}, "cb-1"})
	raw, err := handlePrivacyFilterABIMethod(context.Background(), "response.intercept_after", reqJSON)
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("envelope = %s, err %v", raw, err)
	}
	var resp pluginapi.ResponseInterceptResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil || len(resp.Body) == 0 {
		t.Fatalf("ABI response = %s, err %v", env.Result, err)
	}

	doneJSON, _ := json.Marshal(struct {
		pluginapi.RequestCompletion
		HostCallbackID string `json:"host_callback_id"`
	}{pluginapi.RequestCompletion{RequestID: "req-abi", Outcome: pluginapi.RequestCompletionSucceeded}, "cb-1"})
	raw, err = handlePrivacyFilterABIMethod(context.Background(), "request.complete", doneJSON)
	if err != nil {
		t.Fatalf("dispatch complete: %v", err)
	}
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("completion envelope = %s, err %v", raw, err)
	}
	if _, err := p.store.Get("req-abi"); err == nil {
		t.Fatal("table not released via ABI completion")
	}
}

// TestABI_ReconfigureKeepsTablesInFlight: the host re-registers the plugin
// on every configuration reload while requests are in flight. Two orders
// have to work. A request that stored its table before the reload must be
// restored by the new instance. And a request that entered the old
// instance's interceptor before the reload but stores its table only after
// it, which is the order a token refresh produced on the live system, must
// be restored by the new instance as well; that is only true when both
// instances share one store.
func TestABI_ReconfigureKeepsTablesInFlight(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	installABIPlugin(t, p)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-before", body)
	tableBefore, _ := p.store.Get("req-before")
	upstreamBefore, usedBefore := upstreamResponse(t, tableBefore)

	// A shorter TTL in the new configuration proves the reload reaches the
	// shared store instead of building a second one.
	configYAML := []byte("mode: pseudonymize\nlimits: {mapping_ttl: 11m}\nsalt_secret_path: " + filepath.Join(p.pluginDir, pseudo.DefaultSecretFile) + "\n")
	regJSON, _ := json.Marshal(abiLifecycleRequest{ConfigYAML: configYAML, PluginDir: p.pluginDir})
	raw, err := handlePrivacyFilterABIMethod(context.Background(), "plugin.reconfigure", regJSON)
	if err != nil {
		t.Fatalf("reconfigure: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("reconfigure envelope = %s, err %v", raw, err)
	}
	privacyFilterABIState.RLock()
	next := privacyFilterABIState.plugin
	privacyFilterABIState.RUnlock()
	if next == p {
		t.Fatal("reconfigure did not build a new plugin")
	}
	if next.store != p.store || next.streams != p.streams || next.rt != p.rt {
		t.Fatal("the new instance must share store and streams with the old one")
	}

	// The late request: it holds the old instance, the reload has happened.
	beforeAuth(t, p, "req-late", body)
	tableLate, errLate := next.store.Get("req-late")
	if errLate != nil {
		t.Fatalf("table stored on the old instance after the reload is not visible to the new one: %v", errLate)
	}
	upstreamLate, usedLate := upstreamResponse(t, tableLate)

	for _, tc := range []struct {
		id   string
		body []byte
		used map[detect.Kind]string
	}{
		{"req-before", upstreamBefore, usedBefore},
		{"req-late", upstreamLate, usedLate},
	} {
		resp := interceptResponse(t, next, tc.id, "claude", tc.body)
		if len(resp.Body) == 0 {
			t.Fatalf("%s: response after reconfigure passed through", tc.id)
		}
		var parsed struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(resp.Body, &parsed); err != nil || len(parsed.Content) < 2 {
			t.Fatalf("%s: restored body = %s, err %v", tc.id, resp.Body, err)
		}
		// The thinking block keeps its pseudonym by contract; the text block must not.
		if text := parsed.Content[1].Text; strings.Contains(text, tc.used[detect.KindIPv4]) || !strings.Contains(text, responseOriginals[detect.KindIPv4]) {
			t.Fatalf("%s: response after reconfigure not restored: %q", tc.id, text)
		}
	}

	// Completion on the new instance releases a table the old one stored.
	if err := next.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: "req-late"}); err != nil {
		t.Fatalf("HandleRequestComplete: %v", err)
	}
	if _, err := p.store.Get("req-late"); err == nil {
		t.Fatal("completion on the new instance must release the shared table")
	}
}
