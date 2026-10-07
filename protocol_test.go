package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestRedactionCoversClientFormats(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement_labels:\n  email: '[EMAIL]'")
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"claude system string",
			`{"system":"contact test@example.com","messages":[{"role":"user","content":"hi"}]}`,
			`{"system":"contact [EMAIL]","messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			"claude system blocks",
			`{"system":[{"type":"text","text":"test@example.com","cache_control":{"type":"ephemeral"}}]}`,
			`{"system":[{"type":"text","text":"[EMAIL]","cache_control":{"type":"ephemeral"}}]}`,
		},
		{
			"claude tool_result string and blocks",
			`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"test@example.com"},{"type":"tool_result","tool_use_id":"t2","content":[{"type":"text","text":"test@example.com"}]}]}]}`,
			`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"[EMAIL]"},{"type":"tool_result","tool_use_id":"t2","content":[{"type":"text","text":"[EMAIL]"}]}]}]}`,
		},
		{
			"claude tool_use input and thinking untouched",
			`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"test@example.com","signature":"sig"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"test@example.com"}},{"type":"text","text":"test@example.com"}]}]}`,
			`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"test@example.com","signature":"sig"},{"type":"tool_use","id":"t1","name":"send","input":{"to":"test@example.com"}},{"type":"text","text":"[EMAIL]"}]}]}`,
		},
		{
			"responses instructions and function_call_output",
			`{"instructions":"test@example.com","input":[{"type":"function_call","arguments":"test@example.com"},{"type":"function_call_output","call_id":"c1","output":"test@example.com"},{"type":"function_call_output","call_id":"c2","output":[{"type":"input_text","text":"test@example.com"}]}]}`,
			`{"instructions":"[EMAIL]","input":[{"type":"function_call","arguments":"test@example.com"},{"type":"function_call_output","call_id":"c1","output":"[EMAIL]"},{"type":"function_call_output","call_id":"c2","output":[{"type":"input_text","text":"[EMAIL]"}]}]}`,
		},
		{
			"gemini contents and systemInstruction",
			`{"systemInstruction":{"parts":[{"text":"test@example.com"}]},"contents":[{"role":"user","parts":[{"text":"test@example.com"},{"inlineData":{"mimeType":"text/plain","data":"dGVzdA=="}}]},{"role":"model","parts":[{"text":"test@example.com","thought":true,"thoughtSignature":"sig"},{"functionCall":{"name":"send","args":{"to":"test@example.com"}}}]},{"role":"user","parts":[{"functionResponse":{"name":"send","response":{"to":"test@example.com"}}}]}]}`,
			`{"systemInstruction":{"parts":[{"text":"[EMAIL]"}]},"contents":[{"role":"user","parts":[{"text":"[EMAIL]"},{"inlineData":{"mimeType":"text/plain","data":"dGVzdA=="}}]},{"role":"model","parts":[{"text":"test@example.com","thought":true,"thoughtSignature":"sig"},{"functionCall":{"name":"send","args":{"to":"test@example.com"}}}]},{"role":"user","parts":[{"functionResponse":{"name":"send","response":{"to":"test@example.com"}}}]}]}`,
		},
		{
			"gemini snake_case system_instruction",
			`{"system_instruction":{"parts":[{"text":"test@example.com"}]}}`,
			`{"system_instruction":{"parts":[{"text":"[EMAIL]"}]}}`,
		},
		{
			"gemini cli request wrapper",
			`{"model":"gemini-2.5-pro","project":"p","request":{"systemInstruction":{"parts":[{"text":"test@example.com"}]},"contents":[{"role":"user","parts":[{"text":"test@example.com"}]}]}}`,
			`{"model":"gemini-2.5-pro","project":"p","request":{"systemInstruction":{"parts":[{"text":"[EMAIL]"}]},"contents":[{"role":"user","parts":[{"text":"[EMAIL]"}]}]}}`,
		},
		{
			"completions prompt",
			`{"prompt":["test@example.com",7,"hello"],"suffix":"test@example.com"}`,
			`{"prompt":["[EMAIL]",7,"hello"],"suffix":"test@example.com"}`,
		},
		{
			"completions prompt string",
			`{"prompt":"test@example.com"}`,
			`{"prompt":"[EMAIL]"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := interceptor.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(tc.body)})
			if err != nil {
				t.Fatal(err)
			}
			assertJSONBody(t, resp.Body, tc.want)
		})
	}
}

func TestRedactionPassesStructuredDataThrough(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "")
	for _, body := range []string{
		`{"system":{"text":"test@example.com"}}`,
		`{"instructions":42}`,
		`{"contents":[{"parts":[{"functionResponse":{"response":{"to":"test@example.com"}}}]}]}`,
		`{"contents":[{"parts":[{"text":"test@example.com","thought":true}]}]}`,
		`{"systemInstruction":"test@example.com"}`,
		`{"metadata":{"request":{"contents":[{"parts":[{"text":"test@example.com"}]}]}}}`,
		`{"messages":[{"content":[{"type":"tool_use","input":{"to":"test@example.com"}}]}]}`,
	} {
		resp, err := interceptor.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Body != nil {
			t.Fatalf("expected passthrough for %s, got %s", body, resp.Body)
		}
	}
}

func TestRedactPayloadReportsFieldPaths(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"system":"test@example.com","messages":[{"role":"user","content":"hi"},{"role":"user","content":[{"type":"text","text":"test@example.com"},{"type":"tool_result","content":"test@example.com"}]}],"request":{"contents":[{"parts":[{"text":"test@example.com"}]}]}}`
	modified, hits, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if modified == nil {
		t.Fatal("expected redacted body")
	}
	want := []string{
		"messages[1].content[0].text",
		"messages[1].content[1].content",
		"system",
		"request.contents[0].parts[0].text",
	}
	if !reflect.DeepEqual(hits, want) {
		t.Fatalf("hits = %v, want %v", hits, want)
	}
	for _, hit := range hits {
		if strings.Contains(hit, "@") {
			t.Fatalf("field paths must not contain request content: %q", hit)
		}
	}
}

func TestHostCallbackIDContext(t *testing.T) {
	if got := hostCallbackIDFromContext(nil); got != "" {
		t.Fatalf("nil context id = %q", got)
	}
	if got := hostCallbackIDFromContext(withHostCallbackID(nil, " ")); got != "" {
		t.Fatalf("blank id should be ignored, got %q", got)
	}
	if got := hostCallbackIDFromContext(withHostCallbackID(context.Background(), "cb-1")); got != "cb-1" {
		t.Fatalf("id = %q, want cb-1", got)
	}
}

func TestPluginLogFallsBackWithoutHost(t *testing.T) {
	privacyFilterABIState.Lock()
	previous := privacyFilterABIState.host
	privacyFilterABIState.host = nil
	privacyFilterABIState.Unlock()
	t.Cleanup(func() {
		privacyFilterABIState.Lock()
		privacyFilterABIState.host = previous
		privacyFilterABIState.Unlock()
	})
	if hostLog("", logLevelInfo, "message", nil) {
		t.Fatal("hostLog must report failure without an attached host")
	}
	pluginLog(nil, logLevelInfo, "fallback", map[string]any{"k": "v"})
}

func TestNewFilterErrorNamesRulesSource(t *testing.T) {
	invalid := []byte("[[rules]\n")
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "gitleaks.toml"), invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custom.toml"), invalid, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		cfg  privacyFilterConfig
		want string
	}{
		{"sidecar", privacyFilterConfig{}, "sidecar rules file"},
		{"configured", privacyFilterConfig{GitleaksTOML: "custom.toml"}, "gitleaks_toml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newFilter(dir, tc.cfg)
			if err == nil {
				t.Fatal("expected invalid rules to fail")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q should mention %q", err, tc.want)
			}
			if tc.name == "sidecar" && strings.Contains(err.Error(), "gitleaks_toml") {
				t.Fatalf("sidecar error must not blame gitleaks_toml: %q", err)
			}
		})
	}
}

func registerRequest(t *testing.T, dir, configYAML string) []byte {
	t.Helper()
	raw, err := json.Marshal(abiLifecycleRequest{ConfigYAML: []byte(configYAML), PluginDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeRegistration(t *testing.T, raw []byte) abiRegistration {
	t.Helper()
	var envelope abiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.OK {
		t.Fatalf("expected ok envelope, got %s", raw)
	}
	var registration abiRegistration
	if err := json.Unmarshal(envelope.Result, &registration); err != nil {
		t.Fatal(err)
	}
	return registration
}

func TestReconfigureKeepsPreviousConfigOnInvalidConfig(t *testing.T) {
	privacyFilterABIState.Lock()
	previous := privacyFilterABIState.plugin
	privacyFilterABIState.plugin = nil
	privacyFilterABIState.Unlock()
	t.Cleanup(func() {
		privacyFilterABIState.Lock()
		privacyFilterABIState.plugin = previous
		privacyFilterABIState.Unlock()
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"reconfigure test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := handlePrivacyFilterRegister(ctx, pluginabi.MethodPluginRegister, registerRequest(t, dir, "gitleaks_toml: rules.toml\nreplacement: 123")); err == nil {
		t.Fatal("initial register must reject invalid config")
	}

	raw, err := handlePrivacyFilterRegister(ctx, pluginabi.MethodPluginRegister, registerRequest(t, dir, "gitleaks_toml: rules.toml\nreplacement: '[HIDDEN]'"))
	if err != nil {
		t.Fatalf("register error = %v", err)
	}
	registration := decodeRegistration(t, raw)
	if !registration.Capabilities.RequestInterceptor || registration.Metadata.Name != pluginName {
		t.Fatalf("unexpected registration %+v", registration)
	}
	privacyFilterABIState.RLock()
	valid := privacyFilterABIState.plugin
	privacyFilterABIState.RUnlock()

	raw, err = handlePrivacyFilterRegister(ctx, pluginabi.MethodPluginReconfigure, registerRequest(t, dir, "gitleaks_toml: rules.toml\nreplacement: true"))
	if err != nil {
		t.Fatalf("reconfigure with invalid config must keep serving, got %v", err)
	}
	registration = decodeRegistration(t, raw)
	if !registration.Capabilities.RequestInterceptor || registration.Metadata.Version != pluginVersion {
		t.Fatalf("unexpected registration %+v", registration)
	}
	privacyFilterABIState.RLock()
	current := privacyFilterABIState.plugin
	privacyFilterABIState.RUnlock()
	if current != valid {
		t.Fatal("invalid reconfigure must keep the previous plugin instance")
	}
	resp, err := current.InterceptRequestBeforeAuth(ctx, pluginapi.RequestInterceptRequest{Body: []byte(`{"input":"test@example.com"}`)})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, resp.Body, `{"input":"[HIDDEN]"}`)

	if _, err = handlePrivacyFilterRegister(ctx, pluginabi.MethodPluginReconfigure, registerRequest(t, dir, "gitleaks_toml: rules.toml\nreplacement: '[NEW]'")); err != nil {
		t.Fatalf("valid reconfigure error = %v", err)
	}
	privacyFilterABIState.RLock()
	current = privacyFilterABIState.plugin
	privacyFilterABIState.RUnlock()
	if current == valid {
		t.Fatal("valid reconfigure must replace the plugin instance")
	}
}
