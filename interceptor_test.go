package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"privacyfilter/filter"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func newTestPlugin(t *testing.T) *privacyFilterPlugin {
	t.Helper()
	f, err := filter.New("", filter.Config{})
	if err != nil {
		t.Fatalf("filter.New() error = %v", err)
	}
	return &privacyFilterPlugin{
		cfg:    defaultConfig(),
		filter: f,
	}
}

func TestRedactRequestBody_EmailInContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	modified, _, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if !strings.Contains(string(modified), "[EMAIL]") {
		t.Fatalf("expected [EMAIL] placeholder in output: %s", string(modified))
	}
	if strings.Contains(string(modified), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestRedactRequestBody_NoPII(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`
	modified, _, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified != nil {
		t.Fatalf("expected nil for no-PII body, got: %s", string(modified))
	}
}

func TestRedactRequestBody_MultiPartContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"my phone is 13800138000"}]}]}`
	modified, _, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(modified), "13800138000") {
		t.Fatal("original phone number should be redacted")
	}
}

func TestRedactRequestBody_ResponsesStringInput(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","input":"my email is test@example.com"}`
	modified, _, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(modified), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestInterceptRequest_SkippedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("expected skipped model to pass through, got: %s", string(resp.Body))
	}
}

func TestInterceptRequest_SkippedRequestedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"upstream-model","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Model:          "upstream-model",
		RequestedModel: "gpt-4",
		Body:           []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatalf("expected skipped requested model to pass through, got: %s", string(resp.Body))
	}
}

func TestInterceptRequestBeforeAuth_RedactsRequest(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth() error = %v", err)
	}
	if resp.Body == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

// Another plugin can inject text after the before-auth pass; the after-auth
// pass must catch it while leaving the already-redacted text alone.
func TestInterceptRequestAfterAuth_RedactsTextInjectedLater(t *testing.T) {
	p := newTestPlugin(t)
	before, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		Body: []byte(`{"messages":[{"role":"user","content":"my email is test@example.com"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err = json.Unmarshal(before.Body, &payload); err != nil {
		t.Fatal(err)
	}
	payload["system"] = "memory: other@example.com"
	injected, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	after, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{Body: injected})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth() error = %v", err)
	}
	if after.Body == nil || strings.Contains(string(after.Body), "other@example.com") {
		t.Fatalf("after-auth hook must redact injected text, got %s", after.Body)
	}
	if !strings.Contains(string(after.Body), "my email is [EMAIL]") {
		t.Fatalf("already-redacted text must stay unchanged, got %s", after.Body)
	}
}

func TestInterceptRequestBeforeAuth_Passthrough(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"normal text"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Body: []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatal("expected no modification for non-PII text")
	}
}

func TestRedactRequestBody_KeywordOverlappingCandidateDoesNotPanic(t *testing.T) {
	p := newTestPlugin(t)
	text := strings.Repeat(".", 26) + "api key" + strings.Repeat("A", 20)
	payload, err := json.Marshal(map[string]any{
		"model":    "gpt-4",
		"messages": []any{map[string]any{"role": "user", "content": text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	modified, _, err := p.redactPayload(payload)
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified != nil {
		t.Fatalf("low-entropy text should be unchanged, got: %s", modified)
	}
}

func TestRedactRequestBody_SecretDetection(t *testing.T) {
	p := newTestPlugin(t)

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my api key is AKIAIOSFODNN7EXAMPLE"}]}`
	modified, _, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected AWS key to be redacted")
	}
	if strings.Contains(string(modified), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("AWS key should be redacted")
	}
}

func TestRedactRequestBody_InvalidJSON(t *testing.T) {
	p := newTestPlugin(t)
	body := `not valid json with email test@example.com`
	modified, _, err := p.redactPayload([]byte(body))
	if err != nil {
		t.Fatalf("redactPayload() error = %v", err)
	}
	if modified != nil {
		t.Fatal("expected nil for invalid JSON, got redacted text")
	}
}

func TestConfigShouldSkip(t *testing.T) {
	cfg := privacyFilterConfig{
		SkipModels:  []string{"gpt-4", "claude-3"},
		SkipFormats: []string{"openai"},
	}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "anthropic") {
		t.Fatal("should not skip unknown model/format")
	}
}

func TestConfigParse(t *testing.T) {
	raw := `
skip_models:
  - gpt-4
skip_formats:
  - openai
`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if len(cfg.SkipModels) != 1 || cfg.SkipModels[0] != "gpt-4" {
		t.Fatalf("skip_models = %v, want [gpt-4]", cfg.SkipModels)
	}
}

func TestRegistrationCapabilityJSON(t *testing.T) {
	caps := abiCapabilities{RequestInterceptor: true}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if !strings.Contains(string(raw), `"request_interceptor":true`) {
		t.Fatalf("expected request_interceptor in JSON: %s", string(raw))
	}
}

// Build the public plugin with a minimal rules file so these tests exercise
// configuration and hooks without depending on optional sidecar rules.
func newConfiguredInterceptor(t *testing.T, configYAML string) pluginapi.RequestInterceptor {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.toml"), []byte("title = \"consumer test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin([]byte("gitleaks_toml: rules.toml\n"+configYAML), dir, nil)
	if err != nil {
		t.Fatalf("buildPlugin() error = %v", err)
	}
	return plugin.Capabilities.RequestInterceptor
}

func assertJSONBody(t *testing.T, body []byte, expected string) {
	t.Helper()
	var got, want any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid response JSON %s: %v", body, err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response = %s, want %s", body, expected)
	}
}

func TestBuildPluginRejectsInvalidReplacementConfig(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"global empty", `replacement: ""`},
		{"global whitespace", `replacement: " \t "`},
		{"global boolean", `replacement: true`},
		{"global integer", `replacement: 123`},
		{"global float", `replacement: 1.25`},
		{"global timestamp", `replacement: 2026-10-07`},
		{"global sequence", `replacement: [hidden]`},
		{"global mapping", `replacement: {label: hidden}`},
		{"labels scalar", `replacement_labels: hidden`},
		{"labels boolean", `replacement_labels: false`},
		{"labels sequence", `replacement_labels: [hidden]`},
		{"label empty", `replacement_labels: {email: ""}`},
		{"label whitespace", `replacement_labels: {email: " \t "}`},
		{"label boolean", `replacement_labels: {email: true}`},
		{"label integer", `replacement_labels: {email: 123}`},
		{"label float", `replacement_labels: {email: 1.25}`},
		{"label timestamp", `replacement_labels: {email: 2026-10-07}`},
		{"label null", `replacement_labels: {email: null}`},
		{"label sequence", `replacement_labels: {email: [hidden]}`},
		{"label mapping", `replacement_labels: {email: {label: hidden}}`},
		{"key empty", `replacement_labels: {"": hidden}`},
		{"key leading whitespace", `replacement_labels: {" email": hidden}`},
		{"key trailing whitespace", `replacement_labels: {"email ": hidden}`},
		{"key tab", `replacement_labels: {"email\t": hidden}`},
		{"key number", `replacement_labels: {123: hidden}`},
		{"key boolean", `replacement_labels: {true: hidden}`},
		{"key null", `replacement_labels: {null: hidden}`},
		{"key sequence", "replacement_labels:\n  ? [email]\n  : hidden"},
		{"duplicate type key", "replacement_labels:\n  email: first\n  email: second"},
		{"duplicate global field", "replacement: first\nreplacement: second"},
		{"duplicate labels field", "replacement_labels: {}\nreplacement_labels: {}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildPlugin([]byte(tc.yaml), t.TempDir(), nil); err == nil {
				t.Fatalf("buildPlugin accepted invalid config: %s", tc.yaml)
			}
		})
	}
}

func TestConfiguredReplacementPriority(t *testing.T) {
	const input = `{"input":"raw [邮箱]; test@example.com; 13800138000"}`
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"defaults", "", `{"input":"raw [邮箱]; [EMAIL]; [PHONE]"}`},
		{"null unset", "replacement: null\nreplacement_labels: null", `{"input":"raw [邮箱]; [EMAIL]; [PHONE]"}`},
		{"empty mapping", "replacement_labels: {}", `{"input":"raw [邮箱]; [EMAIL]; [PHONE]"}`},
		{"global", "replacement: '[REDACTED]'", `{"input":"raw [邮箱]; [REDACTED]; [REDACTED]"}`},
		{"type before global", "replacement: '[REDACTED]'\nreplacement_labels:\n  email: '<MAIL>'", `{"input":"raw [邮箱]; <MAIL>; [REDACTED]"}`},
		{"type before default", "replacement_labels:\n  email: '<MAIL>'", `{"input":"raw [邮箱]; <MAIL>; [PHONE]"}`},
		{"future type accepted", "replacement_labels:\n  future_entity: '[FUTURE]'", `{"input":"raw [邮箱]; [EMAIL]; [PHONE]"}`},
		{"quoted numeric label", "replacement: '123'", `{"input":"raw [邮箱]; 123; 123"}`},
		{"quoted boolean label", "replacement: 'true'", `{"input":"raw [邮箱]; true; true"}`},
		{"label whitespace preserved", "replacement_labels:\n  email: ' [EMAIL] '", `{"input":"raw [邮箱];  [EMAIL] ; [PHONE]"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := newConfiguredInterceptor(t, tc.yaml)
			resp, err := interceptor.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{Body: []byte(input)})
			if err != nil {
				t.Fatal(err)
			}
			assertJSONBody(t, resp.Body, tc.want)
		})
	}
}

func TestConfiguredReplacementRequestStructures(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement: '[REDACTED]'\nreplacement_labels:\n  email: '[EMAIL]'")
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"messages string content",
			`{"model":"gpt-4","messages":[{"role":"system","content":"raw [邮箱]"},{"role":"user","content":"test@example.com / 13800138000"}],"temperature":0.5}`,
			`{"model":"gpt-4","messages":[{"role":"system","content":"raw [邮箱]"},{"role":"user","content":"[EMAIL] / [REDACTED]"}],"temperature":0.5}`,
		},
		{
			"messages multipart content",
			`{"messages":[{"role":"user","content":[{"type":"text","text":"test@example.com"},{"type":"image_url","image_url":{"url":"https://example.com/test@example.com"}},{"type":"text","text":42}]}]}`,
			`{"messages":[{"role":"user","content":[{"type":"text","text":"[EMAIL]"},{"type":"image_url","image_url":{"url":"https://example.com/test@example.com"}},{"type":"text","text":42}]}]}`,
		},
		{
			"input string",
			`{"input":"raw [邮箱] test@example.com 13800138000","metadata":{"email":"test@example.com"}}`,
			`{"input":"raw [邮箱] [EMAIL] [REDACTED]","metadata":{"email":"test@example.com"}}`,
		},
		{
			"input string content",
			`{"input":[{"role":"user","content":"test@example.com"},{"type":"function_call","arguments":"test@example.com"}]}`,
			`{"input":[{"role":"user","content":"[EMAIL]"},{"type":"function_call","arguments":"test@example.com"}]}`,
		},
		{
			"input multipart content",
			`{"input":[{"role":"user","content":[{"type":"input_text","text":"test@example.com"},{"type":"input_image","image_url":"https://example.com/test@example.com"},{"type":"input_file","file_data":"test@example.com"}]}]}`,
			`{"input":[{"role":"user","content":[{"type":"input_text","text":"[EMAIL]"},{"type":"input_image","image_url":"https://example.com/test@example.com"},{"type":"input_file","file_data":"test@example.com"}]}]}`,
		},
		{
			"messages and input both redacted",
			`{"messages":[{"content":"test@example.com"}],"input":"test@example.com"}`,
			`{"messages":[{"content":"[EMAIL]"}],"input":"[EMAIL]"}`,
		},
		{
			"input redacted when messages has no hit",
			`{"messages":[{"content":"normal text"}],"input":"test@example.com"}`,
			`{"messages":[{"content":"normal text"}],"input":"[EMAIL]"}`,
		},
		{
			"input redacted when messages is null",
			`{"messages":null,"input":"test@example.com"}`,
			`{"messages":null,"input":"[EMAIL]"}`,
		},
		{
			"mixed content and nonobjects",
			`{"messages":[null,7,"test@example.com",{"content":42},{"content":{"text":"test@example.com"}},{"content":[null,7,{"text":false},{"text":"test@example.com"}]}]}`,
			`{"messages":[null,7,"test@example.com",{"content":42},{"content":{"text":"test@example.com"}},{"content":[null,7,{"text":false},{"text":"[EMAIL]"}]}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := interceptor.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{Body: []byte(tc.body)})
			if err != nil {
				t.Fatal(err)
			}
			assertJSONBody(t, resp.Body, tc.want)
		})
	}
}

func TestConfiguredReplacementPassesNontextAndNoHitsThrough(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement: '[REDACTED]'")
	for _, body := range []string{
		`{"input":"raw [邮箱] ordinary text"}`,
		`{"messages":[{"content":[{"type":"image_url","image_url":{"url":"https://example.com/test@example.com"}}]}]}`,
		`{"input":[{"type":"function_call","arguments":"test@example.com"}]}`,
		`{"messages":[{"content":42},{"content":null},{"content":{"text":"test@example.com"}}]}`,
		`{"messages":42}`,
		`{"input":{"text":"test@example.com"}}`,
		`{"metadata":{"email":"test@example.com"}}`,
		`not JSON test@example.com`,
		"",
	} {
		resp, err := interceptor.InterceptRequestBeforeAuth(nil, pluginapi.RequestInterceptRequest{Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Body != nil {
			t.Fatalf("expected passthrough for %s, got %s", body, resp.Body)
		}
	}
}

func TestConfiguredReplacementBothHooksRemainStable(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, `
replacement: '[REDACTED]'
replacement_labels:
  email: '[EMAIL]'
  secret: '[SECRET]'
  phone: '[PHONE]'
  id: '[ID]'
  bank_card: '[BANK_CARD]'
  ip: '[IP]'
`)
	body := []byte(`{"input":"raw [邮箱]; test@example.com; 13800138000; 11010519900307743X; 4111111111111111; 192.168.1.1; AKIAIOSFODNN7EXAMPLE"}`)
	req := pluginapi.RequestInterceptRequest{Body: body}
	before, err := interceptor.InterceptRequestBeforeAuth(nil, req)
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, before.Body, `{"input":"raw [邮箱]; [EMAIL]; [PHONE]; [ID]; [BANK_CARD]; [IP]; [SECRET]"}`)
	req.Body = before.Body
	after, err := interceptor.InterceptRequestAfterAuth(nil, req)
	if err != nil {
		t.Fatal(err)
	}
	if after.Body != nil {
		t.Fatalf("recommended labels must pass through the second hook, got %s", after.Body)
	}
}

func TestConfiguredReplacementPreservesSkipConfig(t *testing.T) {
	interceptor := newConfiguredInterceptor(t, "replacement: '[REDACTED]'\nskip_models: [' GPT-4 ']\nskip_formats: [' OPENAI ']")
	body := []byte(`{"input":"test@example.com"}`)
	for _, req := range []pluginapi.RequestInterceptRequest{
		{Model: "gpt-4", Body: body},
		{RequestedModel: "gpt-4", Body: body},
		{SourceFormat: "openai", Body: body},
	} {
		before, err := interceptor.InterceptRequestBeforeAuth(nil, req)
		if err != nil {
			t.Fatal(err)
		}
		after, err := interceptor.InterceptRequestAfterAuth(nil, req)
		if err != nil {
			t.Fatal(err)
		}
		if before.Body != nil || after.Body != nil {
			t.Fatalf("skip config must preserve request body: before=%s after=%s", before.Body, after.Body)
		}
	}
}
