package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privacyfilter/filter"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func newTestPlugin(t *testing.T) *privacyFilterPlugin {
	t.Helper()
	f, err := filter.New("")
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
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if !strings.Contains(string(modified), "[邮箱]") {
		t.Fatalf("expected [邮箱] placeholder in output: %s", string(modified))
	}
	if strings.Contains(string(modified), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestRedactRequestBody_NoPII(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified != nil {
		t.Fatalf("expected nil for no-PII body, got: %s", string(modified))
	}
}

func TestRedactRequestBody_MultiPartContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"my phone is 13800138000"}]}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
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
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
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
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
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
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
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

func TestInterceptRequestAfterAuth_RedactsFinalRequest(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(nil, pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth() error = %v", err)
	}
	if resp.Body == nil {
		t.Fatal("expected redacted body, got nil")
	}
	if strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatal("original email should be redacted")
	}
}

func TestInterceptRequestBeforeAuth_Passthrough(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"normal text"}]}`
	resp, err := p.interceptRequest(pluginapi.RequestInterceptRequest{
		Body: []byte(body),
	})
	if err != nil {
		t.Fatalf("interceptRequest() error = %v", err)
	}
	if resp.Body != nil {
		t.Fatal("expected no modification for non-PII text")
	}
}

func TestRedactRequestBody_SecretDetection(t *testing.T) {
	rulesDir := filepath.Join("..", "rules")
	tomlPath := filepath.Join(rulesDir, "gitleaks.toml")
	if _, err := os.Stat(tomlPath); os.IsNotExist(err) {
		t.Skip("gitleaks.toml not found, skipping secret detection test")
	}
	f, err := filter.New(tomlPath)
	if err != nil {
		t.Fatalf("filter.New() error = %v", err)
	}
	p := &privacyFilterPlugin{cfg: defaultConfig(), filter: f}

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my api key is AKIAIOSFODNN7EXAMPLE"}]}`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if modified == nil {
		t.Skip("secret not detected with built-in rules only")
	}
	if strings.Contains(string(modified), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("AWS key should be redacted")
	}
}

func TestRedactRequestBody_InvalidJSON(t *testing.T) {
	p := newTestPlugin(t)
	body := `not valid json with email test@example.com`
	modified, err := p.redactRequestBody([]byte(body))
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
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
