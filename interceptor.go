package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"privacyfilter/filter"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type privacyFilterPlugin struct {
	cfg       privacyFilterConfig
	pluginDir string
	filter    *filter.Filter
}

var _ pluginapi.RequestInterceptor = (*privacyFilterPlugin)(nil)

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

// InterceptRequestAfterAuth redacts again because other plugins can add text
// after the before-auth pass: lower-priority before-auth interceptors and
// higher-priority after-auth interceptors both run later in the chain.
// Redaction is idempotent, so already-clean text produces no hits.
func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req)
}

func (p *privacyFilterPlugin) interceptRequest(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	resp := pluginapi.RequestInterceptResponse{}

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if len(req.Body) == 0 {
		return resp, nil
	}

	modified, hits, err := p.redactPayload(req.Body)
	if err != nil {
		pluginLog(ctx, logLevelWarn, "privacy filter failed to process request body: "+err.Error(), map[string]any{
			"error": err.Error(),
		})
		return resp, nil
	}
	if modified == nil {
		return resp, nil
	}

	// The host text formatter only prints a fixed set of field names, so the
	// summary is repeated in the message.
	message := fmt.Sprintf("privacy filter redacted %d field(s): %s", len(hits), strings.Join(hits, ", "))
	pluginLog(ctx, logLevelInfo, message, map[string]any{
		"model":           req.Model,
		"source_format":   req.SourceFormat,
		"redacted_count":  len(hits),
		"redacted_fields": hits,
	})
	resp.Body = modified
	return resp, nil
}

// redactPayload returns the rewritten body (nil when nothing changed) and the
// JSON paths of the redacted fields. Non-JSON bodies pass through untouched.
func (p *privacyFilterPlugin) redactPayload(body []byte) ([]byte, []string, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, nil
	}

	r := &redaction{filter: p.filter}
	if !r.payload(payload, "") {
		return nil, nil, nil
	}

	out, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal redacted request: %w", err)
	}
	return out, r.hits, nil
}

// redaction walks the prompt-bearing fields of the client request formats the
// host passes to interceptors (OpenAI chat, OpenAI Responses, OpenAI image and
// video generation, Claude, Gemini and Gemini CLI). Only free-form text is rewritten; structured data such as tool
// call arguments, function responses, files and images is left untouched.
type redaction struct {
	filter *filter.Filter
	hits   []string
}

func (r *redaction) payload(m map[string]any, path string) bool {
	changed := false
	// messages: OpenAI chat and Claude. input: OpenAI Responses. contents: Gemini.
	for _, key := range []string{"messages", "input", "contents"} {
		changed = r.itemsField(m, key, path) || changed
	}
	// system: Claude. instructions: OpenAI Responses.
	for _, key := range []string{"system", "instructions"} {
		changed = r.contentField(m, key, path) || changed
	}
	for _, key := range []string{"systemInstruction", "system_instruction"} {
		if instruction, ok := m[key].(map[string]any); ok {
			changed = r.item(instruction, joinPath(path, key)) || changed
		}
	}
	changed = r.promptField(m, path) || changed
	// Gemini CLI wraps a Gemini request in a top-level "request" object.
	if inner, ok := m["request"].(map[string]any); ok && path == "" {
		changed = r.payload(inner, "request") || changed
	}
	return changed
}

func (r *redaction) itemsField(m map[string]any, key, path string) bool {
	path = joinPath(path, key)
	switch v := m[key].(type) {
	case string:
		return r.stringField(m, key, path)
	case []any:
		changed := false
		for i, item := range v {
			if itemMap, ok := item.(map[string]any); ok {
				changed = r.item(itemMap, fmt.Sprintf("%s[%d]", path, i)) || changed
			}
		}
		return changed
	}
	return false
}

// item handles a single conversation entry: an OpenAI/Claude message, an
// OpenAI Responses input item, or a Gemini content / system instruction.
func (r *redaction) item(m map[string]any, path string) bool {
	changed := r.contentField(m, "content", path)
	if m["type"] == "function_call_output" {
		changed = r.contentField(m, "output", path) || changed
	}
	if parts, ok := m["parts"].([]any); ok {
		changed = r.parts(parts, joinPath(path, "parts")) || changed
	}
	return changed
}

func (r *redaction) parts(parts []any, path string) bool {
	changed := false
	for i, part := range parts {
		if partMap, ok := part.(map[string]any); ok {
			changed = r.part(partMap, fmt.Sprintf("%s[%d]", path, i)) || changed
		}
	}
	return changed
}

func (r *redaction) part(m map[string]any, path string) bool {
	// Gemini thought parts are bound to a thoughtSignature; rewriting their
	// text would make the upstream reject the signature.
	if thought, _ := m["thought"].(bool); thought {
		return false
	}
	changed := r.stringField(m, "text", joinPath(path, "text"))
	if m["type"] == "tool_result" {
		changed = r.contentField(m, "content", path) || changed
	}
	return changed
}

// contentField redacts a value that is either plain text or a list of parts.
func (r *redaction) contentField(m map[string]any, key, path string) bool {
	path = joinPath(path, key)
	switch v := m[key].(type) {
	case string:
		return r.stringField(m, key, path)
	case []any:
		return r.parts(v, path)
	}
	return false
}

// promptField handles the image/video generation prompt (a string or a list of
// strings). Completions requests never reach interceptors in this shape: the
// host converts them to chat completions first.
func (r *redaction) promptField(m map[string]any, path string) bool {
	path = joinPath(path, "prompt")
	switch v := m["prompt"].(type) {
	case string:
		return r.stringField(m, "prompt", path)
	case []any:
		changed := false
		for i, item := range v {
			text, ok := item.(string)
			if !ok {
				continue
			}
			if redacted, hit := r.text(text, fmt.Sprintf("%s[%d]", path, i)); hit {
				v[i] = redacted
				changed = true
			}
		}
		return changed
	}
	return false
}

func (r *redaction) stringField(m map[string]any, key, path string) bool {
	text, ok := m[key].(string)
	if !ok {
		return false
	}
	redacted, hit := r.text(text, path)
	if hit {
		m[key] = redacted
	}
	return hit
}

func (r *redaction) text(text, path string) (string, bool) {
	result := r.filter.Redact(text)
	if !result.Hit {
		return text, false
	}
	r.hits = append(r.hits, path)
	return result.Redacted, true
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}
