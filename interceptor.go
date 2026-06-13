package main

import (
	"context"
	"encoding/json"
	"fmt"

	"privacyfilter/filter"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
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
	return p.interceptRequest(req)
}

func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(req)
}

func (p *privacyFilterPlugin) interceptRequest(req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	resp := pluginapi.RequestInterceptResponse{}

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}

	body := req.Body
	if len(body) == 0 {
		return resp, nil
	}

	modified, err := p.redactRequestBody(body)
	if err != nil {
		log.Warnf("privacy filter failed to process request body: %v", err)
		return resp, nil
	}

	if modified != nil {
		resp.Body = modified
	}
	return resp, nil
}

func (p *privacyFilterPlugin) redactRequestBody(body []byte) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil
	}

	field := "messages"
	items, ok := payload[field]
	if !ok {
		field = "input"
		items, ok = payload[field]
	}
	if !ok {
		return nil, nil
	}

	changed := false
	if inputText, ok := items.(string); ok {
		changed = p.editText(&inputText)
		if changed {
			payload[field] = inputText
			log.Infof("privacy filter: redacted entities in %s (model=%s)", field, payload["model"])
		}
	} else if itemSlice, ok := items.([]any); ok {
		changed = p.editContentItems(itemSlice, field, payload["model"])
		if changed {
			payload[field] = itemSlice
		}
	} else {
		return nil, nil
	}
	if !changed {
		return nil, nil
	}

	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal redacted request: %w", err)
	}
	return out, nil
}

func (p *privacyFilterPlugin) editContentItems(items []any, field string, model any) bool {
	changed := false
	for i, item := range items {
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, ok := itemMap["content"]
		if !ok {
			continue
		}
		if p.editContent(&content) {
			itemMap["content"] = content
			changed = true
			log.Infof("privacy filter: redacted entities in %s[%d] (model=%s)", field, i, model)
		}
	}
	return changed
}

func (p *privacyFilterPlugin) editContent(content *any) bool {
	changed := false
	switch v := (*content).(type) {
	case string:
		if p.editText(&v) {
			*content = v
			changed = true
		}
	case []any:
		for j, part := range v {
			partMap, ok := part.(map[string]any)
			if !ok {
				continue
			}
			text, ok := partMap["text"].(string)
			if !ok {
				continue
			}
			if p.editText(&text) {
				partMap["text"] = text
				v[j] = partMap
				changed = true
			}
		}
	}
	return changed
}

func (p *privacyFilterPlugin) editText(text *string) bool {
	result := p.filter.Redact(*text)
	if !result.Hit {
		return false
	}
	*text = result.Redacted
	return true
}
