package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
)

// readmeExample is one invented value per kind, as the README shows it. The
// values identify nobody; they are chosen to look like what an administrator
// pastes into a session. Every one of them must be replaced on the forward
// path and come back on the return path.
type readmeExample struct {
	kind  string
	value string
}

// readmeExamples are assembled at run time where a literal would be
// rewritten in transit by the very plugin this repository builds (the
// sessions that maintain it run through it).
func readmeExamples() []readmeExample {
	ip := strings.Join([]string{"10", "20", "30", "7"}, ".")
	net := strings.Join([]string{"10", "20", "0", "0"}, ".") + "/16"
	home := "/" + strings.Join([]string{"home", "imuster", "projekte", "muster-gmbh", "deploy.sh"}, "/")
	return []readmeExample{
		{"host", "helios-nas01"},
		{"domain", "muster-gmbh.de"},
		{"person", "Ingrid Muster"},
		{"email", "ingrid.muster" + "@" + "muster-gmbh.de"},
		{"cidr", net},
		{"ipv4", ip},
		{"ipv6", "2a01:4f8:1c17:6f3::2"},
		{"mac", "3c:97:0e:4b:12:aa"},
		{"iban", "DE89370400440532013000"},
		{"uuid", "6f1c2a3e-9b4d-4e0f-8a7b-1c2d3e4f5a6b"},
		{"hexid", "9e3f4a1b8c2d4e5f6a7b8c9d0e1f2a3b"},
		{"fingerprint", "SHA256:Qz7vL2pXk9aRtY4mN8wS1bC3dF5gH6jK0lZ2xV4uB7e"},
		{"serial", "Serial Number: C02ZK3XYLVDL"},
		{"path_segment", home},
		{"secret", fixtures.FakeToken()},
	}
}

// TestRoundTrip_ReadmeExamples sends one value per kind through the forward
// path, builds the answer a model would give with the pseudonyms it saw, and
// runs it through the return path. Every original must be absent from the
// request that leaves and present again in the answer that arrives.
//
// With README_EXAMPLES_OUT set to a file path, the test also writes what it
// saw as tab-separated lines: kind, original, pseudonym, and four "stage"
// lines with the sentence at each station. tools/readme-examples.py renders
// the README section from that file, so the README shows values the plugin
// produced rather than values somebody typed.
func TestRoundTrip_ReadmeExamples(t *testing.T) {
	examples := readmeExamples()
	byKind := map[string]string{}
	var lines []string
	for _, e := range examples {
		byKind[e.kind] = e.value
		lines = append(lines, e.kind+"\t"+e.value)
	}
	sentence := byKind["person"] + " reports that " + byKind["host"] + " (" + byKind["ipv4"] +
		") does not answer since the last change to " + byKind["path_segment"] + "."

	req := map[string]any{
		"model": "claude-fable-5-1",
		"messages": []any{
			map[string]any{"role": "user", "content": strings.Join(lines, "\n")},
			map[string]any{"role": "user", "content": sentence},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	p := newPseudoPlugin(t, map[string]any{
		"terms": []any{
			map[string]any{"value": byKind["host"], "kind": "host"},
			map[string]any{"value": byKind["domain"], "kind": "domain"},
			map[string]any{"value": byKind["person"], "kind": "person", "ignore_case": true},
			map[string]any{"value": byKind["cidr"], "kind": "cidr"},
		},
		"path": map[string]any{"enabled": true, "replace_unknown": true},
	})
	resp := beforeAuth(t, p, "req-readme", body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	var out struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		t.Fatalf("unmarshal rewritten body: %v", err)
	}
	if len(out.Messages) != 2 {
		t.Fatalf("rewritten body has %d messages, want 2", len(out.Messages))
	}

	pseudo := map[string]string{}
	for _, line := range strings.Split(out.Messages[0].Content, "\n") {
		kind, value, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("rewritten line without tab: %q", line)
		}
		pseudo[kind] = value
	}
	for _, e := range examples {
		got, ok := pseudo[e.kind]
		if !ok {
			t.Fatalf("kind %s missing from the rewritten body", e.kind)
		}
		if got == e.value || strings.Contains(got, e.value) {
			t.Errorf("%s: %q was not replaced (got %q)", e.kind, e.value, got)
		}
		if e.kind == "email" && !strings.HasPrefix(got, "u-") {
			t.Errorf("email: the address must be replaced as a whole, got %q", got)
		}
	}
	modelSees := out.Messages[1].Content
	for _, e := range examples {
		if strings.Contains(modelSees, e.value) {
			t.Errorf("sentence still carries the %s value: %s", e.kind, modelSees)
		}
	}

	// The model answers with the pseudonyms it saw, verbatim, as a model does.
	modelSays := pseudo["host"] + " is reachable at " + pseudo["ipv4"] + " again. " +
		"The change in " + pseudo["path_segment"] + " reverted the route, I told " + pseudo["person"] + "."
	answer, err := json.Marshal(map[string]any{
		"id": "msg_01", "type": "message", "role": "assistant", "model": "claude-fable-5-1",
		"content":     []any{map[string]any{"type": "text", "text": modelSays}},
		"stop_reason": "end_turn",
		"usage":       map[string]any{"input_tokens": 10, "output_tokens": 20},
	})
	if err != nil {
		t.Fatalf("marshal answer: %v", err)
	}
	restored := interceptResponse(t, p, "req-readme", "claude", answer)
	if len(restored.Body) == 0 {
		t.Fatal("expected a restored body")
	}
	var back struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(restored.Body, &back); err != nil {
		t.Fatalf("unmarshal restored body: %v", err)
	}
	clientGets := back.Content[0].Text
	for _, kind := range []string{"host", "ipv4", "path_segment", "person"} {
		if !strings.Contains(clientGets, byKind[kind]) {
			t.Errorf("restored answer lacks the %s original: %s", kind, clientGets)
		}
		if strings.Contains(clientGets, pseudo[kind]) {
			t.Errorf("restored answer still carries the %s pseudonym: %s", kind, clientGets)
		}
	}

	outPath := os.Getenv("README_EXAMPLES_OUT")
	if outPath == "" {
		return
	}
	var sb strings.Builder
	for _, e := range examples {
		sb.WriteString(e.kind + "\t" + e.value + "\t" + pseudo[e.kind] + "\n")
	}
	sb.WriteString("stage\tclient_sends\t" + sentence + "\n")
	sb.WriteString("stage\tmodel_receives\t" + modelSees + "\n")
	sb.WriteString("stage\tmodel_answers\t" + modelSays + "\n")
	sb.WriteString("stage\tclient_gets\t" + clientGets + "\n")
	if err := os.WriteFile(outPath, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", outPath, err)
	}
}
