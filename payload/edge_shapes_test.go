package payload_test

// Shapes the schema allows and the deny list has an opinion about: content
// as a plain string, a tool result whose content is a list of blocks, fields
// the API knows and the plugin does not, and an object made of nothing but
// denied keys.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The content of a message may be a plain string instead of a list of
// blocks, and so may the system prompt. Both carry user text and both have
// to be filtered.
func TestJSONEdge_ContentAsString(t *testing.T) {
	body := fmt.Sprintf(`{"system":%q,"messages":[`+
		`{"role":"user","content":%q},`+
		`{"role":"assistant","content":[{"type":"text","text":%q}]},`+
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01","content":%q}]}]}`,
		needle, needle, needle, needle)

	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if leaked(out) {
			t.Errorf("%s: content as a plain string was not filtered: %s", name, out)
		}
	}
	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("visited: %q", paths)
}

// A tool result whose content mixes text, an image and a document. The text
// must be filtered, the base64 image data must stay untouched, and the
// document source of type text is the documented hole in source.data: it
// carries user text and has to be filtered.
func TestJSONEdge_ToolResultWithNestedContent(t *testing.T) {
	const imageData = "QUFBQUFB"
	body := fmt.Sprintf(`{"messages":[{"role":"user","content":[`+
		`{"type":"tool_result","tool_use_id":"toolu_01","is_error":false,"content":[`+
		`{"type":"text","text":%q},`+
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":%q}},`+
		`{"type":"document","source":{"type":"text","media_type":"text/plain","data":%q}},`+
		`{"type":"tool_result","content":[{"type":"text","text":%q}]}]}]}]}`,
		needle, imageData, needle, needle)

	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if leaked(out) {
			t.Errorf("%s: a text inside the nested tool result was not filtered: %s", name, out)
		}
		if !bytes.Contains(out, []byte(imageData)) {
			t.Errorf("%s: the base64 image data was rewritten: %s", name, out)
		}
		if !bytes.Contains(out, []byte("toolu_01")) {
			t.Errorf("%s: the tool_use_id was rewritten: %s", name, out)
		}
		if !bytes.Contains(out, []byte("image/png")) || !bytes.Contains(out, []byte("text/plain")) {
			t.Errorf("%s: a media_type was rewritten: %s", name, out)
		}
	}
	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("visited: %q", paths)
}

// Fields the API knows and the deny list does not name. Two of them hold a
// name that is defined somewhere else in the same body: tool_choice.name
// points at tools[].name, and input_schema.required points at a key of
// input_schema.properties. The name is replaced at one end and kept at the
// other, so the request ends up pointing at something that is not there.
func TestJSONEdge_FieldsTheAPIKnows(t *testing.T) {
	body := fmt.Sprintf(`{"model":"claude","max_tokens":1024,`+
		`"betas":["beta-one"],"container":%q,"service_tier":"auto",`+
		`"anthropic_version":"2023-06-01","stop_sequences":[%q],`+
		`"mcp_servers":[{"type":"url","name":%q,"authorization_token":"token"}],`+
		`"tool_choice":{"type":"tool","name":%q},`+
		`"tools":[{"name":%q,"description":"looks things up","input_schema":`+
		`{"type":"object","properties":{%q:{"type":"string","description":%q}},"required":[%q]}}],`+
		`"metadata":{"user_id":"u1"},`+
		`"messages":[{"role":"user","content":%q}]}`,
		"cnt_"+alias, alias, alias, alias, alias, alias, needle, alias, needle)

	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("visited: %q", paths)

	fwd, ret := checkBoth(t, body)

	var got struct {
		ToolChoice struct {
			Name string `json:"name"`
		} `json:"tool_choice"`
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]any `json:"properties"`
				Required   []string       `json:"required"`
			} `json:"input_schema"`
		} `json:"tools"`
		MCPServers []struct {
			Name string `json:"name"`
		} `json:"mcp_servers"`
		Container string `json:"container"`
	}
	if err := json.Unmarshal(fwd, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Tools) != 1 || len(got.Tools[0].InputSchema.Required) != 1 {
		t.Fatalf("body did not survive: %s", fwd)
	}
	t.Logf("tools[0].name=%q tool_choice.name=%q", got.Tools[0].Name, got.ToolChoice.Name)
	t.Logf("required=%q properties keys=%v", got.Tools[0].InputSchema.Required, keysOf(got.Tools[0].InputSchema.Properties))
	t.Logf("mcp_servers[0].name=%q container=%q", got.MCPServers[0].Name, got.Container)

	if got.ToolChoice.Name != got.Tools[0].Name {
		t.Errorf("tool_choice now names %q while the tool is called %q, so the request points at a tool that does not exist",
			got.ToolChoice.Name, got.Tools[0].Name)
	}
	if _, ok := got.Tools[0].InputSchema.Properties[got.Tools[0].InputSchema.Required[0]]; !ok {
		t.Errorf("input_schema requires %q, which is not among its properties %v",
			got.Tools[0].InputSchema.Required[0], keysOf(got.Tools[0].InputSchema.Properties))
	}
	if bytes.Contains(ret, []byte(alias)) && !bytes.Contains(ret, []byte(aliasMask)) {
		t.Logf("the return path touched none of the names")
	}
}

// keysOf lists the keys of a decoded object, for a readable message.
func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// An object made of nothing but denied keys is invisible to the filter. That
// is right where the keys mean what the schema says; the same names as the
// arguments of a tool are arbitrary JSON the model fills in, and there the
// deny list does not apply: every argument is visited, its key included.
// "signature" is not in the list here because it is bound to the thinking
// block, not to the key name; elsewhere it is ordinary text.
func TestJSONEdge_ObjectOfOnlyDeniedKeys(t *testing.T) {
	denied := []string{"model", "role", "type", "id", "tool_use_id",
		"stop_reason", "stop_sequence", "media_type", "cache_control"}

	var b strings.Builder
	b.WriteByte('{')
	for i, k := range denied {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%q:%q`, k, needle)
	}
	b.WriteByte('}')

	out, changed, err := outbound(b.String())
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	t.Logf("a body of only denied keys: changed=%v", changed)
	if changed {
		t.Errorf("a denied key was rewritten after all: %s", out)
	}

	// The same names one level down, where they are the arguments of a tool
	// and mean nothing to the schema.
	var args strings.Builder
	args.WriteByte('{')
	for i, k := range denied {
		if i > 0 {
			args.WriteByte(',')
		}
		fmt.Fprintf(&args, `%q:%q`, k, needle)
	}
	fmt.Fprintf(&args, `,"query":%q}`, needle)

	body := fmt.Sprintf(`{"messages":[{"role":"user","content":[`+
		`{"type":"tool_use","id":"toolu_01","name":"crm_lookup","input":%s}]}]}`, args.String())

	fwd, _, err := outbound(body)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("of %d tool arguments the walk offered %d strings, keys and values: %q", len(denied)+1, len(paths), paths)
	if n := bytes.Count(fwd, []byte(needle)); n > 0 {
		t.Errorf("%d tool arguments kept their clear text because their key is denied: %s", n, fwd)
	}
	if len(paths) != 2*(len(denied)+1) {
		t.Errorf("want every argument offered twice, as key and as value, got %d offers", len(paths))
	}
}

// A denied key whose value is an array is not protected: the leaf of the
// path is then an index, and an index never matches a key. The dotted rules
// do not have the gap, because they strip the indexes first. Documented in
// the comment on DenyList.Keys, so this only records the difference.
func TestJSONEdge_DeniedKeyWithArrayValue(t *testing.T) {
	body := fmt.Sprintf(`{"id":[%q],"model":[%q],"metadata":{"user_id":[%q]},"signature":{"nested":%q}}`,
		needle, needle, needle, needle)
	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("visited behind denied keys: %q", paths)
	out, _, err := outbound(body)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	t.Logf("out=%s", out)
}
