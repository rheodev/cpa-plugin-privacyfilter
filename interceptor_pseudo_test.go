package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

// newPseudoPlugin builds the plugin from a YAML document the way the host does,
// with a secret file in a temporary directory. override replaces top-level keys
// of the document, so a single test can switch mode, on_error or the limits.
// tableOf returns the table bound to requestID or fails the test.
func (p *privacyFilterPlugin) tableOf(t *testing.T, requestID string) *mapping.Table {
	t.Helper()
	table, err := p.store.Get(requestID)
	if err != nil {
		t.Fatalf("store.Get(%s): %v", requestID, err)
	}
	return table
}

func newPseudoPlugin(t *testing.T, override map[string]any) *privacyFilterPlugin {
	t.Helper()

	dir := t.TempDir()
	secretPath := filepath.Join(dir, pseudo.DefaultSecretFile)
	secret := append(append([]byte{}, fixtures.Secret...), '\n')
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	doc := map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": secretPath,
		"terms":            fixtureTermsDoc(),
		"patterns": map[string]any{
			"ipv4": true, "ipv6": true, "cidr": true,
			"mac": true, "email": true, "iban": true, "url": false,
		},
		"packyme": map[string]any{"enabled": true},
		// filenames: all is the strongest setting; the corpus test below
		// demands that the fixture's file name does not survive either.
		"path":     map[string]any{"enabled": true, "replace_unknown": true, "filenames": "all"},
		"on_error": string(OnErrorBlock),
	}
	for k, v := range override {
		doc[k] = v
	}

	raw, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	plug, err := buildPlugin(raw, dir, nil)
	if err != nil {
		t.Fatalf("buildPlugin: %v", err)
	}
	p, ok := plug.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok {
		t.Fatalf("RequestInterceptor is %T, want *privacyFilterPlugin", plug.Capabilities.RequestInterceptor)
	}
	return p
}

// fixtureTermsDoc returns the fixture's terms as the YAML document lists
// them, so a test can add a term before it builds the plugin.
func fixtureTermsDoc() []any {
	terms := make([]any, 0, len(fixtures.Terms))
	for _, term := range fixtures.Terms {
		entry := map[string]any{"kind": string(term.Kind)}
		if term.Value != "" {
			entry["value"] = term.Value
		} else {
			entry["regex"] = term.Regex
		}
		if term.IgnoreCase {
			entry["ignore_case"] = true
		}
		terms = append(terms, entry)
	}
	return terms
}

// fixtureBody marshals the shared request fixture.
func fixtureBody(t *testing.T, session string) ([]byte, map[string]any) {
	t.Helper()
	req := fixtures.Request(session)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return body, req
}

// thinkingText returns the text of the thinking block of the fixture, read from
// the fixture itself so the test does not hard-code a value that lives there.
func thinkingText(t *testing.T, req map[string]any) string {
	t.Helper()
	messages, ok := req["messages"].([]any)
	if !ok || len(messages) < 2 {
		t.Fatal("fixture has no assistant turn")
	}
	blocks, ok := messages[1].(map[string]any)["content"].([]any)
	if !ok || len(blocks) == 0 {
		t.Fatal("fixture assistant turn has no blocks")
	}
	text, ok := blocks[0].(map[string]any)["thinking"].(string)
	if !ok {
		t.Fatal("fixture assistant turn has no thinking block")
	}
	return text
}

func jsonString(t *testing.T, s string) []byte {
	t.Helper()
	enc, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal %q: %v", s, err)
	}
	return enc
}

func beforeAuth(t *testing.T, p *privacyFilterPlugin, requestID string, body []byte) pluginapi.RequestInterceptResponse {
	t.Helper()
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    requestID,
		SourceFormat: "claude",
		Model:        "claude-fable-5-1",
		Headers:      http.Header{},
		Body:         body,
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}
	return resp
}

// TestPseudonymizeRequest_NoCorpusValueSurvives is the leak test on the
// interceptor: no confidential value of the corpus may leave in the rewritten
// body.
//
// Two regions are cut out of the search before it runs, because the contract
// preserves them byte for byte and both contain corpus text on purpose: the
// thinking block, which the deny list excludes as a whole, and the benign
// message, whose look-alikes ("Markusplatz" contains the person term "markus")
// must survive untouched. Everything else has to be clean. See the disagreement
// noted for internal/leaktest, which asserts both properties over the whole
// body at once.
func TestPseudonymizeRequest_NoCorpusValueSurvives(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, req := fixtureBody(t, fixtures.SessionA)

	resp := beforeAuth(t, p, "req-1", body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	if len(resp.Body) == 0 {
		t.Fatal("expected a rewritten body, got none")
	}
	if !json.Valid(resp.Body) {
		t.Fatalf("rewritten body is not valid JSON: %s", resp.Body)
	}

	preserved := jsonString(t, thinkingText(t, req))
	benign := jsonString(t, fixtures.Benign)
	scan := bytes.ReplaceAll(resp.Body, preserved, []byte(`""`))
	scan = bytes.ReplaceAll(scan, benign, []byte(`""`))
	lower := bytes.ToLower(scan)

	for _, term := range fixtures.All() {
		haystack, needle := scan, []byte(term.Value)
		if term.IgnoreCase {
			haystack, needle = lower, []byte(strings.ToLower(term.Value))
		}
		if bytes.Contains(haystack, needle) {
			t.Errorf("%s %q leaked", term.Kind, term.Value)
		}
		escaped := jsonString(t, term.Value)
		if bytes.Contains(scan, escaped[1:len(escaped)-1]) {
			t.Errorf("%s %q leaked in escaped form", term.Kind, term.Value)
		}
	}

	// The system prompt and the tool description are fields the original
	// plugin never looked at.
	for _, s := range []string{"Markus Wendler", "athene.lan", "10.13.0.0/16", "helios-nas-01"} {
		if bytes.Contains(scan, []byte(s)) {
			t.Errorf("%q survived in the system prompt or the tool description", s)
		}
	}
}

// TestPseudonymizeRequest_DeniedFieldsUntouched: the thinking block with its
// signature, metadata.user_id and the benign message come back unchanged.
func TestPseudonymizeRequest_DeniedFieldsUntouched(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, req := fixtureBody(t, fixtures.SessionA)
	resp := beforeAuth(t, p, "req-1", body)

	thinking := jsonString(t, thinkingText(t, req))
	for _, want := range [][]byte{
		append([]byte(`"thinking":`), thinking...),
		[]byte(`"signature":"` + fixtures.ThinkingSignature + `"`),
		[]byte(`"user_id":"` + fixtures.UserIDFor(fixtures.SessionA) + `"`),
		[]byte(`"id":"` + fixtures.ToolUseID + `"`),
		[]byte(`"tool_use_id":"` + fixtures.ToolUseID + `"`),
		[]byte(`"name":"Bash"`),
		[]byte(`"model":"claude-fable-5-1"`),
		jsonString(t, fixtures.Benign),
	} {
		if !bytes.Contains(resp.Body, want) {
			t.Errorf("denied field changed or lost: %s", want)
		}
	}
}

// TestPseudonymizeRequest_StoresTable: the mapping table lands under the
// RequestID, and it is stored even when nothing was replaced.
func TestPseudonymizeRequest_StoresTable(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", body)

	table, err := p.store.Get("req-1")
	if err != nil {
		t.Fatalf("store.Get(req-1): %v", err)
	}
	if table.Len() == 0 {
		t.Fatal("stored table is empty")
	}

	clean := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"Der Plan steht."}]}`)
	resp := beforeAuth(t, p, "req-2", clean)
	if resp.Body != nil {
		t.Fatalf("expected no rewrite for a clean body, got: %s", resp.Body)
	}
	empty, err := p.store.Get("req-2")
	if err != nil {
		t.Fatalf("store.Get(req-2): %v", err)
	}
	if empty.Len() != 0 {
		t.Fatalf("table for a clean body has %d entries, want 0", empty.Len())
	}
}

// afterAuth sends body through the hook after authentication, as the host
// does with the first hook's output once the credentials are checked.
func afterAuth(t *testing.T, p *privacyFilterPlugin, requestID string, body []byte) pluginapi.RequestInterceptResponse {
	t.Helper()
	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    requestID,
		SourceFormat: "claude",
		Model:        "claude-fable-5-1",
		Headers:      http.Header{},
		Body:         body,
	})
	if err != nil {
		t.Fatalf("InterceptRequestAfterAuth: %v", err)
	}
	return resp
}

// TestPseudonymizeRequest_AfterAuthIsQuietOverTheFirstPass: the second hook
// sees the first pass's output. It walks it over the table the first pass
// bound, and that table excludes its own pseudonyms, so nothing changes, no
// row is added and no second table or binding appears.
func TestPseudonymizeRequest_AfterAuthIsQuietOverTheFirstPass(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-1", body)
	rows := p.tableOf(t, "req-1").Len()
	if rows == 0 {
		t.Fatal("the first pass replaced nothing")
	}

	second := afterAuth(t, p, "req-1", first.Body)
	if second.Body != nil || second.Terminate {
		t.Fatalf("the second pass changed the body:\n%s", second.Body)
	}
	if got := p.tableOf(t, "req-1").Len(); got != rows {
		t.Fatalf("the second pass grew the table from %d to %d rows", rows, got)
	}
	if p.store.Len() != 1 || p.store.Bound() != 1 {
		t.Fatalf("store holds %d tables and %d bindings, want 1 and 1", p.store.Len(), p.store.Bound())
	}
}

// TestPseudonymizeRequest_AfterAuthRewritesWhatCameInBetween: text the host
// or another plugin adds between the two hooks is rewritten with the first
// pass's table and salt. A value the first pass replaced gets the same
// pseudonym again, a new one gets a row in the same table, the text of the
// first pass stays byte for byte, the pass is idempotent over its own
// output, and the return path restores the new row as any other.
func TestPseudonymizeRequest_AfterAuthRewritesWhatCameInBetween(t *testing.T) {
	const injected = "10.77.0.80"
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-1", body)
	table := p.tableOf(t, "req-1")
	rows := table.Len()
	if !table.Has(detect.KindHost, "athene.lan") {
		t.Fatal("the first pass did not replace the host of the fixture")
	}
	host := table.Lookup(detect.KindHost, "athene.lan")

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(first.Body, &fields); err != nil {
		t.Fatal(err)
	}
	fields["system"] = jsonString(t, "memory: athene.lan answers at "+injected)
	between, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}

	after := afterAuth(t, p, "req-1", between)
	if after.Body == nil || after.Terminate {
		t.Fatalf("the second pass left the injected text alone: %+v", after)
	}
	out := string(after.Body)
	for _, gone := range []string{"athene.lan", injected} {
		if strings.Contains(out, gone) {
			t.Errorf("%q survived the second pass, body: %s", gone, out)
		}
	}
	if !strings.Contains(out, `"system":"memory: `+host+` answers at `) {
		t.Errorf("the host did not get the first pass's pseudonym %q, body: %s", host, out)
	}
	if got := table.Len(); got != rows+1 {
		t.Errorf("the second pass grew the table from %d to %d rows, want one new row", rows, got)
	}
	if !table.Has(detect.KindIPv4, injected) {
		t.Fatalf("the injected address has no row in the request's table")
	}
	address := table.Lookup(detect.KindIPv4, injected)
	if !strings.Contains(out, address) {
		t.Errorf("the injected address was not replaced by its row %q, body: %s", address, out)
	}
	// json.Marshal re-escaped the first pass's text while splicing the
	// system field in, so the bytes to compare with are those of between.
	var betweenFields, afterFields map[string]json.RawMessage
	if err := json.Unmarshal(between, &betweenFields); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(after.Body, &afterFields); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterFields["messages"], betweenFields["messages"]) {
		t.Errorf("the second pass touched the messages of the first pass:\n%s\n%s", afterFields["messages"], betweenFields["messages"])
	}
	if p.store.Len() != 1 || p.store.Bound() != 1 {
		t.Fatalf("store holds %d tables and %d bindings, want 1 and 1", p.store.Len(), p.store.Bound())
	}

	if again := afterAuth(t, p, "req-1", after.Body); again.Body != nil {
		t.Fatalf("the second pass is not idempotent over its own output:\n%s", again.Body)
	}

	response := []byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ping ` + address + `"}],"model":"claude-fable-5-1"}`)
	restored := interceptResponse(t, p, "req-1", "claude", response)
	if !bytes.Contains(restored.Body, []byte("ping "+injected)) {
		t.Fatalf("the return path did not restore the row the second pass added: %s", restored.Body)
	}
}

// TestPseudonymizeRequest_AfterAuthWithoutBindingRunsTheFullPass: a request
// the store does not know, no first pass, an empty RequestID or a table
// dropped in between, is identified and rewritten as in the first hook, with
// the same result, and bound for the return path.
func TestPseudonymizeRequest_AfterAuthWithoutBindingRunsTheFullPass(t *testing.T) {
	body, _ := fixtureBody(t, fixtures.SessionA)
	reference := beforeAuth(t, newPseudoPlugin(t, nil), "req-1", body)

	p := newPseudoPlugin(t, nil)
	after := afterAuth(t, p, "req-1", body)
	if after.Terminate || !bytes.Equal(after.Body, reference.Body) {
		t.Fatalf("the full pass in the second hook differs from the first hook's:\n%s\n%s", after.Body, reference.Body)
	}
	if p.store.Len() != 1 || p.store.Bound() != 1 {
		t.Fatalf("store holds %d tables and %d bindings, want 1 and 1", p.store.Len(), p.store.Bound())
	}
}

// TestPseudonymizeRequest_SessionSources: header and metadata.user_id name the
// same conversation, so both give the same pseudonyms; another conversation
// gives different ones.
func TestPseudonymizeRequest_SessionSources(t *testing.T) {
	p := newPseudoPlugin(t, nil)

	viaMetadata, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", viaMetadata)

	noSession, _ := fixtureBody(t, "")
	headers := http.Header{}
	headers.Set(pseudo.SessionHeader, fixtures.SessionA)
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID:    "req-2",
		SourceFormat: "claude",
		Headers:      headers,
		Body:         noSession,
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}

	a, _ := p.store.Get("req-1")
	b, _ := p.store.Get("req-2")
	for _, e := range a.Entries() {
		if got := b.Lookup(e.Kind, e.Original); got != e.Pseudonym {
			t.Errorf("%s: header session gives %q, metadata session gave %q", e.Kind, got, e.Pseudonym)
		}
	}
	if !json.Valid(resp.Body) {
		t.Fatalf("rewritten body is not valid JSON: %s", resp.Body)
	}

	other, _ := fixtureBody(t, fixtures.SessionB)
	beforeAuth(t, p, "req-3", other)
	c, _ := p.store.Get("req-3")
	same := 0
	for _, e := range a.Entries() {
		if c.Lookup(e.Kind, e.Original) == e.Pseudonym {
			same++
		}
	}
	if same != 0 {
		t.Fatalf("%d pseudonyms identical across two conversations", same)
	}
}

// TestPseudonymizeRequest_Deterministic: the same body twice gives the same
// bytes, so the thinking-block signatures of a conversation stay valid.
func TestPseudonymizeRequest_Deterministic(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-1", body)
	second := beforeAuth(t, p, "req-2", body)
	if !bytes.Equal(first.Body, second.Body) {
		t.Fatal("two forward passes over the same body differ")
	}
}

// TestPseudonymizeRequest_RealShapedToken is the positive control for the
// credential layer: a token of the documented shape and full entropy is
// replaced. The value is assembled from parts so this file never contains a
// complete token literal, as internal/fixtures does it.
func TestPseudonymizeRequest_RealShapedToken(t *testing.T) {
	token := "gh" + "p_" + "Xk9mQ2vTb7YpLz4Rw8NcHs5JdFg1AeUi3Bo0"
	req := map[string]any{
		"model":    "claude-fable-5-1",
		"messages": []any{map[string]any{"role": "user", "content": "Der Token lautet " + token + " und gehört rotiert."}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	p := newPseudoPlugin(t, nil)
	resp := beforeAuth(t, p, "req-1", body)
	if bytes.Contains(resp.Body, []byte(token)) {
		t.Fatalf("the credential survived: %s", resp.Body)
	}
	if !bytes.Contains(resp.Body, []byte(pseudo.PrefixSecret)) {
		t.Fatalf("expected an opaque secret pseudonym, got: %s", resp.Body)
	}
}

// TestPseudonymizeRequest_FilenamesLeftToTerms: with the default
// path.filenames of "terms", an ordinary file name survives the forward
// path while the directories around it are replaced, and a file named after
// a customer loses the customer's name to the term layer and keeps the rest.
func TestPseudonymizeRequest_FilenamesLeftToTerms(t *testing.T) {
	// Paths are joined at run time: a literal path in this source would be
	// pseudonymized in transit and land here in a different form.
	tree := strings.Join([]string{"", "home", "mwendler", "Projekte", "kunde-x"}, "/")
	code := tree + "/" + strings.Join([]string{"src", "main.go"}, "/")
	readme := tree + "/" + "README.md"
	contract := tree + "/" + "kunde-x-vertrag.pdf"
	req := map[string]any{
		"model":    "claude-fable-5-1",
		"messages": []any{map[string]any{"role": "user", "content": "Lies " + code + ", " + readme + " und " + contract + "."}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	// The customer is a term of the list, as it would be in practice; the
	// fixture list does not carry it, so it is added here.
	p := newPseudoPlugin(t, map[string]any{
		"path":  map[string]any{"enabled": true, "replace_unknown": true},
		"terms": []any{map[string]any{"value": "kunde-x", "kind": "path_segment"}},
	})
	resp := beforeAuth(t, p, "req-1", body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	out := string(resp.Body)
	for _, keep := range []string{"/src/" + "main.go", "/" + "README.md", "-vertrag.pdf"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q should survive, body: %s", keep, out)
		}
	}
	for _, gone := range []string{"mwendler", "kunde-x", "Projekte"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q leaked, body: %s", gone, out)
		}
	}
	if strings.Count(out, "-vertrag.pdf") != 1 || strings.Contains(out, "f-") {
		t.Errorf("the customer's file should keep its suffix and get no filename pseudonym, body: %s", out)
	}
}

// TestPseudonymizeRequest_SecondPassIsQuiet: the mapping table belongs to
// the conversation, and the composite excludes what the table knows. A
// second request of the same conversation whose body is the first one's
// output therefore replaces nothing and adds no row: every pseudonym in it
// is one the table produced. The address the fixture composes out of a
// person and a domain pseudonym is a pseudonym of the table as well, since
// the promotion replaces the whole address as one e-mail row.
func TestPseudonymizeRequest_SecondPassIsQuiet(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	first := beforeAuth(t, p, "req-1", body)
	rows := p.tableOf(t, "req-1").Len()
	if rows == 0 {
		t.Fatal("the first pass replaced nothing")
	}
	second := beforeAuth(t, p, "req-2", first.Body)
	if second.Body != nil && !bytes.Equal(first.Body, second.Body) {
		t.Fatalf("the second pass changed the body:\n%s", second.Body)
	}
	if got := p.tableOf(t, "req-2").Len(); got != rows {
		t.Fatalf("the second pass grew the conversation's table from %d to %d rows", rows, got)
	}
}

// TestPseudonymizeRequest_SecondPassIsQuietOverASuffixedPseudonym: a text
// that names the marker range itself, as a note about the plugin does, is
// a network to the pattern layer; the loader refuses it as a term. Its
// pseudonym can only be the network with the collision suffix appended,
// because every attempt masks back onto the range, and in that pseudonym
// the network stands as a prefix with the "#" for a boundary. The first
// pass writes it; a second pass over the output, in the hook after
// authentication or as the next request, used to see the prefix as a
// network and append the suffix once more, five bytes every pass, as the
// log of the 7th of October showed. The pseudonym's span is inert now.
func TestPseudonymizeRequest_SecondPassIsQuietOverASuffixedPseudonym(t *testing.T) {
	const marker = "100.64.0.0/10"
	suffixed := marker + "#1024"
	p := newPseudoPlugin(t, nil)
	_, req := fixtureBody(t, fixtures.SessionA)
	req["messages"] = []any{map[string]any{"role": "user", "content": "The range " + marker + " is the marker range of the pseudonyms."}}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	first := beforeAuth(t, p, "req-1", body)
	if first.Terminate || first.Body == nil {
		t.Fatalf("the first pass did not rewrite: %+v", first)
	}
	table := p.tableOf(t, "req-1")
	if !table.Has(detect.KindCIDR, marker) {
		t.Fatal("the pattern layer did not report the marker range as a network")
	}
	if got := table.Lookup(detect.KindCIDR, marker); got != suffixed {
		t.Fatalf("the marker range got the pseudonym %q, want the range with the collision suffix", got)
	}
	out := string(first.Body)
	if strings.Count(out, suffixed) != 1 || strings.Contains(out, suffixed+"#") {
		t.Fatalf("the first pass wrote the suffixed pseudonym %d times or doubled it:\n%s", strings.Count(out, suffixed), out)
	}
	rows := table.Len()

	if again := afterAuth(t, p, "req-1", first.Body); again.Body != nil {
		t.Fatalf("the second hook changed the body:\n%s", again.Body)
	}
	if next := beforeAuth(t, p, "req-2", first.Body); next.Body != nil && !bytes.Equal(next.Body, first.Body) {
		t.Fatalf("the next request changed the body:\n%s", next.Body)
	}
	if got := table.Len(); got != rows {
		t.Fatalf("the second passes grew the table from %d to %d rows", rows, got)
	}
}

// TestPseudonymizeRequest_TableFollowsTheConversation: two requests of one
// conversation share a table, so a pseudonym the model repeats from an
// earlier turn resolves in a later one; another conversation has a table
// of its own, and a request whose completion arrived leaves the table
// with the conversation.
func TestPseudonymizeRequest_TableFollowsTheConversation(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, "req-1", body)
	first := p.tableOf(t, "req-1")
	host := first.Lookup(detect.KindHost, "athene.lan")
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: "req-1", Outcome: pluginapi.RequestCompletionSucceeded}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.store.Get("req-1"); err == nil {
		t.Fatal("the binding of req-1 survived its completion")
	}

	// The second request carries only the pseudonym, as a history does
	// after the model repeated it.
	_, req := fixtureBody(t, fixtures.SessionA)
	req["messages"] = []any{map[string]any{"role": "user", "content": "prüfe " + host}}
	later, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	beforeAuth(t, p, "req-2", later)
	second := p.tableOf(t, "req-2")
	if second != first {
		t.Fatal("the second request of the conversation got a table of its own")
	}
	answer := []byte(`{"id":"msg_2","type":"message","role":"assistant","content":[{"type":"text","text":"` + host + ` antwortet"}],"model":"claude-fable-5-1"}`)
	restored := interceptResponse(t, p, "req-2", "claude", answer)
	if !strings.Contains(string(restored.Body), "athene.lan") {
		t.Fatalf("the pseudonym of the first request was not restored in the second: %s", restored.Body)
	}

	other, _ := fixtureBody(t, fixtures.SessionB)
	beforeAuth(t, p, "req-3", other)
	if p.tableOf(t, "req-3") == first {
		t.Fatal("another conversation shares the table")
	}
	if p.store.Len() != 2 {
		t.Fatalf("store holds %d tables, want one per conversation", p.store.Len())
	}
}

// TestPseudonymizeRequest_BlocksNonJSON: on_error block terminates with an
// Anthropic-shaped error body.
func TestPseudonymizeRequest_BlocksNonJSON(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	resp := beforeAuth(t, p, "req-1", []byte("not valid json, athene.lan"))

	if !resp.Terminate {
		t.Fatal("expected the request to be terminated")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if got := resp.ResponseHeaders.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type = %q, want application/json", got)
	}
	var errBody apiError
	if err := json.Unmarshal(resp.ResponseBody, &errBody); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if errBody.Type != "error" || errBody.Error.Type != "invalid_request_error" {
		t.Fatalf("unexpected error shape: %+v", errBody)
	}
	if !strings.HasPrefix(errBody.Error.Message, "privacyfilter: ") {
		t.Fatalf("message = %q, want a privacyfilter prefix", errBody.Error.Message)
	}
	if strings.Contains(string(resp.ResponseBody), "athene.lan") {
		t.Fatal("the error body echoes the request body")
	}
	if p.store.Len() != 0 {
		t.Fatalf("a blocked request stored %d tables, want 0", p.store.Len())
	}
}

// TestPseudonymizeRequest_PassthroughNonJSON: on_error passthrough forwards the
// body unfiltered, as the original plugin always did.
func TestPseudonymizeRequest_PassthroughNonJSON(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"on_error": string(OnErrorPassthrough)})
	resp := beforeAuth(t, p, "req-1", []byte("not valid json, athene.lan"))
	if resp.Terminate || resp.Body != nil || resp.ResponseBody != nil {
		t.Fatalf("expected an empty response, got %+v", resp)
	}
}

// TestPseudonymizeRequest_BlocksOversizeBody: a body over the configured limit
// is blocked rather than forwarded unfiltered.
func TestPseudonymizeRequest_BlocksOversizeBody(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{
		"limits": map[string]any{"max_body_bytes": 512, "mapping_ttl": "10m"},
	})
	body, _ := fixtureBody(t, fixtures.SessionA)
	if len(body) <= 512 {
		t.Fatalf("fixture body is only %d bytes, the limit no longer bites", len(body))
	}
	resp := beforeAuth(t, p, "req-1", body)
	if !resp.Terminate || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected a 400 termination, got %+v", resp)
	}
	var errBody apiError
	if err := json.Unmarshal(resp.ResponseBody, &errBody); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	if !strings.Contains(errBody.Error.Message, "size limit") {
		t.Fatalf("message = %q, want the size limit named", errBody.Error.Message)
	}
}

// TestPseudonymizeRequest_SkipFormat: skip_formats still short-circuits before
// anything is touched.
func TestPseudonymizeRequest_SkipFormat(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"skip_formats": []any{"claude"}})
	body, _ := fixtureBody(t, fixtures.SessionA)
	resp := beforeAuth(t, p, "req-1", body)
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("expected a skipped format to pass through, got %+v", resp)
	}
	if p.store.Len() != 0 {
		t.Fatalf("a skipped request stored %d tables, want 0", p.store.Len())
	}
}

// TestPseudonymizeRequest_CallerScopeSeparatesTables: the conversation
// identifier is the client's claim, the caller scope the host's. One
// identifier under two callers gets two tables and two salts, so a response
// of the second caller that carries a pseudonym of the first restores
// nothing; the same identifier under the same caller shares the table as
// before, and a request without a scope keys by the identifier alone.
func TestPseudonymizeRequest_CallerScopeSeparatesTables(t *testing.T) {
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	send := func(requestID, caller string) pluginapi.RequestInterceptResponse {
		t.Helper()
		req := pluginapi.RequestInterceptRequest{
			RequestID:    requestID,
			SourceFormat: "claude",
			Model:        "claude-fable-5-1",
			Headers:      http.Header{},
			Body:         body,
		}
		if caller != "" {
			req.Metadata = map[string]any{pseudo.MetadataCallerScope: caller}
		}
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), req)
		if err != nil {
			t.Fatalf("InterceptRequestBeforeAuth(%s): %v", requestID, err)
		}
		if resp.Terminate || resp.Body == nil {
			t.Fatalf("%s: expected a rewritten body, got %+v", requestID, resp)
		}
		return resp
	}

	a := send("req-a", "scope-a")
	b := send("req-b", "scope-b")
	plain := send("req-plain", "")
	again := send("req-a2", "scope-a")

	if p.store.Len() != 3 {
		t.Fatalf("store holds %d tables, want 3: one per caller and one without a scope", p.store.Len())
	}
	if p.tableOf(t, "req-a") != p.tableOf(t, "req-a2") {
		t.Fatal("one conversation under one caller got two tables")
	}
	if p.tableOf(t, "req-a") == p.tableOf(t, "req-b") || p.tableOf(t, "req-a") == p.tableOf(t, "req-plain") {
		t.Fatal("a table is shared across callers")
	}
	if bytes.Equal(a.Body, b.Body) || bytes.Equal(a.Body, plain.Body) {
		t.Fatal("pseudonyms equal across callers, the salt ignores the scope")
	}
	if !bytes.Equal(a.Body, again.Body) {
		t.Fatal("pseudonyms differ within one caller")
	}

	// A response for caller b that repeats the pseudonyms of caller a:
	// nothing of a's table comes back, while a's own response is restored.
	upstream, pseudonyms := upstreamResponse(t, p.tableOf(t, "req-a"))
	own := interceptResponse(t, p, "req-a", "claude", upstream)
	foreign := interceptResponse(t, p, "req-b", "claude", upstream)
	foreignBody := foreign.Body
	if len(foreignBody) == 0 {
		foreignBody = upstream // no body means the host keeps what the upstream sent
	}
	for kind, original := range responseOriginals {
		if !bytes.Contains(own.Body, []byte(original)) {
			t.Errorf("%s: the caller's own response did not restore %q", kind, original)
		}
		if bytes.Contains(foreignBody, []byte(original)) {
			t.Errorf("%s: a foreign caller's response restored %q", kind, original)
		}
		if !bytes.Contains(foreignBody, []byte(pseudonyms[kind])) {
			t.Errorf("%s: a foreign caller's response lost the pseudonym %q instead of passing it through", kind, pseudonyms[kind])
		}
	}
}

// TestBuildPlugin_MissingSecretFails: registration fails when the secret file
// is absent, so the plugin never silently forwards plain text.
func TestBuildPlugin_MissingSecretFails(t *testing.T) {
	dir := t.TempDir()
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": filepath.Join(dir, pseudo.DefaultSecretFile),
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	plugin, err := buildPlugin(raw, dir, nil)
	assertBlocked(t, plugin, err, "secret")
}

// TestBuildPlugin_ShortSecretFails: a secret below pseudo.MinSecretLen is
// refused at registration.
func TestBuildPlugin_ShortSecretFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pseudo.DefaultSecretFile)
	if err := os.WriteFile(path, []byte("too short\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": path,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	plugin, err := buildPlugin(raw, dir, nil)
	assertBlocked(t, plugin, err, "32")
}

// TestBuildPlugin_InvalidTermKindFails: an unknown kind in terms[] is caught at
// registration, not at the first request.
func TestBuildPlugin_InvalidTermKindFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pseudo.DefaultSecretFile)
	if err := os.WriteFile(path, fixtures.Secret, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": path,
		"terms":            []any{map[string]any{"value": "athene.lan", "kind": "hostname"}},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	plugin, err := buildPlugin(raw, dir, nil)
	assertBlocked(t, plugin, err, "invalid kind")
}

// TestBuildPlugin_TermInThePseudonymRangeIsReplaced: a term whose value
// lies where a kind draws its pseudonyms from, a node address out of the
// carrier-grade NAT range, a network inside it, an address under the marker
// prefix or a token of the host shape, is accepted and replaced like any
// other value. The exclude judges by the conversation's table, not by the
// shape, so nothing takes such a value for the plugin's own output; and the
// table never hands the value out as a pseudonym of something else. The one
// refusal left is a network that covers the whole range: it can only map
// onto itself.
func TestBuildPlugin_TermInThePseudonymRangeIsReplaced(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		kind   string
		refuse bool
	}{
		{"cgnat address", "100.100.1.1", "ipv4", false},
		{"cgnat subnet", "100.100.0.0/16", "cidr", false},
		{"whole cgnat range", "100.64.0.0/10", "cidr", true},
		{"whole marker prefix", "fdff:5046:5346::/48", "cidr", true},
		{"marker ula", "fdff:5046:5346::1", "ipv6", false},
		{"host shaped", "h-0123456789ab", "host", false},
		{"ordinary address", "10.13.7.42", "ipv4", false},
		{"ordinary person", "markus", "person", false},
		// A term equal to a built-in name is not refused: the entry is left
		// out of the list for this plugin, whatever kind the term declares.
		{"built-in person", pseudo.Names[0], "person", false},
		{"built-in given name", strings.Fields(pseudo.Names[0])[0], "person", false},
		{"name as host", pseudo.Names[0], "host", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.refuse {
				dir := t.TempDir()
				path := filepath.Join(dir, pseudo.DefaultSecretFile)
				if err := os.WriteFile(path, fixtures.Secret, 0o600); err != nil {
					t.Fatalf("write secret: %v", err)
				}
				raw, err := yaml.Marshal(map[string]any{
					"mode":             string(ModePseudonymize),
					"salt_secret_path": path,
					"terms":            []any{map[string]any{"value": tc.value, "kind": tc.kind}},
				})
				if err != nil {
					t.Fatalf("marshal config: %v", err)
				}
				plugin, err := buildPlugin(raw, dir, nil)
				assertBlocked(t, plugin, err, "map onto itself")
				return
			}
			p := newPseudoPlugin(t, map[string]any{
				"terms": []any{map[string]any{"value": tc.value, "kind": tc.kind}},
			})
			body := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"wert ` + tc.value + ` ende"}]}`)
			resp := beforeAuth(t, p, "req-1", body)
			if resp.Terminate {
				t.Fatalf("request terminated: %s", resp.ResponseBody)
			}
			if resp.Body == nil || bytes.Contains(resp.Body, []byte(tc.value)) {
				t.Fatalf("the term %q was not replaced: %s", tc.value, resp.Body)
			}
			table := p.tableOf(t, "req-1")
			e, ok := table.Original(tc.value)
			if ok {
				t.Fatalf("the term %q was handed out as the pseudonym of %q", tc.value, e.Original)
			}
		})
	}
}

// TestBuildPlugin_SecretsLayerUnavailable: without the betterleaks build tag,
// secrets.enabled aborts registration instead of pretending to scan.
func TestBuildPlugin_SecretsLayerUnavailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pseudo.DefaultSecretFile)
	if err := os.WriteFile(path, fixtures.Secret, 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	raw, err := yaml.Marshal(map[string]any{
		"mode":             string(ModePseudonymize),
		"salt_secret_path": path,
		"secrets":          map[string]any{"enabled": true},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	plugin, err := buildPlugin(raw, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plugin.Capabilities.ResponseInterceptor != nil {
		// Only a binary built with the betterleaks tag gets here.
		return
	}
	assertBlocked(t, plugin, nil, detect.ErrSecretsUnavailable.Error())
}

// TestRedactMode_Unchanged: the default mode keeps the original behaviour, and
// none of the pseudonymize machinery is built.
func TestRedactMode_Unchanged(t *testing.T) {
	p := newPseudoPlugin(t, map[string]any{"mode": string(ModeRedact)})
	if p.store != nil || p.layers != nil || p.secret != nil || p.deny != nil {
		t.Fatal("redact mode built pseudonymize state")
	}

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`)
	for _, hook := range []struct {
		name string
		call func(context.Context, pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error)
	}{
		{"BeforeAuth", p.InterceptRequestBeforeAuth},
		{"AfterAuth", p.InterceptRequestAfterAuth},
	} {
		resp, err := hook.call(context.Background(), pluginapi.RequestInterceptRequest{
			RequestID: "req-1",
			Model:     "gpt-4",
			Body:      body,
		})
		if err != nil {
			t.Fatalf("%s: %v", hook.name, err)
		}
		if resp.Terminate {
			t.Fatalf("%s: redact mode must never terminate a request", hook.name)
		}
		if !strings.Contains(string(resp.Body), "[EMAIL]") {
			t.Fatalf("%s: expected the redaction placeholder, got: %s", hook.name, resp.Body)
		}
		if strings.Contains(string(resp.Body), "test@example.com") {
			t.Fatalf("%s: the original email survived", hook.name)
		}
	}

	// Invalid JSON stays a pass-through in redact mode, whatever on_error says.
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		Body: []byte("not valid json with email test@example.com"),
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}
	if resp.Terminate || resp.Body != nil {
		t.Fatalf("expected a pass-through, got %+v", resp)
	}
}

// TestPseudonymizeRequest_PatternToggleReachesEveryLayer: with
// patterns.ipv4 switched off, an IPv4 address survives the forward path
// even though the packyme layer would report it on its own. The e-mail
// address in the same text, whose toggle stays on, is still replaced.
func TestPseudonymizeRequest_PatternToggleReachesEveryLayer(t *testing.T) {
	addr := strings.Join([]string{"100", "73", "67", "152"}, ".")
	mail := "sophie" + "@" + "example.org"
	req := map[string]any{
		"model":    "claude-fable-5-1",
		"messages": []any{map[string]any{"role": "user", "content": "Ping " + addr + " and mail " + mail + "."}},
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	p := newPseudoPlugin(t, map[string]any{
		"patterns": map[string]any{
			"ipv4": false, "ipv6": true, "cidr": true,
			"mac": true, "email": true, "iban": true, "url": false,
		},
		"packyme": map[string]any{"enabled": true},
	})
	resp := beforeAuth(t, p, "req-1", body)
	if resp.Terminate {
		t.Fatalf("request terminated: %s", resp.ResponseBody)
	}
	out := string(resp.Body)
	if !strings.Contains(out, addr) {
		t.Errorf("address should survive with ipv4 off, body: %s", out)
	}
	if strings.Contains(out, mail) {
		t.Errorf("e-mail should be replaced with email on, body: %s", out)
	}
}

// The host passes the plugin directory as it stands in its configuration,
// relative to the proxy's working directory. The secret is looked up there,
// and the plugin makes the directory absolute before it does, so the
// refusal of a relative secret path does not fire on the host's own value.
func TestBuildPlugin_RelativePluginDirFromTheHost(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join("plugins", "linux", "amd64")
	dir := filepath.Join(root, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := append(append([]byte{}, fixtures.Secret...), '\n')
	if err := os.WriteFile(filepath.Join(dir, pseudo.DefaultSecretFile), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)

	raw := []byte("mode: pseudonymize\nterms:\n  - {value: zeus.lan, kind: host}\n")
	plug, err := buildPlugin(raw, rel, nil)
	if err != nil {
		t.Fatalf("buildPlugin with the host's relative directory: %v", err)
	}
	p, ok := plug.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok || p == nil {
		t.Fatal("no interceptor returned")
	}
	if !filepath.IsAbs(p.pluginDir) {
		t.Errorf("plugin directory stayed relative: %q", p.pluginDir)
	}
}
