package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"

	"privacyfilter/filter"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type privacyFilterPlugin struct {
	cfg       privacyFilterConfig
	pluginDir string
	filter    *filter.Filter

	// blocked is the error that stopped the set-up of ModePseudonymize: a
	// missing secret, an unreadable term list, a refused term. The plugin
	// registers all the same and answers every request with this error
	// until the configuration is fixed and the proxy restarted. A failed
	// registration would leave the host running without the filter, and
	// the only trace would be one line in its log.
	blocked error

	// The fields below are built once at registration and only in
	// ModePseudonymize; in ModeRedact they stay nil and nothing outside
	// interceptRequest and redactRequestBody ever runs, so that mode keeps
	// behaving exactly as the original plugin does.
	//
	// secret is the HMAC key from pseudonym.secret. layers are the detection
	// layers in order of precedence; the Composite around them is per request
	// because its Exclude is bound to that request's generator. deny is the
	// read-only deny list handed to every payload.Walk. store keeps the
	// mapping tables the return path will need, keyed by RequestID; it is
	// rt.store, shared with every other instance of this library.
	secret []byte
	// renderers is the renderer map of every generator of this plugin: the
	// defaults, with the built-in person names that equal a term left out.
	renderers map[detect.Kind]pseudo.Renderer
	// networks are the cidr terms of the list, parsed; every generator of
	// this plugin keeps their structure, see pseudo.Generator.WithNetworks.
	networks []netip.Prefix
	// terms is the term layer alone, the first of layers; the forward pass
	// asks it whether a value the model wrote carries a term inside, see
	// authorship.
	terms  detect.Detector
	layers []detect.Detector
	deny   *payload.DenyList
	store  *mapping.Store
	// streams holds the holdback state of every open streamed response; it
	// is rt.streams, or nil when restore.stream is off.
	streams *streams
	// rt is the process-wide state this instance joined at buildPlugin; see
	// runtimeState in main.go. Set in every mode, used only in pseudonymize.
	rt *runtimeState
	// audit is the clear-text record of tables and restores, nil unless
	// audit.path is set; see audit.go.
	audit *auditLog
	// termCount is the size of the merged term list, for the registration log.
	termCount int
	// termLiterals are the literal values of the term list. No pseudonym
	// of a conversation may equal one of them, see mapping.Table.SetAvoid.
	termLiterals map[string]bool
}

// isTermLiteral reports whether s is a literal of the term list.
func (p *privacyFilterPlugin) isTermLiteral(s string) bool {
	return p.termLiterals[s]
}

var _ pluginapi.RequestInterceptor = (*privacyFilterPlugin)(nil)

// errForwardPanic marks a recovered panic from the detection or walk step, so
// forwardReason can turn it into a message that carries no request content.
var errForwardPanic = errors.New("privacyfilter: recovered panic on the forward path")

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	if p.blocked != nil {
		return p.blockedResponse(), nil
	}
	if p.cfg.IsPseudonymize() {
		return p.pseudonymizeRequest(req), nil
	}
	return p.interceptRequest(ctx, req)
}

// blockedResponse terminates a request with the error that stopped the
// set-up, in the same Anthropic-shaped body as forwardFailure, so the client
// shows it to the user at the first request. Skip lists do not apply: a
// plugin that could not be set up filters nothing, so nothing may pass. The
// message names files, lines and classes, never a value of the term list.
func (p *privacyFilterPlugin) blockedResponse() pluginapi.RequestInterceptResponse {
	log.Warnf("privacyfilter: blocking the request, the plugin is not set up: %v", p.blocked)
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	reason := "not set up, every request is blocked until the configuration is fixed and the proxy restarted: " +
		strings.TrimPrefix(p.blocked.Error(), "privacyfilter: ")
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusBadRequest,
		ResponseHeaders: headers,
		ResponseBody:    errorBody(reason),
	}
}

// InterceptRequestAfterAuth filters a second time in ModeRedact, as the
// original plugin does, because the host may have rewritten the body between
// the two hooks. In ModePseudonymize it returns an empty response: the body was
// already walked in InterceptRequestBeforeAuth, and a second pass would build a
// second mapping table under the same RequestID and count every replacement
// twice.
func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	if p.blocked != nil {
		return p.blockedResponse(), nil
	}
	if p.cfg.IsPseudonymize() {
		return p.pseudonymizeAgain(req), nil
	}
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

// forwardResult carries what one forward pass produced: the new body, whether
// anything changed, the mapping table the return path will need, which
// identifier the salt came from, and how many replacements happened per kind.
type forwardResult struct {
	out     []byte
	changed bool
	// table is the conversation's table, with the rows of this request
	// added; added are the rows this request put in, for the audit log.
	table   *mapping.Table
	added   []mapping.Entry
	session pseudo.Session
	counts  map[detect.Kind]int
	// kept counts, per kind, the detected values left standing because
	// the model wrote them first; see authorship.
	kept map[detect.Kind]int
}

// pseudonymizeRequest is the forward pass of ModePseudonymize: identify the
// conversation, derive its salt, walk every string the deny list allows,
// replace every detected value by its pseudonym and keep the mapping table for
// the return path. It is composed exactly as internal/leaktest wires the four
// packages together.
func (p *privacyFilterPlugin) pseudonymizeRequest(req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	resp := pluginapi.RequestInterceptResponse{}

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp
	}

	body := req.Body
	if len(body) == 0 {
		return resp
	}

	res, err := p.runForward(req.Headers, req.Metadata, body)
	if err != nil {
		// A table opened for this request alone is dropped again, so a
		// blocked request leaves nothing behind; a table the conversation
		// already had stays.
		p.store.Discard(res.table)
		return p.forwardFailure(err)
	}

	if res.changed {
		resp.Body = res.out
	}
	// The request is bound to its conversation's table even when nothing
	// was replaced, so the return path finds the table instead of none and
	// restores what the model repeats from earlier turns. An empty
	// RequestID cannot be correlated with a response, and two requests
	// would share the key, so that case is skipped.
	if req.RequestID != "" {
		p.store.Bind(req.RequestID, res.table)
	}
	p.audit.request(req.RequestID, res, req.SourceFormat, len(body))

	log.WithFields(log.Fields{
		"source_format":  req.SourceFormat,
		"session_source": string(res.session.Source),
		"caller_scoped":  res.session.Caller != "",
		"replacements":   formatCounts(res.counts),
		"kept":           formatCounts(res.kept),
		"distinct":       len(res.added),
		"body_bytes":     len(body),
		"out_bytes":      len(res.out),
	}).Info("privacyfilter: request pseudonymized")

	return resp
}

// pseudonymizeAgain is the forward pass in the hook after authentication.
// The body it sees is the first pass's output plus whatever the host or a
// plugin between the two hooks added, so it is walked once more, over the
// table the first pass bound to the request: that table excludes its own
// pseudonyms, so the text already rewritten stays byte for byte, and a value
// that came in between gets the pseudonym the first pass would have given
// it, same salt, same rows, and the return path finds it in the same table.
// A request the store does not know, an empty RequestID or a table that was
// dropped in between, gets the full pass, which identifies the conversation
// again and binds the request.
func (p *privacyFilterPlugin) pseudonymizeAgain(req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	resp := pluginapi.RequestInterceptResponse{}

	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp
	}
	body := req.Body
	if len(body) == 0 {
		return resp
	}
	table, errGet := p.store.Get(req.RequestID)
	if errGet != nil {
		return p.pseudonymizeRequest(req)
	}

	res, err := p.runForwardBound(table, body)
	if err != nil {
		// The table has the rows and the binding of the first pass; there
		// is nothing of this pass to drop.
		return p.forwardFailure(err)
	}
	if !res.changed {
		return resp
	}
	resp.Body = res.out
	p.audit.request(req.RequestID, res, req.SourceFormat, len(body))

	log.WithFields(log.Fields{
		"source_format":  req.SourceFormat,
		"session_source": string(res.session.Source),
		"replacements":   formatCounts(res.counts),
		"kept":           formatCounts(res.kept),
		"distinct":       len(res.added),
		"body_bytes":     len(body),
		"out_bytes":      len(res.out),
	}).Info("privacyfilter: request pseudonymized after auth")

	return resp
}

// runForward is the forward pass of a request the store does not know yet:
// it identifies the conversation, opens its table and runs the detection and
// replacement over it. It never returns an error that carries request
// content, and it turns a panic in a detection layer into an ordinary error
// so on_error decides what happens instead of the host crashing.
func (p *privacyFilterPlugin) runForward(headers http.Header, metadata map[string]any, body []byte) (res forwardResult, err error) {
	defer recoverInto(&err, errForwardPanic)

	// The conversation identifier comes from the client, the caller scope
	// from the host; salt and table are keyed by both, so an identifier
	// another caller sends reaches a table of its own, see pseudo.Session.Key.
	session := pseudo.IdentifySession(headers, body)
	session.Caller = pseudo.CallerScope(metadata)
	key := session.Key()
	gen, err := p.generator(key)
	if err != nil {
		return res, err
	}
	// The table belongs to the conversation and outlives the request: the
	// values of earlier turns are already in it, and the values of this one
	// are added.
	return p.forward(session, key, p.store.Open(key, gen), gen, body)
}

// runForwardBound is the forward pass over a table an earlier pass of the
// same request bound: the second hook of a request, see pseudonymizeAgain.
// The key is the one the table was opened under, so salt and memory are
// the first pass's; the identifier is not read again, and the result names
// the table as the source of the session.
func (p *privacyFilterPlugin) runForwardBound(table *mapping.Table, body []byte) (res forwardResult, err error) {
	defer recoverInto(&err, errForwardPanic)

	key := table.Session()
	gen, err := p.generator(key)
	if err != nil {
		return res, err
	}
	return p.forward(pseudo.Session{Source: pseudo.SourceBound}, key, table, gen, body)
}

// generator builds the pseudonym generator of the conversation key, the
// salt derived from the secret and the key.
func (p *privacyFilterPlugin) generator(key string) (*pseudo.Generator, error) {
	gen := pseudo.NewGenerator(p.secret, pseudo.DeriveSalt(p.secret, key), p.renderers).WithNetworks(p.networks)
	if gen == nil {
		return nil, errors.New("privacyfilter: pseudonym generator unavailable")
	}
	return gen, nil
}

// forward performs detection and replacement over body with the table of
// the conversation key. The exclude is the table itself, not the shape of
// a pseudonym, so a value the plugin produced is left alone and a real
// value that merely looks like one, a node address out of the
// carrier-grade NAT range, is replaced.
func (p *privacyFilterPlugin) forward(session pseudo.Session, key string, table *mapping.Table, gen *pseudo.Generator, body []byte) (res forwardResult, err error) {
	res.session = session
	table.SetAvoid(p.isTermLiteral)
	det := detect.NewComposite(table.Knows, p.layers...)
	counts := make(map[detect.Kind]int)
	kept := make(map[detect.Kind]int)
	res.table = table
	res.counts = counts
	res.kept = kept

	opts := payload.WalkOptions{
		MaxBodyBytes: p.cfg.Limits.MaxBodyBytes,
		Deny:         p.deny,
	}
	// The reading pass detects every string once and notes, in the order
	// of the conversation, which values the model wrote before anybody
	// else did; the rewriting pass below uses its matches and leaves those
	// values standing. See authorship.
	auth := newAuthorship(gen, p.store.Memory(key), table, p.terms, p.networks, payload.Roles(body))
	if _, _, errRead := payload.Walk(body, opts, func(path payload.Path, text string) (string, bool) {
		auth.observe(det, path, text)
		return text, false
	}); errRead != nil {
		return res, errRead
	}
	auth.decide()

	out, changed, errWalk := payload.Walk(body, opts, func(_ payload.Path, text string) (string, bool) {
		matches := auth.matches(det, text)
		if len(matches) == 0 {
			return text, false
		}
		var b strings.Builder
		b.Grow(len(text))
		prev, replaced := 0, 0
		for _, m := range matches {
			// Merge guarantees a sorted, disjoint list; the check only keeps a
			// broken layer from slicing out of range.
			if m.Start < prev || m.End > len(text) || m.End < m.Start {
				continue
			}
			if auth.exempt(m) {
				// The value stays; it is written with the text around it.
				kept[m.Kind]++
				continue
			}
			b.WriteString(text[prev:m.Start])
			before := table.Len()
			pseudonym := table.Lookup(m.Kind, m.Value)
			if table.Len() > before {
				auth.seen(m)
				if e, ok := table.Original(pseudonym); ok {
					res.added = append(res.added, e)
				}
			}
			b.WriteString(pseudonym)
			prev = m.End
			counts[m.Kind]++
			replaced++
		}
		if replaced == 0 {
			return text, false
		}
		b.WriteString(text[prev:])
		return b.String(), true
	})
	if errWalk != nil {
		return res, errWalk
	}

	res.out = out
	res.changed = changed
	return res, nil
}

// forwardFailure applies the on_error setting. With block the request is
// terminated with an Anthropic-shaped error body, with passthrough it goes on
// unfiltered, as the original plugin always did.
func (p *privacyFilterPlugin) forwardFailure(err error) pluginapi.RequestInterceptResponse {
	if p.cfg.OnError == OnErrorPassthrough {
		log.Warnf("privacyfilter: %v, forwarding the request unfiltered (on_error=passthrough)", err)
		return pluginapi.RequestInterceptResponse{}
	}

	log.Warnf("privacyfilter: %v, blocking the request (on_error=block)", err)
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	return pluginapi.RequestInterceptResponse{
		Terminate:       true,
		StatusCode:      http.StatusBadRequest,
		ResponseHeaders: headers,
		ResponseBody:    errorBody(forwardReason(err)),
	}
}

// forwardReason maps an error to a short message for the client. It is
// deliberately coarse: the message reaches the caller, so it names the class of
// failure and never a value, a path or a byte of the body.
func forwardReason(err error) string {
	switch {
	case errors.Is(err, payload.ErrNotJSON):
		return "request body is not a JSON object"
	case errors.Is(err, payload.ErrBodyTooLarge):
		return "request body exceeds the configured size limit"
	case errors.Is(err, errForwardPanic):
		return "internal error while filtering the request"
	default:
		return "failed to filter the request"
	}
}

// apiErrorDetail and apiError render the error shape of the Anthropic Messages
// API, so a terminated request looks to the client like a rejection by the
// upstream rather than a broken proxy.
type apiErrorDetail struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type apiError struct {
	Type  string         `json:"type"`
	Error apiErrorDetail `json:"error"`
}

func errorBody(reason string) []byte {
	out, err := json.Marshal(apiError{
		Type:  "error",
		Error: apiErrorDetail{Type: "invalid_request_error", Message: "privacyfilter: " + reason},
	})
	if err != nil {
		return []byte(`{"type":"error","error":{"type":"invalid_request_error","message":"privacyfilter: failed to filter the request"}}`)
	}
	return out
}

// formatCounts renders the per-kind replacement counts in a fixed order, so two
// identical requests produce an identical log line.
// sumCounts returns the total over the kinds.
func sumCounts(counts map[detect.Kind]int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

func formatCounts(counts map[detect.Kind]int) string {
	if len(counts) == 0 {
		return "none"
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, string(k))
	}
	sort.Strings(kinds)
	var b strings.Builder
	for i, k := range kinds {
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d", k, counts[detect.Kind(k)])
	}
	return b.String()
}
