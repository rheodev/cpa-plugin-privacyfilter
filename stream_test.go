package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// Wire forms of the events a stream test feeds, in the shape the upstream
// sends them.
func evStart(index int, blockType string) []byte {
	block := `{"type":"text","text":""}`
	switch blockType {
	case "tool_use":
		block = `{"type":"tool_use","id":"` + fixtures.ToolUseID + `","name":"Bash","input":{}}`
	case "thinking":
		block = `{"type":"thinking","thinking":"","signature":""}`
	}
	return []byte(fmt.Sprintf("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":%d,\"content_block\":%s}\n\n", index, block))
}

func evStop(index int) []byte {
	return []byte(fmt.Sprintf("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":%d}\n\n", index))
}

func evMessageStop() []byte {
	return []byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
}

func evThinking(index int, text string) []byte {
	enc, _ := json.Marshal(text)
	return []byte(fmt.Sprintf("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":%d,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":%s}}\n\n", index, enc))
}

const evMessageStart = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-fable-5-1\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"

// streamRun feeds chunks through the plugin under one RequestID after the
// header-init call and returns what the client would receive.
type streamRun struct {
	t         *testing.T
	p         *privacyFilterPlugin
	requestID string
	index     int
	out       [][]byte
	dropped   int
}

func newStreamRun(t *testing.T, p *privacyFilterPlugin, requestID string) *streamRun {
	t.Helper()
	r := &streamRun{t: t, p: p, requestID: requestID}
	r.call(nil, pluginapi.StreamChunkHeaderInitIndex)
	return r
}

func (r *streamRun) call(body []byte, index int) pluginapi.StreamChunkInterceptResponse {
	r.t.Helper()
	resp, err := r.p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
		RequestID:    r.requestID,
		SourceFormat: "claude",
		Model:        "claude-fable-5-1",
		Body:         body,
		ChunkIndex:   index,
	})
	if err != nil {
		r.t.Fatalf("InterceptStreamChunk: %v", err)
	}
	return resp
}

// feed sends one chunk and records the delivered bytes the way the host
// does: the returned body when non-empty, the chunk itself otherwise, and
// nothing when DropChunk is set.
func (r *streamRun) feed(chunk []byte) {
	r.t.Helper()
	resp := r.call(chunk, r.index)
	r.index++
	if resp.DropChunk {
		r.dropped++
		return
	}
	if len(resp.Body) > 0 {
		r.out = append(r.out, resp.Body)
		return
	}
	r.out = append(r.out, chunk)
}

// delivered parses everything the client received and returns the
// concatenated text per block index, the concatenated partial_json per
// block index and the events in order.
func (r *streamRun) delivered() (texts map[int]string, partials map[int]string, events []payload.Event) {
	r.t.Helper()
	texts, partials = map[int]string{}, map[int]string{}
	for _, chunk := range r.out {
		evs, err := payload.ParseEvents(chunk)
		if err != nil {
			r.t.Fatalf("delivered chunk does not parse: %v\n%s", err, chunk)
		}
		for _, ev := range evs {
			events = append(events, ev)
			field, ok := payload.ReplaceableText(ev)
			if !ok {
				continue
			}
			text, err := payload.GetText(ev, field)
			if err != nil {
				r.t.Fatalf("GetText: %v", err)
			}
			if field.Escaped {
				partials[ev.Index] += text
			} else {
				texts[ev.Index] += text
			}
		}
	}
	return texts, partials, events
}

// pseudonymizedPlugin builds the plugin, runs the fixture request through
// the forward pass under requestID and returns the plugin and its table.
func pseudonymizedPlugin(t *testing.T, requestID string) (*privacyFilterPlugin, *mapping.Table) {
	t.Helper()
	p := newPseudoPlugin(t, nil)
	body, _ := fixtureBody(t, fixtures.SessionA)
	beforeAuth(t, p, requestID, body)
	table, err := p.store.Get(requestID)
	if err != nil {
		t.Fatal(err)
	}
	return p, table
}

// runeSplits returns every byte offset of text that begins a rune, except 0
// and len(text). The upstream never splits inside a rune.
func runeSplits(text string) []int {
	var out []int
	for i := 1; i < len(text); i++ {
		if utf8.RuneStart(text[i]) {
			out = append(out, i)
		}
	}
	return out
}

// TestStream_SplitAtEveryPosition is the central test of the stream: a
// text block with pseudonyms is delivered as two deltas cut at every rune
// boundary, and the client must always receive exactly the text the
// non-streaming path would produce.
func TestStream_SplitAtEveryPosition(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-split")
	host := table.Lookup(detect.KindHost, "athene.lan")
	ip := table.Lookup(detect.KindIPv4, "10.13.7.42")
	person := table.Lookup(detect.KindPerson, "markus")
	text := "Ich pinge " + host + " (" + ip + ") für " + person + ", dann ssh " + host + " über Zürich."
	want, _ := table.Restorer().Restore(text, false)
	if want == text || strings.Contains(want, host) || strings.Contains(want, ip) {
		t.Fatalf("reference restore failed: %q", want)
	}

	for _, cut := range runeSplits(text) {
		r := newStreamRun(t, p, "req-split")
		r.feed(evStart(0, "text"))
		r.feed(payload.SyntheticDelta(0, payload.DeltaText, text[:cut]))
		r.feed(payload.SyntheticDelta(0, payload.DeltaText, text[cut:]))
		r.feed(evStop(0))
		r.feed(evMessageStop())
		texts, _, events := r.delivered()
		if texts[0] != want {
			t.Fatalf("cut at %d: got %q, want %q", cut, texts[0], want)
		}
		// The stop events keep their place: nothing textual follows them.
		last := events[len(events)-1]
		if last.Type != payload.EventMessageStop || events[len(events)-2].Type != payload.EventContentBlockStop {
			t.Fatalf("cut at %d: stop events out of order: %+v", cut, events)
		}
	}
}

// TestStream_ThreeWaySplitsAndDrop: a pseudonym spread over three deltas,
// the middle one entirely inside the pseudonym, is restored, and the middle
// chunk is dropped because nothing of it can be delivered yet.
func TestStream_ThreeWaySplitsAndDrop(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-three")
	host := table.Lookup(detect.KindHost, "athene.lan")
	text := "ping " + host + " jetzt"
	want, _ := table.Restorer().Restore(text, false)
	start := strings.Index(text, host)
	a, b, c := text[:start+2], text[start+2:start+6], text[start+6:]

	r := newStreamRun(t, p, "req-three")
	r.feed(evStart(0, "text"))
	r.feed(payload.SyntheticDelta(0, payload.DeltaText, a))
	r.feed(payload.SyntheticDelta(0, payload.DeltaText, b))
	r.feed(payload.SyntheticDelta(0, payload.DeltaText, c))
	r.feed(evStop(0))
	texts, _, _ := r.delivered()
	if texts[0] != want {
		t.Fatalf("got %q, want %q", texts[0], want)
	}
	if r.dropped == 0 {
		t.Fatal("a delta that lies entirely inside a pseudonym must be dropped")
	}
}

// TestStream_ToolInputEscaped: tool arguments arrive as JSON fragments; the
// pseudonyms inside are restored in JSON-escaped form so the assembled
// input stays valid JSON, and the holdback works across fragment cuts.
func TestStream_ToolInputEscaped(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-json")
	host := table.Lookup(detect.KindHost, "athene.lan")
	person := table.Lookup(detect.KindPerson, "markus")
	input := `{"command": "ssh ` + host + ` && echo \"` + person + `\"", "count": 1}`
	if !json.Valid([]byte(input)) {
		t.Fatal("test input is not valid JSON")
	}

	for _, cut := range runeSplits(input) {
		r := newStreamRun(t, p, "req-json")
		r.feed(evStart(1, "tool_use"))
		r.feed(payload.SyntheticDelta(1, payload.DeltaInputJSON, input[:cut]))
		r.feed(payload.SyntheticDelta(1, payload.DeltaInputJSON, input[cut:]))
		r.feed(evStop(1))
		_, partials, _ := r.delivered()
		var parsed struct {
			Command string `json:"command"`
			Count   int    `json:"count"`
		}
		if err := json.Unmarshal([]byte(partials[1]), &parsed); err != nil {
			t.Fatalf("cut at %d: assembled input is not JSON: %v\n%s", cut, err, partials[1])
		}
		if parsed.Command != `ssh athene.lan && echo "markus"` || parsed.Count != 1 {
			t.Fatalf("cut at %d: command = %q", cut, parsed.Command)
		}
	}
}

// TestStream_EscapedOriginal: an original with characters that need JSON
// escaping goes back into a partial_json fragment in escaped form.
func TestStream_EscapedOriginal(t *testing.T) {
	table := mapping.NewTable(genFunc(func(kind detect.Kind, value string, _ int) string {
		return "PF-" + string(kind) + "-x"
	}))
	pseudo := table.Lookup(detect.KindPerson, `Ingrid "Bobby" Müster\`)
	st := &streamState{restorer: table.Restorer(), holds: map[int]*blockHold{}}
	fragment := `{"who": "` + pseudo + `"}`
	out, drop, err := st.chunk(payload.SyntheticDelta(0, payload.DeltaInputJSON, fragment))
	if err != nil || drop {
		t.Fatalf("chunk = drop %v, err %v", drop, err)
	}
	flushed, _, err := st.chunk(evStop(0))
	if err != nil {
		t.Fatal(err)
	}
	var assembled string
	for _, raw := range [][]byte{out, flushed} {
		evs, _ := payload.ParseEvents(raw)
		for _, ev := range evs {
			if f, ok := payload.ReplaceableText(ev); ok {
				s, _ := payload.GetText(ev, f)
				assembled += s
			}
		}
	}
	var parsed struct {
		Who string `json:"who"`
	}
	if err := json.Unmarshal([]byte(assembled), &parsed); err != nil || parsed.Who != `Ingrid "Bobby" Müster\` {
		t.Fatalf("assembled = %s, parsed %q, err %v", assembled, parsed.Who, err)
	}
}

// genFunc adapts a function to mapping.Generator.
type genFunc func(kind detect.Kind, value string, attempt int) string

func (f genFunc) Pseudonym(kind detect.Kind, value string, attempt int) string {
	return f(kind, value, attempt)
}

// TestStream_UntouchedAndPassThrough: thinking deltas, pings and events of
// other blocks are delivered byte for byte, a chunk with several events is
// handled event by event, and text without pseudonyms is not rewritten.
func TestStream_UntouchedAndPassThrough(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-mixed")
	host := table.Lookup(detect.KindHost, "athene.lan")

	r := newStreamRun(t, p, "req-mixed")
	r.feed([]byte(evMessageStart))
	r.feed(evStart(0, "thinking"))
	thinking := evThinking(0, "ich pinge "+host)
	r.feed(thinking)
	r.feed(evStop(0))
	combined := append(append([]byte{}, evStart(1, "text")...), payload.SyntheticDelta(1, payload.DeltaText, "Hallo "+host)...)
	r.feed(combined)
	r.feed([]byte("event: ping\ndata: {\"type\": \"ping\"}\n\n"))
	clean := payload.SyntheticDelta(1, payload.DeltaText, " nichts weiter")
	r.feed(clean)
	r.feed(evStop(1))
	r.feed(evMessageStop())

	texts, _, events := r.delivered()
	if texts[1] != "Hallo athene.lan nichts weiter" {
		t.Fatalf("text = %q", texts[1])
	}
	var sawThinking, sawPing bool
	for i, ev := range events {
		switch {
		case ev.DeltaType == payload.DeltaThinking:
			sawThinking = true
			if string(ev.Raw) != string(thinking) {
				t.Fatalf("thinking delta changed: %s", ev.Raw)
			}
		case ev.Type == payload.EventPing:
			sawPing = true
		case ev.Type == payload.EventMessageStart:
			if i != 0 || string(ev.Raw) != evMessageStart {
				t.Fatalf("message_start changed or moved: %s", ev.Raw)
			}
		}
	}
	if !sawThinking || !sawPing {
		t.Fatal("thinking delta or ping missing from the output")
	}
	// The delta in front ended right behind a pseudonym, so the pseudonym
	// waited for the next byte and comes out, restored, in front of the
	// clean delta's text; the clean delta is therefore rewritten. The one
	// before it, "Hallo " with the pseudonym held, went out shortened.
	last := r.out[len(r.out)-3]
	if string(last) == string(clean) {
		t.Fatalf("the clean delta went out untouched although the pseudonym in front of it was still held: %s", last)
	}
	evs, err := payload.ParseEvents(last)
	if err != nil || len(evs) != 1 {
		t.Fatalf("ParseEvents: %v (%d events)", err, len(evs))
	}
	if got, _ := payload.GetText(evs[0], payload.TextField{Path: payload.Path{"delta", "text"}}); got != "athene.lan nichts weiter" {
		t.Fatalf("the clean delta carries %q, want the restored pseudonym in front of its own text", got)
	}
}

// TestStream_MessageStopFlushesAllBlocks: a block that ends without its own
// stop event still gets its holdback before message_stop.
func TestStream_MessageStopFlushesAllBlocks(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-nostop")
	host := table.Lookup(detect.KindHost, "athene.lan")
	r := newStreamRun(t, p, "req-nostop")
	r.feed(payload.SyntheticDelta(0, payload.DeltaText, "a "+host[:5]))
	r.feed(payload.SyntheticDelta(2, payload.DeltaText, "b "+host))
	r.feed(evMessageStop())
	texts, _, events := r.delivered()
	if texts[0] != "a "+host[:5] || texts[2] != "b athene.lan" {
		t.Fatalf("texts = %v", texts)
	}
	if events[len(events)-1].Type != payload.EventMessageStop {
		t.Fatal("message_stop must come last")
	}
}

// TestStream_HeaderInitResetsState: the host repeats the header-init call
// when it retries the upstream; the holdback of the first attempt is gone.
func TestStream_HeaderInitResetsState(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-retry")
	host := table.Lookup(detect.KindHost, "athene.lan")
	r := newStreamRun(t, p, "req-retry")
	r.feed(payload.SyntheticDelta(0, payload.DeltaText, "x "+host[:4]))
	r.call(nil, pluginapi.StreamChunkHeaderInitIndex)
	r.index, r.out, r.dropped = 0, nil, 0
	r.feed(payload.SyntheticDelta(0, payload.DeltaText, "neu "+host))
	r.feed(evStop(0))
	texts, _, _ := r.delivered()
	if texts[0] != "neu athene.lan" {
		t.Fatalf("text after retry = %q", texts[0])
	}
}

// TestStream_PassThroughCases: no table, other format, empty body and
// malformed data pass through without an error.
func TestStream_PassThroughCases(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-ok")
	host := table.Lookup(detect.KindHost, "athene.lan")
	delta := payload.SyntheticDelta(0, payload.DeltaText, host)
	cases := map[string]pluginapi.StreamChunkInterceptRequest{
		"no table":     {RequestID: "req-unknown", SourceFormat: "claude", Body: delta, ChunkIndex: 0},
		"empty id":     {RequestID: "", SourceFormat: "claude", Body: delta, ChunkIndex: 0},
		"other format": {RequestID: "req-ok", SourceFormat: "openai", Body: delta, ChunkIndex: 0},
		"empty body":   {RequestID: "req-ok", SourceFormat: "claude", Body: nil, ChunkIndex: 0},
		"bad data":     {RequestID: "req-ok", SourceFormat: "claude", Body: []byte("data: {not json\n\n"), ChunkIndex: 0},
	}
	for name, req := range cases {
		hdr := req
		hdr.Body, hdr.ChunkIndex = nil, pluginapi.StreamChunkHeaderInitIndex
		if _, err := p.InterceptStreamChunk(context.Background(), hdr); err != nil {
			t.Errorf("%s: header-init returned %v", name, err)
		}
		resp, err := p.InterceptStreamChunk(context.Background(), req)
		if err != nil || len(resp.Body) != 0 || resp.DropChunk {
			t.Errorf("%s: expected pass-through, got body %d bytes, drop %v, err %v", name, len(resp.Body), resp.DropChunk, err)
		}
	}
	// Without a header-init call the state is built from the table on the
	// first chunk, so a stream that began with restore.stream off and meets
	// an instance with it on still restores. The instances share the store.
	fresh := newPseudoPlugin(t, nil)
	fresh.store, fresh.rt = p.store, p.rt
	resp, err := fresh.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{RequestID: "req-ok", SourceFormat: "claude", Body: payload.SyntheticDelta(0, payload.DeltaText, host+" "), ChunkIndex: 3})
	if err != nil || !strings.Contains(string(resp.Body), "athene.lan") {
		t.Fatalf("mid-stream state not rebuilt: %s, %v", resp.Body, err)
	}
}

// TestStream_CapabilityAndRelease: restore.stream decides whether the stream
// interceptor is announced, the ABI routes the method, and the completion
// event releases the stream state.
func TestStream_CapabilityAndRelease(t *testing.T) {
	off := newPseudoPlugin(t, map[string]any{"restore": map[string]any{"stream": false}})
	if capabilitiesFor(off).StreamChunkInterceptor != nil || off.streams != nil {
		t.Fatal("restore.stream=false must not announce the stream interceptor")
	}
	if resp, err := off.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{RequestID: "x", SourceFormat: "claude", Body: []byte("data: {}\n\n")}); err != nil || len(resp.Body) != 0 {
		t.Fatalf("stream call with restore.stream=false = %+v, %v", resp, err)
	}

	p, table := pseudonymizedPlugin(t, "req-abi-stream")
	if capabilitiesFor(p).StreamChunkInterceptor == nil {
		t.Fatal("pseudonymize mode must announce the stream interceptor")
	}
	installABIPlugin(t, p)
	host := table.Lookup(detect.KindHost, "athene.lan")
	for _, req := range []pluginapi.StreamChunkInterceptRequest{
		{RequestID: "req-abi-stream", SourceFormat: "claude", ChunkIndex: pluginapi.StreamChunkHeaderInitIndex},
		{RequestID: "req-abi-stream", SourceFormat: "claude", ChunkIndex: 0, Body: payload.SyntheticDelta(0, payload.DeltaText, "via "+host+" ok")},
	} {
		raw, err := handlePrivacyFilterABIMethod(context.Background(), "response.intercept_stream_chunk", mustJSON(t, req))
		if err != nil {
			t.Fatalf("dispatch: %v", err)
		}
		var env abiEnvelope
		if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
			t.Fatalf("envelope = %s, err %v", raw, err)
		}
		if req.ChunkIndex >= 0 {
			var resp pluginapi.StreamChunkInterceptResponse
			if err := json.Unmarshal(env.Result, &resp); err != nil || !strings.Contains(string(resp.Body), "via athene.lan ok") {
				t.Fatalf("ABI stream body = %s, err %v", resp.Body, err)
			}
		}
	}
	if p.streams.get("req-abi-stream") == nil {
		t.Fatal("stream state missing before completion")
	}
	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: "req-abi-stream", Stream: true, Outcome: pluginapi.RequestCompletionSucceeded}); err != nil {
		t.Fatal(err)
	}
	if p.streams.get("req-abi-stream") != nil {
		t.Fatal("stream state not released on completion")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
