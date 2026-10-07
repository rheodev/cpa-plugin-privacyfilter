package main

// Events that arrive whole: the start of a block with whatever it carries,
// a citation with cited text and document title, the message of an error,
// and an event spread over several data lines. They are restored through
// the deny-listed walk of the whole-response path, nothing held back, and
// what the deny list keeps out on every other path stays out here.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// TestStream_WholeEventsRestored: a citation delta with both its texts, a
// server-side tool result that arrives whole in its block start, a text
// delta over two data lines and the message of an error all come back
// restored; a thinking block start with text stays byte for byte.
func TestStream_WholeEventsRestored(t *testing.T) {
	p, table := pseudonymizedPlugin(t, "req-whole")
	host := table.Lookup(detect.KindHost, "athene.lan")
	ip := table.Lookup(detect.KindIPv4, "10.13.7.42")

	r := newStreamRun(t, p, "req-whole")
	r.feed([]byte(evMessageStart))
	r.feed(sse(payload.EventContentBlockDelta, `{"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"ping `+host+`","document_index":0,"document_title":"Notizen zu `+host+`","start_char_index":0,"end_char_index":5}}}`))
	r.feed(sse(payload.EventContentBlockStart, `{"type":"content_block_start","index":1,"content_block":{"type":"mcp_tool_result","tool_use_id":"`+fixtures.ToolUseID+`","is_error":false,"content":[{"type":"text","text":"`+host+` hat `+ip+`"}]}}`))
	r.feed(evStop(1))
	thinking := sse(payload.EventContentBlockStart, `{"type":"content_block_start","index":2,"content_block":{"type":"thinking","thinking":"ich pinge `+host+`","signature":"sig"}}`)
	r.feed(thinking)
	r.feed(evStop(2))
	r.feed([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":3,\ndata: \"delta\":{\"type\":\"text_delta\",\"text\":\"Hallo " + host + ".\"}}\n\n"))
	r.feed(evStop(3))
	r.feed(sse(payload.EventError, `{"type":"error","error":{"type":"invalid_request_error","message":"`+host+` unknown"}}`))

	texts, _, events := r.delivered()
	if texts[3] != "Hallo athene.lan." {
		t.Errorf("text over two data lines = %q, want it restored", texts[3])
	}
	all := string(bytes.Join(r.out, nil))
	for _, want := range []string{
		`"cited_text":"ping athene.lan"`,
		`"document_title":"Notizen zu athene.lan"`,
		`"text":"athene.lan hat 10.13.7.42"`,
		`"message":"athene.lan unknown"`,
		"\ndata: \"delta\":{\"type\":\"text_delta\",\"text\":\"Hallo athene.lan.\"}}\n",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the client did not receive %q:\n%s", want, all)
		}
	}
	var sawThinking bool
	for _, ev := range events {
		if ev.Type == payload.EventContentBlockStart && ev.Index == 2 {
			sawThinking = true
			if !bytes.Equal(ev.Raw, thinking) {
				t.Errorf("the thinking block start changed:\n%s", ev.Raw)
			}
		}
	}
	if !sawThinking {
		t.Error("the thinking block start is missing from the output")
	}
	outside := strings.Replace(all, string(thinking), "", 1)
	if strings.Contains(outside, host) || strings.Contains(outside, ip) {
		t.Errorf("a pseudonym survived outside the thinking block:\n%s", outside)
	}
}

// TestStream_WholeEventsUntouchedWithoutPseudonyms: whole events that
// carry no pseudonym go out as they came, byte for byte, and are not
// counted as restored.
func TestStream_WholeEventsUntouchedWithoutPseudonyms(t *testing.T) {
	p, _ := pseudonymizedPlugin(t, "req-plain")
	r := newStreamRun(t, p, "req-plain")
	chunks := [][]byte{
		[]byte(evMessageStart),
		sse(payload.EventContentBlockStart, `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"`+fixtures.ToolUseID+`","name":"Bash","input":{}}}`),
		evStop(0),
		evMessageDelta("end_turn", 7),
		evMessageStop(),
	}
	for _, c := range chunks {
		r.feed(c)
	}
	if len(r.out) != len(chunks) {
		t.Fatalf("%d chunks delivered, want %d", len(r.out), len(chunks))
	}
	for i, c := range chunks {
		if !bytes.Equal(r.out[i], c) {
			t.Errorf("chunk %d changed:\n%s\n%s", i, r.out[i], c)
		}
	}
}
