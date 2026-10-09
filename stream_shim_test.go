package main

// What the probes of the streamed return path need besides stream.go itself:
// a constructor, two observers and the builders of the wire events. The
// probes come from the external test lab, where package main could not be
// imported and the state machine had to be rebuilt out of its pieces; here
// they run against the real streamState, so the rebuild is gone and with it
// the question whether it drifted from the original.
//
// What they measure is the event sequence from message_start to
// message_stop, the per-block holdback, and what becomes of text that is
// still held when a block or the whole stream ends.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// state is the name the probes use for the return-path state of stream.go.
type state = streamState

func newState(tab *mapping.Table) *state {
	return &state{restorer: tab.Restorer(), holds: make(map[int]*blockHold)}
}

// pending reports the blocks that still hold text and the held text itself,
// the way streams.finish counts it before it warns about a stream that ended
// without a stop event.
func (st *state) pending() (blocks int, text string) {
	idx := make([]int, 0, len(st.holds))
	for i := range st.holds {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	var b strings.Builder
	for _, i := range idx {
		if st.holds[i].text() == "" {
			continue
		}
		blocks++
		b.WriteString(st.holds[i].text())
	}
	return blocks, b.String()
}

// deliver runs one chunk through the state the way the host acts on the
// InterceptStreamChunk response: an error passes the chunk through as it
// came, DropChunk delivers nothing, and a nil body means no byte changed.
func (st *state) deliver(chunk []byte) []byte {
	out, drop, err := st.chunk(chunk)
	if err != nil {
		return chunk
	}
	if drop {
		return nil
	}
	if out == nil {
		return chunk
	}
	return out
}

// client assembles what the user's tool sees: the text of every content
// block and the sequence of event types in arrival order.
type client struct {
	t     *testing.T
	text  map[int]*strings.Builder
	types []string
	// parseErrors counts chunks the client could not parse at all.
	parseErrors int
}

func newClient(t *testing.T) *client {
	t.Helper()
	return &client{t: t, text: make(map[int]*strings.Builder)}
}

// feed takes what the host would write to the socket for one chunk.
func (c *client) feed(b []byte) {
	c.t.Helper()
	if len(b) == 0 {
		return
	}
	evs, err := payload.ParseEvents(b)
	if err != nil {
		c.parseErrors++
	}
	for _, ev := range evs {
		c.types = append(c.types, ev.Type)
		field, ok := payload.ReplaceableText(ev)
		if !ok {
			continue
		}
		s, errGet := payload.GetText(ev, field)
		if errGet != nil {
			continue
		}
		c.write(ev.Index, s)
	}
}

func (c *client) write(index int, s string) {
	b := c.text[index]
	if b == nil {
		b = &strings.Builder{}
		c.text[index] = b
	}
	b.WriteString(s)
}

// block returns the assembled text of one content block.
func (c *client) block(index int) string {
	if b := c.text[index]; b != nil {
		return b.String()
	}
	return ""
}

// run feeds every chunk through the state into the client.
func run(st *state, c *client, chunks ...[]byte) {
	for _, ch := range chunks {
		c.feed(st.deliver(ch))
	}
}

// jstr encodes s as a JSON string, so no value has to be spelled as a
// literal inside the event builders.
func jstr(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// sse wraps a data line in the wire form the upstream uses.
func sse(kind, data string) []byte {
	return []byte("event: " + kind + "\ndata: " + data + "\n\n")
}

func sseMessageStart(model string) []byte {
	return sse(payload.EventMessageStart, fmt.Sprintf(
		`{"type":"message_start","message":{"id":"msg_lab","type":"message","role":"assistant","model":%s,"content":[],"stop_reason":null,"usage":{"input_tokens":10,"output_tokens":1}}}`,
		jstr(model)))
}

func evMessageDelta(stopReason string, out int) []byte {
	return sse(payload.EventMessageDelta, fmt.Sprintf(
		`{"type":"message_delta","delta":{"stop_reason":%s,"stop_sequence":null},"usage":{"output_tokens":%d}}`,
		jstr(stopReason), out))
}

func evBlockStartText(index int, text string) []byte {
	return sse(payload.EventContentBlockStart, fmt.Sprintf(
		`{"type":"content_block_start","index":%d,"content_block":{"type":"text","text":%s}}`,
		index, jstr(text)))
}

// evBlockStartRaw builds a content_block_start whose content_block is given
// as raw JSON, for the block types beyond plain text.
func evBlockStartRaw(index int, block string) []byte {
	return sse(payload.EventContentBlockStart, fmt.Sprintf(
		`{"type":"content_block_start","index":%d,"content_block":%s}`, index, block))
}

func evBlockStop(index int) []byte {
	return sse(payload.EventContentBlockStop, fmt.Sprintf(
		`{"type":"content_block_stop","index":%d}`, index))
}

// evBlockStopNoIndex is the malformed form: a stop event without its index.
func evBlockStopNoIndex() []byte {
	return sse(payload.EventContentBlockStop, `{"type":"content_block_stop"}`)
}

func evTextDelta(index int, text string) []byte {
	return sse(payload.EventContentBlockDelta, fmt.Sprintf(
		`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`,
		index, jstr(text)))
}

// evTextDeltaRaw builds a text delta whose text is given as raw JSON, for
// escapes that json.Marshal would not produce.
func evTextDeltaRaw(index int, rawText string) []byte {
	return sse(payload.EventContentBlockDelta, fmt.Sprintf(
		`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta","text":%s}}`,
		index, rawText))
}

// evTextDeltaWithoutText is a truncated text delta: the delta type says
// text_delta but the text field is missing.
func evTextDeltaWithoutText(index int) []byte {
	return sse(payload.EventContentBlockDelta, fmt.Sprintf(
		`{"type":"content_block_delta","index":%d,"delta":{"type":"text_delta"}}`, index))
}

func evJSONDelta(index int, fragment string) []byte {
	return sse(payload.EventContentBlockDelta, fmt.Sprintf(
		`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":%s}}`,
		index, jstr(fragment)))
}

func evPing() []byte {
	return sse(payload.EventPing, `{"type":"ping"}`)
}

// evComment is the bare SSE comment some proxies send as a keep-alive; it
// carries no data line at all.
func evComment() []byte {
	return []byte(": ping\n\n")
}

func evError(kind, message string) []byte {
	return sse(payload.EventError, fmt.Sprintf(
		`{"type":"error","error":{"type":%s,"message":%s}}`, jstr(kind), jstr(message)))
}
