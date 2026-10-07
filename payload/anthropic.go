package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
)

// errNoDataLine marks a chunk that is not a usable SSE event because it
// carries no data line. The caller passes such a chunk through untouched.
var errNoDataLine = errors.New("payload: sse chunk has no data line")

// errEditAcrossLines: a string edit on the joined data does not fall into
// one data line, which no JSON string can do; the event is left alone.
var errEditAcrossLines = errors.New("payload: sse string edit spans data lines")

// FormatClaude is the SourceFormat the host reports for Claude Code traffic.
// It is the only format the return pass handles until other clients appear.
const FormatClaude = "claude"

// Event types of the Anthropic Messages stream, as they appear in the
// "type" field of the data line.
const (
	EventMessageStart      = "message_start"
	EventMessageDelta      = "message_delta"
	EventMessageStop       = "message_stop"
	EventContentBlockStart = "content_block_start"
	EventContentBlockDelta = "content_block_delta"
	EventContentBlockStop  = "content_block_stop"
	EventPing              = "ping"
	EventError             = "error"
)

// Delta types inside content_block_delta, field delta.type.
const (
	DeltaText      = "text_delta"
	DeltaInputJSON = "input_json_delta"
	DeltaThinking  = "thinking_delta"
	DeltaSignature = "signature_delta"
	DeltaCitations = "citations_delta"
)

// TextField says where the replaceable text of a stream event lives and how
// it is encoded.
type TextField struct {
	// Path to the string inside the event JSON, e.g. {"delta","text"}.
	Path Path
	// Escaped is true when the string holds a fragment of JSON text, so
	// originals must be inserted in their JSON-escaped form (partial_json).
	Escaped bool
}

// Event is one parsed SSE event of an Anthropic stream.
type Event struct {
	// Type is the event type; equals the "event:" line and the "type" field.
	Type string
	// Index is content_block index for block events, -1 otherwise.
	Index int
	// DeltaType is delta.type for content_block_delta, empty otherwise.
	DeltaType string
	// Data is the raw JSON of the data line, without the "data: " prefix.
	Data []byte
	// Raw is the complete event as received, including the event: line,
	// the data: line and the terminating blank line, for pass-through.
	Raw []byte
	// segments maps the data lines into Raw: SSE joins several data lines
	// with a newline, so an offset into Data is not one into Raw. See
	// rawEdits.
	segments []dataSegment
}

// dataSegment is one data line of an event: where its field begins in Raw
// and in Data, and how long it is.
type dataSegment struct {
	raw, data, n int
}

// ParseEvent parses one SSE event. The host delivers whole events, never a
// partial one; a chunk that is not a well-formed event (no data line, data
// not a JSON object) is returned with Type "" and the error, and the caller
// passes it through unchanged. Multiple events in one chunk are not expected
// from this host but are handled: ParseEvents returns them all in order.
func ParseEvent(chunk []byte) (Event, error) {
	ev := Event{Index: -1, Raw: chunk}

	var eventLine string
	var data []byte
	var segments []dataSegment
	for pos := 0; pos < len(chunk); {
		next := len(chunk)
		if i := bytes.IndexByte(chunk[pos:], '\n'); i >= 0 {
			next = pos + i + 1
		}
		line := bytes.TrimSuffix(bytes.TrimSuffix(chunk[pos:next], []byte("\n")), []byte("\r"))
		switch {
		case bytes.HasPrefix(line, []byte("event:")):
			eventLine = string(bytes.TrimSpace(line[len("event:"):]))
		case bytes.HasPrefix(line, []byte("data:")):
			// SSE strips one optional space after the colon and joins
			// several data lines with a newline. This host sends one,
			// but every line is noted with its place in the chunk, so
			// an edit on the joined data finds its line again. data is
			// a copy, never a view into chunk: appending to a view would
			// write into Raw.
			skip := len("data:")
			field := line[skip:]
			if bytes.HasPrefix(field, []byte(" ")) {
				field = field[1:]
				skip++
			}
			if data != nil {
				data = append(data, '\n')
			}
			segments = append(segments, dataSegment{raw: pos + skip, data: len(data), n: len(field)})
			data = append(data, field...)
		}
		pos = next
	}
	if data == nil {
		return Event{Index: -1, Raw: chunk}, errNoDataLine
	}
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return Event{Index: -1, Raw: chunk}, ErrNotJSON
	}
	ev.Data = data
	ev.segments = segments

	var head struct {
		Type  string `json:"type"`
		Index *int   `json:"index"`
		Delta *struct {
			Type string `json:"type"`
		} `json:"delta"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		// A well-formed object with an unexpected shape, for instance a
		// numeric "index" that is not an int. Fall back to the event line.
		ev.Type = eventLine
		return ev, nil
	}
	ev.Type = head.Type
	if ev.Type == "" {
		ev.Type = eventLine
	}
	if head.Index != nil {
		ev.Index = *head.Index
	}
	if ev.Type == EventContentBlockDelta && head.Delta != nil {
		ev.DeltaType = head.Delta.Type
	}
	return ev, nil
}

// ParseEvents splits a chunk into events at blank lines and parses each. An
// event without a data line, such as an SSE comment, is kept with Type ""
// and its Raw bytes so the caller passes it through in place; a data line
// that is not a JSON object is an error for the whole chunk.
func ParseEvents(chunk []byte) ([]Event, error) {
	var out []Event
	rest := chunk
	for len(rest) > 0 {
		raw, remainder := splitEvent(rest)
		rest = remainder
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		ev, err := ParseEvent(raw)
		if err != nil && !errors.Is(err, errNoDataLine) {
			return out, err
		}
		out = append(out, ev)
	}
	return out, nil
}

// splitEvent cuts the first SSE event off b. The returned event keeps its
// terminating blank line so that Raw stays byte-identical to what arrived.
func splitEvent(b []byte) (event, rest []byte) {
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return b[:i+4], b[i+4:]
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return b[:i+2], b[i+2:]
	}
	return b, nil
}

// ReplaceableText returns the text field the return pass may rewrite in ev,
// or ok == false for events that carry none or must not be touched:
//
//	content_block_delta / text_delta        delta.text          Escaped false
//	content_block_delta / input_json_delta  delta.partial_json  Escaped true
//	content_block_delta / citations_delta   delta.citation.cited_text
//	content_block_delta / thinking_delta    none (never touched)
//	content_block_delta / signature_delta   none
//	content_block_start with a text block   content_block.text  Escaped false
//	message_start                           none in practice; the message
//	                                        head carries no user text
//	everything else                         none
//
// The cited text of a citation arrives whole, not as a fragment, so it is
// restored without holdback; Streamed reports which fields are fragments.
func ReplaceableText(ev Event) (field TextField, ok bool) {
	switch ev.Type {
	case EventContentBlockDelta:
		switch ev.DeltaType {
		case DeltaText:
			return TextField{Path: Path{"delta", "text"}}, true
		case DeltaInputJSON:
			return TextField{Path: Path{"delta", "partial_json"}, Escaped: true}, true
		case DeltaCitations:
			var head struct {
				Delta struct {
					Citation struct {
						CitedText *string `json:"cited_text"`
					} `json:"citation"`
				} `json:"delta"`
			}
			if err := json.Unmarshal(ev.Data, &head); err != nil || head.Delta.Citation.CitedText == nil {
				return TextField{}, false
			}
			return TextField{Path: Path{"delta", "citation", "cited_text"}}, true
		}
	case EventContentBlockStart:
		var head struct {
			ContentBlock struct {
				Type string  `json:"type"`
				Text *string `json:"text"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal(ev.Data, &head); err != nil {
			return TextField{}, false
		}
		if head.ContentBlock.Type == "text" && head.ContentBlock.Text != nil {
			return TextField{Path: Path{"content_block", "text"}}, true
		}
	}
	return TextField{}, false
}

// Streamed reports whether the text of ev is a fragment that may cut a
// pseudonym, so the stream has to hold back a suffix: the text deltas and
// the tool input deltas of a block. A citation is delivered whole, and the
// text of content_block_start is empty in practice, so both are restored
// as they are.
func Streamed(ev Event) bool {
	return ev.Type == EventContentBlockDelta && (ev.DeltaType == DeltaText || ev.DeltaType == DeltaInputJSON)
}

// GetText returns the decoded string at field inside the data of ev.
func GetText(ev Event, field TextField) (string, error) {
	if len(ev.Data) == 0 {
		return "", errNoDataLine
	}
	start, end, err := findValue(ev.Data, field.Path)
	if err != nil {
		return "", err
	}
	return decodeString(ev.Data[start:end])
}

// SetText returns a copy of ev.Raw with the string at field replaced by
// text, re-encoded as a JSON string with the escaping encoding/json uses
// (no HTML escaping). The event: line, key order and all other fields are
// preserved byte for byte; only the one string value changes.
func SetText(ev Event, field TextField, text string) ([]byte, error) {
	if len(ev.Data) == 0 {
		return nil, errNoDataLine
	}
	start, end, err := findValue(ev.Data, field.Path)
	if err != nil {
		return nil, err
	}
	if ev.Data[start] != '"' {
		return nil, errNotString
	}
	edits, err := ev.rawEdits([]stringEdit{{start: start, end: end, enc: encodeString(text)}})
	if err != nil {
		return nil, err
	}
	return splice(ev.Raw, edits)
}

// ReplaceData is ReplaceStrings for a stream event that arrives whole: it
// visits every string of the event's data that deny allows and splices the
// replacements into Raw, so the event: line, the data lines and every other
// byte survive as they came. deny nil means DefaultDeny. It returns Raw
// itself and 0 when nothing changed.
func ReplaceData(ev Event, deny *DenyList, fn func(Path, string) (string, bool)) (out []byte, replaced int, err error) {
	if len(ev.Data) == 0 {
		return nil, 0, errNoDataLine
	}
	if !json.Valid(ev.Data) {
		return nil, 0, ErrNotJSON
	}
	if deny == nil {
		deny = DefaultDeny()
	}
	edits, err := collectEdits(ev.Data, deny, fn)
	if err != nil {
		return nil, 0, err
	}
	if len(edits) == 0 {
		return ev.Raw, 0, nil
	}
	if edits, err = ev.rawEdits(edits); err != nil {
		return nil, 0, err
	}
	if out, err = splice(ev.Raw, edits); err != nil {
		return nil, 0, err
	}
	return out, len(edits), nil
}

// rawEdits maps edits on Data to edits on Raw, line by line. A JSON string
// cannot hold a raw newline, so a string value lies within one data line;
// an edit that does not is an error. An event built without data lines,
// Data and Raw set by hand, is handled when Data is a contiguous part of
// Raw.
func (ev Event) rawEdits(edits []stringEdit) ([]stringEdit, error) {
	if len(ev.segments) == 0 {
		offset := bytes.Index(ev.Raw, ev.Data)
		if offset < 0 {
			return nil, errNoDataLine
		}
		for i := range edits {
			edits[i].start += offset
			edits[i].end += offset
		}
		return edits, nil
	}
	for i, e := range edits {
		start, lineStart, okStart := ev.rawOffset(e.start)
		end, lineEnd, okEnd := ev.rawOffset(e.end)
		if !okStart || !okEnd || lineStart != lineEnd {
			return nil, errEditAcrossLines
		}
		edits[i].start, edits[i].end = start, end
	}
	return edits, nil
}

// rawOffset maps an offset into Data to the offset of the same byte in Raw
// and names the data line it falls into; ok is false when it falls into no
// line. The end of a line belongs to that line, so the end of a value on
// its last byte maps as well.
func (ev Event) rawOffset(off int) (raw, line int, ok bool) {
	for i, s := range ev.segments {
		if off >= s.data && off <= s.data+s.n {
			return s.raw + (off - s.data), i, true
		}
	}
	return 0, 0, false
}

// SyntheticDelta builds a complete SSE event of type content_block_delta
// for block index with the given delta type and text, in the same wire form
// the upstream uses: "event: content_block_delta\ndata: {...}\n\n". The
// stream flushes its holdback with it before content_block_stop and
// message_stop. deltaType is DeltaText or DeltaInputJSON; text is inserted
// as the value of delta.text or delta.partial_json respectively.
func SyntheticDelta(index int, deltaType, text string) []byte {
	key := "text"
	if deltaType == DeltaInputJSON {
		key = "partial_json"
	}
	// Assembled by hand rather than marshalled from a map, because the wire
	// form must keep the upstream's field order: type, index, delta.
	var buf bytes.Buffer
	buf.WriteString("event: ")
	buf.WriteString(EventContentBlockDelta)
	buf.WriteString("\ndata: {\"type\":")
	buf.Write(encodeString(EventContentBlockDelta))
	buf.WriteString(",\"index\":")
	buf.WriteString(strconv.Itoa(index))
	buf.WriteString(",\"delta\":{\"type\":")
	buf.Write(encodeString(deltaType))
	buf.WriteByte(',')
	buf.Write(encodeString(key))
	buf.WriteByte(':')
	buf.Write(encodeString(text))
	buf.WriteString("}}\n\n")
	return buf.Bytes()
}

// ReplaceStrings is the return-path counterpart of Walk: it visits every
// string value of the JSON object body that deny does not cover, and every
// object key below the input of a tool block, in document order, and
// rewrites those for which fn returns true. deny nil means DefaultDeny, the
// same list the forward pass applies, so what was never pseudonymized on the
// way out, thinking blocks above all, is never touched on the way back, and
// a field the list does not name is handled by the list alone, not by a
// second enumeration here.
//
// The body is not re-serialized: only the replaced strings change, every
// other byte survives as it was, so key order, whitespace and number
// formatting of the upstream response are preserved and a duplicate key is
// rewritten in both places. The body is read once. When no value changed,
// body itself is returned and replaced is 0. A body that is not a JSON
// object is ErrNotJSON. Walk runs the same pass with the forward path's
// limit; the two differ in nothing else.
func ReplaceStrings(body []byte, deny *DenyList, fn func(Path, string) (string, bool)) (out []byte, replaced int, err error) {
	if !json.Valid(body) {
		return nil, 0, ErrNotJSON
	}
	if deny == nil {
		deny = DefaultDeny()
	}
	return rewrite(body, deny, fn)
}
