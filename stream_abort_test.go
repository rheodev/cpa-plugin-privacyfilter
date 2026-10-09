package main

// What happens when the stream ends before its stop events, and what a chunk
// that fails halfway leaves behind. The question both probes answer: does a
// held remainder stay behind, and is text lost or doubled by it.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// The upstream stops after half a block, once by dropping the connection and
// once with an error event. The error event flushes the holdback in front of
// itself, like the stop events do; the dropped connection leaves nothing to
// flush in front of, and the tail stays held, which streams.finish warns
// about.
func TestStream_EndWithoutStopEventLosesHeldText(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()

	// The last fragment ends inside a pseudonym, so its tail waits for a
	// continuation that never comes.
	sent := "Der Auftrag lief auf " + ps[0][:len(ps[0])-3]

	cases := []struct {
		name string
		tail [][]byte
		// flushed says the stream gets a last event to flush in front of.
		flushed bool
	}{
		{"connection dropped", nil, false},
		{"error event", [][]byte{evError("overloaded_error", "Overloaded")}, true},
	}
	for _, tc := range cases {
		st, c := newState(tab), newClient(t)
		chunks := [][]byte{sseMessageStart("claude-lab"), evBlockStartText(0, "")}
		chunks = append(chunks, deltaChunks(0, sent, 6)...)
		chunks = append(chunks, tc.tail...)
		run(st, c, chunks...)

		blocks, held := st.pending()
		got, want := c.block(0), whole(r, sent)
		if tc.flushed {
			if got != want {
				t.Errorf("%s: %d bytes of the answer never reached the client, %d block(s) still holding:\n got %q\nwant %q",
					tc.name, len(want)-len(got), blocks, got, want)
			}
			if blocks != 0 {
				t.Errorf("%s: %d block(s) still hold %q after the error event", tc.name, blocks, held)
			}
			continue
		}
		// Without any last event the plugin has nothing to flush in front
		// of; the warning in streams.finish is all it can do.
		if got == want {
			t.Errorf("%s: the held text reached the client although no event carried it", tc.name)
		}
		if blocks == 0 || held == "" {
			t.Errorf("%s: text is missing although nothing is held", tc.name)
		}
		t.Logf("%s: %d bytes stay held, the stream ends with a warning", tc.name, len(held))
	}
}

// An error event arrives whole and is restored as a whole: its message may
// quote the request, and the stream says the same about it as the
// non-streaming return path would, which walks the same data with the same
// deny list. The error's own type stays, the list covers it.
func TestStream_ErrorEventRestoresItsMessage(t *testing.T) {
	tab, ps := fixture(t)
	st := newState(tab)

	ev := evError("invalid_request_error", "messages.0.content.0.text: "+ps[0]+" ist unbekannt")
	out := st.deliver(ev)
	if string(out) == string(ev) {
		t.Fatalf("error event passed through with its pseudonym:\n%s", out)
	}

	evs, err := payload.ParseEvents(ev)
	if err != nil || len(evs) != 1 {
		t.Fatalf("ParseEvents: %v (%d events)", err, len(evs))
	}
	data, n, err := payload.ReplaceStrings(evs[0].Data, payload.DefaultDeny(), func(_ payload.Path, v string) (string, bool) {
		return st.restorer.Restore(v, false)
	})
	if err != nil || n != 1 {
		t.Fatalf("ReplaceStrings: %d, %v", n, err)
	}
	want := "event: error\ndata: " + string(data) + "\n\n"
	if string(out) != want {
		t.Errorf("the stream and the non-streaming path disagree about the error event:\n got %q\nwant %q", out, want)
	}
	if !strings.Contains(string(out), `"type":"invalid_request_error"`) {
		t.Errorf("the error type was touched: %s", out)
	}
}

// A chunk with a good delta in front of a truncated one. The good delta has
// already moved its tail into the holdback when the second event fails; the
// failing event alone passes through as it came, and the chunk goes on, so
// the tail goes out once, from the holdback.
func TestStream_PartialStateThenChunkError(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	st, c := newState(tab), newClient(t)

	head := "Der Wirt " + ps[0][:len(ps[0])-3]
	tail := ps[0][len(ps[0])-3:] + " ist erreichbar."

	first := append(append([]byte{}, evTextDelta(0, head)...), evTextDeltaWithoutText(0)...)
	run(st, c,
		evBlockStartText(0, ""),
		first,
		evTextDelta(0, tail),
		evBlockStop(0),
		evMessageStop(),
	)

	sent := head + tail
	if got, want := c.block(0), whole(r, sent); got != want {
		t.Errorf("a chunk that failed behind a good delta left its holdback in place:\n got %q\nwant %q", got, want)
	}
}

// The same chunk without the good delta in front: a lone malformed event is
// passed through, which is the documented behaviour, and no state moves.
func TestStream_LoneMalformedEventPassesThrough(t *testing.T) {
	tab, _ := fixture(t)
	st := newState(tab)

	ev := evTextDeltaWithoutText(0)
	if out := st.deliver(ev); string(out) != string(ev) {
		t.Errorf("malformed event was rewritten:\n got %q\nwant %q", out, ev)
	}
	if blocks, held := st.pending(); blocks != 0 {
		t.Errorf("a malformed event left %d block(s) holding %q", blocks, held)
	}
}
