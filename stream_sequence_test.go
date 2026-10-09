package main

// The event sequence of a streamed answer: the whole run from message_start
// to message_stop, keep-alives in between, several blocks at once, the
// message_delta that carries the stop reason, and the same run with the
// order disturbed.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// count returns how often kind appears in the event types the client saw.
func count(types []string, kind string) int {
	n := 0
	for _, t := range types {
		if t == kind {
			n++
		}
	}
	return n
}

// indexOf returns the position of the first event of type kind, or -1.
func indexOf(types []string, kind string) int {
	for i, t := range types {
		if t == kind {
			return i
		}
	}
	return -1
}

// The ordinary run: one block, the answer cut into three-byte fragments,
// stop reason and stop event at the end. What the client assembles has to
// be what the same text yields restored in one piece.
func TestStream_FullSequenceInOrder(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	st := newState(tab)
	c := newClient(t)

	text := "Der Rechner " + ps[0] + " antwortet, " + ps[2] + " hat ihn bestellt; Pfad /srv/" + ps[3] + "/log."
	chunks := [][]byte{sseMessageStart("claude-lab"), evBlockStartText(0, "")}
	chunks = append(chunks, deltaChunks(0, text, 3)...)
	chunks = append(chunks, evBlockStop(0), evMessageDelta("end_turn", 42), evMessageStop())
	run(st, c, chunks...)

	if got, want := c.block(0), whole(r, text); got != want {
		t.Errorf("streamed text differs from the whole one:\n got %q\nwant %q", got, want)
	}
	if c.parseErrors != 0 {
		t.Errorf("client could not parse %d delivered chunks", c.parseErrors)
	}
	if c.types[0] != payload.EventMessageStart {
		t.Errorf("first event delivered is %q, want %q", c.types[0], payload.EventMessageStart)
	}
	if last := c.types[len(c.types)-1]; last != payload.EventMessageStop {
		t.Errorf("last event delivered is %q, want %q", last, payload.EventMessageStop)
	}
	if n := count(c.types, payload.EventContentBlockStop); n != 1 {
		t.Errorf("content_block_stop delivered %d times, want 1", n)
	}
	if n := count(c.types, payload.EventMessageStop); n != 1 {
		t.Errorf("message_stop delivered %d times, want 1", n)
	}
	if a, b := indexOf(c.types, payload.EventContentBlockStop), indexOf(c.types, payload.EventMessageDelta); a > b {
		t.Errorf("content_block_stop at %d arrived behind message_delta at %d", a, b)
	}
	if blocks, held := st.pending(); blocks != 0 {
		t.Errorf("%d blocks still hold text after message_stop: %q", blocks, held)
	}
}

// Keep-alives between the fragments must change nothing, whether they come
// in a chunk of their own or glued to a delta. The bare comment form has no
// data line at all and has to survive as it is.
func TestStream_PingAndCommentBetweenDeltas(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	text := "Der Wirt " + ps[1] + " liegt unter /srv/" + ps[3] + "/data, " + ps[2] + " pflegt ihn."
	want := whole(r, text)

	t.Run("separate chunks", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		var chunks [][]byte
		for _, d := range deltaChunks(0, text, 4) {
			chunks = append(chunks, d, evPing(), evComment())
		}
		chunks = append(chunks, evBlockStop(0), evMessageStop())
		run(st, c, chunks...)
		if got := c.block(0); got != want {
			t.Errorf("pings between the fragments changed the text:\n got %q\nwant %q", got, want)
		}
	})

	t.Run("ping in the same chunk", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		pieces := deltaChunks(0, text, 4)
		var chunks [][]byte
		for _, d := range pieces {
			chunks = append(chunks, append(append([]byte{}, d...), evPing()...))
		}
		chunks = append(chunks, evBlockStop(0), evMessageStop())
		run(st, c, chunks...)
		if got := c.block(0); got != want {
			t.Errorf("ping glued to the delta changed the text:\n got %q\nwant %q", got, want)
		}
		if n := count(c.types, payload.EventPing); n != len(pieces) {
			t.Errorf("%d of %d pings reached the client; a ping is lost when its chunk is dropped", n, len(pieces))
		}
	})
}

// message_delta carries the stop reason and the token count and has no text.
// It must arrive byte for byte as it came.
func TestStream_MessageDeltaCarriesStopReason(t *testing.T) {
	tab, ps := fixture(t)
	st, c := newState(tab), newClient(t)

	md := evMessageDelta("max_tokens", 4096)
	run(st, c,
		sseMessageStart("claude-lab"),
		evBlockStartText(0, ""),
		evTextDelta(0, "Abbruch bei "+ps[0]),
		evBlockStop(0),
		md,
		evMessageStop(),
	)
	if n := count(c.types, payload.EventMessageDelta); n != 1 {
		t.Fatalf("message_delta delivered %d times, want 1", n)
	}
	st2 := newState(tab)
	out := st2.deliver(md)
	if string(out) != string(md) {
		t.Errorf("message_delta was rewritten:\n got %q\nwant %q", out, md)
	}
}

// A message_delta that arrives while a block still holds text: the held text
// is flushed only at message_stop, so it reaches the client behind the stop
// reason. No text is lost, but the order is not the upstream's.
func TestStream_MessageDeltaAheadOfTheFlush(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	st, c := newState(tab), newClient(t)

	// The fragment stops inside the pseudonym, so the tail waits.
	half := ps[0][:len(ps[0])-3]
	run(st, c,
		sseMessageStart("claude-lab"),
		evBlockStartText(0, ""),
		evTextDelta(0, "Rechner "+half),
		evMessageDelta("end_turn", 12),
		evMessageStop(),
	)
	sent := "Rechner " + half
	if got, want := c.block(0), whole(r, sent); got != want {
		t.Errorf("text lost around the missing content_block_stop:\n got %q\nwant %q", got, want)
	}
	stop := indexOf(c.types, payload.EventMessageDelta)
	flush := -1
	for i, ty := range c.types {
		if ty == payload.EventContentBlockDelta && i > stop {
			flush = i
			break
		}
	}
	if flush > stop {
		t.Logf("held text is flushed at position %d, behind the message_delta at %d: a client that stops assembling on the stop reason would drop it", flush, stop)
	}
}

// Two blocks open at the same time, their deltas interleaved. Each block has
// its own holdback, and each stop event may only flush its own.
func TestStream_MultipleBlocksInterleaved(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	st, c := newState(tab), newClient(t)

	t0 := "Block null nennt " + ps[0] + " und " + ps[4] + " im Netz."
	t1 := "Block eins nennt " + ps[1] + " und " + ps[5] + " am Port."
	p0, p1 := splitSafe(t0, 5), splitSafe(t1, 5)

	chunks := [][]byte{sseMessageStart("claude-lab"), evBlockStartText(0, ""), evBlockStartText(1, "")}
	for i := 0; i < len(p0) || i < len(p1); i++ {
		if i < len(p0) {
			chunks = append(chunks, evTextDelta(0, p0[i]))
		}
		if i < len(p1) {
			chunks = append(chunks, evTextDelta(1, p1[i]))
		}
	}
	chunks = append(chunks, evBlockStop(1), evBlockStop(0), evMessageStop())
	run(st, c, chunks...)

	if got, want := c.block(0), whole(r, t0); got != want {
		t.Errorf("block 0:\n got %q\nwant %q", got, want)
	}
	if got, want := c.block(1), whole(r, t1); got != want {
		t.Errorf("block 1:\n got %q\nwant %q", got, want)
	}
	if blocks, held := st.pending(); blocks != 0 {
		t.Errorf("%d blocks still hold text: %q", blocks, held)
	}
}

// The stop event of one block must not flush the other block's holdback.
func TestStream_BlockStopFlushesOnlyItsOwnBlock(t *testing.T) {
	tab, ps := fixture(t)
	st, c := newState(tab), newClient(t)

	half0 := ps[0][:len(ps[0])-2]
	half1 := ps[1][:len(ps[1])-2]
	run(st, c,
		evBlockStartText(0, ""), evBlockStartText(1, ""),
		evTextDelta(0, "null "+half0),
		evTextDelta(1, "eins "+half1),
		evBlockStop(0),
	)
	if blocks, held := st.pending(); blocks != 1 || !strings.HasSuffix(held, half1) {
		t.Errorf("after content_block_stop of block 0 the pending holdback is %d blocks, %q; want only block 1 with the tail of its own text", blocks, held)
	}
	if !strings.Contains(c.block(0), half0) {
		t.Errorf("block 0 was not flushed at its stop event: %q", c.block(0))
	}
	if strings.Contains(c.block(0), half1) {
		t.Errorf("the holdback of block 1 was flushed into block 0: %q", c.block(0))
	}
}

// The sequence out of order. None of these shapes may lose or double text
// that the upstream did send.
func TestStream_DisturbedOrder(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	text := "Wirt " + ps[0] + " unter /srv/" + ps[3] + "/etc."

	t.Run("stop before the deltas", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		chunks := [][]byte{evBlockStartText(0, ""), evBlockStop(0)}
		chunks = append(chunks, deltaChunks(0, text, 4)...)
		chunks = append(chunks, evMessageStop())
		run(st, c, chunks...)
		if got, want := c.block(0), whole(r, text); got != want {
			t.Errorf("deltas behind their stop event:\n got %q\nwant %q", got, want)
		}
	})

	t.Run("message_stop before the block stop", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		chunks := deltaChunks(0, text, 4)
		chunks = append(chunks, evMessageStop(), evBlockStop(0))
		run(st, c, chunks...)
		if got, want := c.block(0), whole(r, text); got != want {
			t.Errorf("message_stop ahead of the block stop:\n got %q\nwant %q", got, want)
		}
	})

	t.Run("two message_start events", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		chunks := [][]byte{sseMessageStart("claude-lab"), sseMessageStart("claude-lab"), evBlockStartText(0, "")}
		chunks = append(chunks, deltaChunks(0, text, 4)...)
		chunks = append(chunks, evBlockStop(0), evMessageStop())
		run(st, c, chunks...)
		if got, want := c.block(0), whole(r, text); got != want {
			t.Errorf("a repeated message_start changed the text:\n got %q\nwant %q", got, want)
		}
		if n := count(c.types, payload.EventMessageStart); n != 2 {
			t.Errorf("%d message_start events reached the client, want 2", n)
		}
	})

	t.Run("deltas behind message_stop", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		chunks := [][]byte{evBlockStartText(0, ""), evMessageStop()}
		chunks = append(chunks, deltaChunks(0, text, 4)...)
		run(st, c, chunks...)
		if got, want := c.block(0), whole(r, text); got != want {
			t.Errorf("deltas behind message_stop:\n got %q\nwant %q", got, want)
		}
		if _, held := st.pending(); held != "" {
			t.Logf("after message_stop the stream keeps holding %d bytes: nothing flushes them any more", len(held))
		}
	})
}

// A content_block_stop without an index is the malformed form, and Event.Index
// is then -1, the same value the flush uses for "every block". The stop of one
// block therefore empties every other block's holdback as well.
func TestStream_BlockStopWithoutIndexFlushesEverything(t *testing.T) {
	tab, ps := fixture(t)
	st, c := newState(tab), newClient(t)

	half0 := ps[0][:len(ps[0])-2]
	half1 := ps[1][:len(ps[1])-2]
	rest1 := ps[1][len(ps[1])-2:]

	// Two blocks are open and each holds the beginning of a pseudonym.
	run(st, c,
		evBlockStartText(0, ""), evBlockStartText(1, ""),
		evTextDelta(0, "null "+half0),
		evTextDelta(1, "eins "+half1),
	)
	if blocks, held := st.pending(); blocks != 2 {
		t.Fatalf("before the unindexed stop %d block(s) hold %q, want both", blocks, held)
	}

	// The malformed stop carries no index, so Event.Index is -1, which is
	// the value flushBefore reads as "every block".
	run(st, c, evBlockStopNoIndex())
	if blocks, held := st.pending(); blocks != 0 {
		t.Errorf("after the unindexed stop %d block(s) still hold %q; the finding is that it empties them all", blocks, held)
	}
	if !strings.HasSuffix(c.block(1), half1) {
		t.Errorf("block 1 was still open, yet its holdback went out at the unindexed stop of another block: %q, want it to end in %q", c.block(1), half1)
	}
	t.Logf("an unindexed content_block_stop flushed both open blocks; block 1 already reads %q", c.block(1))

	// Block 1 runs on. Its pseudonym was cut in two by that flush, and both
	// halves reach the client unresolved.
	run(st, c, evTextDelta(1, rest1+" fertig"), evBlockStop(1), evMessageStop())
	if !strings.Contains(c.block(1), ps[1]) {
		t.Errorf("block 1 no longer carries the unresolved pseudonym: %q", c.block(1))
	}
	t.Logf("block 1 still shows its pseudonym after the unindexed stop cut it in two: %q", c.block(1))
}
