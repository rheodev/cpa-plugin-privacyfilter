package main

// The content blocks themselves: a block start that carries text, the block
// types beside plain text, a pseudonym that falls exactly on the seam
// between two blocks, a block delivered one rune at a time, and the tool
// input whose fragments are JSON inside JSON.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// content_block_start of a text block carries its text whole, so it is
// restored without holdback.
func TestStream_BlockStartWithPrefilledText(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	st, c := newState(tab), newClient(t)

	text := "Vorbelegt: " + ps[0] + " und " + ps[3] + "."
	run(st, c, evBlockStartText(0, text), evBlockStop(0), evMessageStop())
	if got, want := c.block(0), whole(r, text); got != want {
		t.Errorf("prefilled block text:\n got %q\nwant %q", got, want)
	}
}

// A text block start whose text ends inside a pseudonym: it is restored
// whole and without holdback, so the first delta cannot complete it. The
// case does not arise with today's API, which sends an empty text.
func TestStream_BlockStartTextEndsInsideAPseudonym(t *testing.T) {
	tab, ps := fixture(t)
	st, c := newState(tab), newClient(t)

	alias := ps[0]
	run(st, c,
		evBlockStartText(0, "Wirt "+alias[:len(alias)-3]),
		evTextDelta(0, alias[len(alias)-3:]+" ist da."),
		evBlockStop(0), evMessageStop(),
	)
	// Nothing is lost, and nothing is restored either: the two halves are
	// two strings, so the pseudonym reaches the client as it went out.
	if got, want := c.block(0), "Wirt "+alias+" ist da."; got != want {
		t.Errorf("text of the split block:\n got %q\nwant %q", got, want)
	}
	t.Logf("a pseudonym split between content_block_start and the first delta stays a pseudonym: %q", c.block(0))
}

// Beside the text block the stream restores nothing: the four fields of
// ReplaceableText are the whole of it. thinking has to stay untouched, which
// it does; a tool_use block that arrives with its input already filled keeps
// its pseudonyms, although the non-streaming path would restore them.
func TestStream_BlockStartBesideTheTextBlock(t *testing.T) {
	tab, ps := fixture(t)
	st := newState(tab)
	alias := ps[0]

	shapes := []struct {
		name  string
		block string
		// keep is true for the block types that must not be touched.
		keep bool
	}{
		{"text", `{"type":"text","text":` + jstr("Wirt "+alias) + `}`, false},
		{"thinking", `{"type":"thinking","thinking":` + jstr("Wirt "+alias) + `,"signature":"sig"}`, true},
		{"tool_use with a filled input", `{"type":"tool_use","id":"toolu_lab","name":"Bash","input":{"command":` + jstr("ssh "+alias) + `}}`, false},
		{"web_search_tool_result", `{"type":"web_search_tool_result","tool_use_id":"srvtoolu_lab","content":[{"type":"web_search_result","title":` + jstr("Status "+alias) + `,"url":"https://example.invalid/s"}]}`, false},
	}
	for i, s := range shapes {
		out := st.deliver(evBlockStartRaw(i, s.block))
		left := bytes.Contains(out, []byte(alias))
		switch {
		case s.keep && !left:
			t.Errorf("%s: the pseudonym was restored although the block must stay untouched", s.name)
		case s.keep:
			// correct: thinking is never touched in either direction
		case left:
			t.Logf("%s: the pseudonym reaches the client unresolved; only content_block.text of a text block is restored", s.name)
		}
	}
}

// A pseudonym that falls on the seam between two blocks is never restored,
// on the stream as in the whole response, because the two halves belong to
// two different strings. What matters is that the held half is flushed into
// its own block and not into the next one.
func TestStream_PseudonymOnTheBlockBoundary(t *testing.T) {
	tab, ps := fixture(t)
	st, c := newState(tab), newClient(t)

	alias := ps[0]
	head, tail := alias[:len(alias)-4], alias[len(alias)-4:]
	run(st, c,
		evBlockStartText(0, ""),
		evTextDelta(0, "Ende von Block null "+head),
		evBlockStop(0),
		evBlockStartText(1, ""),
		evTextDelta(1, tail+" Anfang von Block eins"),
		evBlockStop(1),
		evMessageStop(),
	)
	if !strings.HasSuffix(c.block(0), head) {
		t.Errorf("the held half was not flushed into its own block: %q", c.block(0))
	}
	if !strings.HasPrefix(c.block(1), tail) {
		t.Errorf("block 1 does not begin with the second half: %q", c.block(1))
	}
	if strings.Contains(c.block(1), head) {
		t.Errorf("the holdback of block 0 was flushed into block 1: %q", c.block(1))
	}
	t.Logf("a pseudonym on the seam of two blocks stays a pseudonym in both halves: %q | %q", c.block(0), c.block(1))
}

// A block whose deltas carry one rune each. Almost every chunk vanishes into
// the holdback while a pseudonym is being spelled out, and the text has to
// come out whole all the same.
func TestStream_SingleRuneDeltas(t *testing.T) {
	tab, ps := fixture(t)
	r := tab.Restorer()
	st, c := newState(tab), newClient(t)

	text := "Byte fuer Byte: " + ps[0] + ", " + ps[3] + " und " + ps[4] + "."
	chunks := [][]byte{evBlockStartText(0, "")}
	chunks = append(chunks, deltaChunks(0, text, 1)...)
	chunks = append(chunks, evBlockStop(0), evMessageStop())

	dropped := 0
	for _, ch := range chunks {
		out := st.deliver(ch)
		if out == nil {
			dropped++
		}
		c.feed(out)
	}
	if got, want := c.block(0), whole(r, text); got != want {
		t.Errorf("one rune per delta:\n got %q\nwant %q", got, want)
	}
	if c.parseErrors != 0 {
		t.Errorf("client could not parse %d delivered chunks", c.parseErrors)
	}
	t.Logf("%d of %d chunks were dropped into the holdback", dropped, len(chunks))
}

// The tool input arrives as fragments of JSON inside a JSON string. An
// original with a double quote has to be escaped twice on its way back, and
// the assembled fragments have to parse again whatever the cut.
func TestStream_ToolInputFragments(t *testing.T) {
	tab := lab.Table()
	orig := "Ingrid " + `"Bobby"` + " Müller"
	alias := tab.Lookup(detect.KindPerson, orig)
	host := "zeus.lan"
	hostAlias := tab.Lookup(detect.KindHost, host)
	r := tab.Restorer()

	inner, err := json.Marshal(map[string]string{"kunde": alias, "host": hostAlias})
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(inner)

	for size := 1; size <= 7; size++ {
		st, c := newState(tab), newClient(t)
		chunks := [][]byte{evBlockStartRaw(0, `{"type":"tool_use","id":"toolu_lab","name":"Bash","input":{}}`)}
		for _, p := range splitSafe(fragment, size) {
			chunks = append(chunks, evJSONDelta(0, p))
		}
		chunks = append(chunks, evBlockStop(0), evMessageStop())
		run(st, c, chunks...)

		got := c.block(0)
		var out map[string]string
		if err := json.Unmarshal([]byte(got), &out); err != nil {
			t.Errorf("size %d: the assembled tool input is not JSON any more: %v\n%s", size, err, got)
			continue
		}
		if out["kunde"] != orig {
			t.Errorf("size %d: kunde = %q, want %q", size, out["kunde"], orig)
		}
		if out["host"] != host {
			t.Errorf("size %d: host = %q, want %q", size, out["host"], host)
		}
	}

	// A tool call the upstream cut off inside a pseudonym: the flush at
	// content_block_stop has to use the delta type of its own block, or the
	// client gets a text delta inside a tool_use block.
	t.Run("truncated tool call", func(t *testing.T) {
		st, c := newState(tab), newClient(t)
		cut := fragment[:strings.Index(fragment, hostAlias)+len(hostAlias)-3]
		chunks := [][]byte{evBlockStartRaw(0, `{"type":"tool_use","id":"toolu_lab","name":"Bash","input":{}}`)}
		for _, p := range splitSafe(cut, 5) {
			chunks = append(chunks, evJSONDelta(0, p))
		}
		run(st, c, chunks...)
		if blocks, held := st.pending(); blocks != 1 {
			t.Fatalf("the truncated fragment left %d blocks holding %q, want 1", blocks, held)
		}
		stopOut := st.deliver(evBlockStop(0))
		evs, err := payload.ParseEvents(stopOut)
		if err != nil {
			t.Fatalf("ParseEvents on the flushed stop: %v", err)
		}
		if len(evs) != 2 {
			t.Fatalf("stop event delivered %d events, want a synthetic delta in front of the stop", len(evs))
		}
		if evs[0].DeltaType != payload.DeltaInputJSON {
			t.Errorf("the flush used delta type %q, want %q", evs[0].DeltaType, payload.DeltaInputJSON)
		}
		if evs[0].Index != 0 {
			t.Errorf("the flush went to block %d, want 0", evs[0].Index)
		}
		c.feed(stopOut)
		if got, want := c.block(0), whole(r, cut); got != want {
			t.Errorf("truncated tool call:\n got %q\nwant %q", got, want)
		}
	})
}

// A delta whose text is half a surrogate pair. On its own the event is
// passed through byte for byte and the escape survives on the wire. Behind a
// holdback the event is rewritten, and re-encoding a lone surrogate replaces
// it. The finding itself is the one already recorded for Walk; this is the
// place on the stream where an unrelated delta reaches it.
func TestStream_LoneSurrogateBehindAHoldback(t *testing.T) {
	tab, ps := fixture(t)
	half := ps[0][:len(ps[0])-3]
	surrogate := []byte(`\ud83d`)

	alone := newState(tab)
	aloneOut := alone.deliver(evTextDeltaRaw(0, `"\ud83d"`))

	behind := newState(tab)
	behind.deliver(evTextDelta(0, "vor "+half))
	behindOut := behind.deliver(evTextDeltaRaw(0, `"\ud83d"`))

	if !bytes.Contains(aloneOut, surrogate) {
		t.Errorf("a lone surrogate delta was rewritten although nothing matched: %q", aloneOut)
	}
	if !bytes.Contains(behindOut, surrogate) {
		t.Logf("behind a holdback the same delta is re-encoded and the escape is gone: %q", behindOut)
	}
}
