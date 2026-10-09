package main

import (
	"encoding/json"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// TestStream_PseudonymEndingInStartByte is the regression test of the fault
// seen live on the sixth of September: a path segment pseudonym whose last
// hex digit is the "d" every path segment pseudonym begins with, cut by a
// delta boundary anywhere inside, reached the client unrestored. The old
// holdback kept the last byte as the possible start of the next pseudonym
// and so split a complete one in two. The tool input is cut at every byte,
// and the assembled command must carry the original path each time.
func TestStream_PseudonymEndingInStartByte(t *testing.T) {
	table := mapping.NewTable(genFunc(func(_ detect.Kind, value string, _ int) string {
		return map[string]string{
			"alpha": "d-aaaaaaaaaaad",
			"beta":  "d-bbbbbbbbbbbb",
		}[value]
	}))
	alpha := table.Lookup(detect.KindPathSegment, "alpha")
	beta := table.Lookup(detect.KindPathSegment, "beta")
	input := `{"command": "ls -la /home/` + alpha + `/` + beta + `/src && cd /home/` + alpha + `"}`
	want := `ls -la /home/alpha/beta/src && cd /home/alpha`

	assemble := func(t *testing.T, raws ...[]byte) string {
		t.Helper()
		var out string
		for _, raw := range raws {
			evs, err := payload.ParseEvents(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range evs {
				if f, ok := payload.ReplaceableText(ev); ok {
					s, _ := payload.GetText(ev, f)
					out += s
				}
			}
		}
		return out
	}

	for _, cut := range runeSplits(input) {
		st := &streamState{restorer: table.Restorer(), holds: map[int]*blockHold{}}
		var delivered [][]byte
		for _, piece := range []string{input[:cut], input[cut:]} {
			raw := payload.SyntheticDelta(0, payload.DeltaInputJSON, piece)
			out, drop, err := st.chunk(raw)
			if err != nil {
				t.Fatalf("cut at %d: %v", cut, err)
			}
			switch {
			case drop:
			case out == nil:
				delivered = append(delivered, raw)
			default:
				delivered = append(delivered, out)
			}
		}
		flushed, _, err := st.chunk(evStop(0))
		if err != nil {
			t.Fatal(err)
		}
		delivered = append(delivered, flushed)
		var parsed struct {
			Command string `json:"command"`
		}
		assembled := assemble(t, delivered...)
		if err := json.Unmarshal([]byte(assembled), &parsed); err != nil {
			t.Fatalf("cut at %d: assembled input is not JSON: %v\n%s", cut, err, assembled)
		}
		if parsed.Command != want {
			t.Fatalf("cut at %d: command = %q, want %q", cut, parsed.Command, want)
		}
	}
}
