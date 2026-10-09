package payload_test

// The deny list matches by key name, by dotted suffix and by the type of an
// enclosing object. All three rules are applied at every depth, including
// inside tool_use.input, which is not the schema at all but arbitrary JSON
// that the model writes and a tool reads.

import (
	"bytes"
	"fmt"
	"testing"
)

// A tool argument that happens to be shaped like a part of the schema. None
// of the three rules asks how deep it is or whether the position means what
// the name suggests.
func TestJSONEdge_DenyRulesReachIntoToolArguments(t *testing.T) {
	cases := map[string]string{
		"source.data suffix": fmt.Sprintf(`{"source":{"type":"base64","data":%q}}`, needle),
		"metadata.user_id":   fmt.Sprintf(`{"metadata":{"user_id":%q}}`, needle),
		"a type of thinking": fmt.Sprintf(`{"type":"thinking","label":%q,"rows":[%q]}`, needle, needle),
		"an ordinary object": fmt.Sprintf(`{"type":"table","label":%q,"rows":[%q]}`, needle, needle),
	}
	for name, args := range cases {
		body := fmt.Sprintf(`{"messages":[{"role":"user","content":[`+
			`{"type":"tool_use","id":"toolu_01","name":"report","input":%s}]}]}`, args)
		paths, err := visitedOut(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, _, err := outbound(body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		kept := bytes.Count(out, []byte(needle))
		t.Logf("%-18s visited=%q clear text left=%d", name, paths, kept)
		if kept > 0 && name != "an ordinary object" {
			t.Errorf("%s: %d values of a tool argument kept their clear text because the "+
				"argument is shaped like a part of the schema: %s", name, kept, out)
		}
	}
}

// The counter probe: the same names where the schema puts them must stay
// denied, or the cure for the case above would break what works.
func TestJSONEdge_DenyRulesStillHoldWhereTheyBelong(t *testing.T) {
	body := fmt.Sprintf(`{"metadata":{"user_id":%q},"messages":[{"role":"user","content":[`+
		`{"type":"thinking","thinking":%q,"signature":%q},`+
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":%q}}]}]}`,
		needle, needle, needle, needle)
	out, changed, err := outbound(body)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if changed {
		t.Errorf("a field that has to stay untouched was rewritten: %s", out)
	}
	if n := bytes.Count(out, []byte(needle)); n != 4 {
		t.Errorf("expected all four denied fields to stay as they are, %d did: %s", n, out)
	}
}
