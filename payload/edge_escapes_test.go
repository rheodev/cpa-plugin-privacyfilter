package payload_test

// A string with every escape JSON knows, and one with bytes that are no
// character at all. The forward path decodes and re-encodes every string, so
// what comes out is Go's spelling of the same text; the return path only
// touches the strings it replaces. Both have to mean the same thing they did
// before.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// escaped assembles a string that uses every escape sequence of the JSON
// grammar, in the form it has on the wire. It is assembled from character
// codes rather than written out, for the same reason as v4: an escape
// sequence in a source file is exactly the kind of thing that does not
// survive the way to disk unchanged.
func escaped() string {
	bs := string(rune(92))
	u := func(cp int) string { return bs + fmt.Sprintf("u%04x", cp) }
	parts := []string{
		"quote:" + bs + string(rune(34)),
		"backslash:" + bs + bs,
		"solidus:" + bs + string(rune(47)),
		"ctl:" + bs + "b" + bs + "f" + bs + "n" + bs + "r" + bs + "t",
		"nul:" + u(0),
		"unit:" + u(0x1f),
		"pair:" + u(0xd83d) + u(0xde00),
		"nbsp:" + u(0xa0),
		"html:<&>",
	}
	return strings.Join(parts, " ")
}

// The escaped string sits beside a value that does change, so the body is
// written back in both directions. Its meaning must survive that.
func TestJSONEdge_AllJSONEscapes(t *testing.T) {
	esc := escaped()
	body := fmt.Sprintf(`{"esc":"%s","hit":%q}`, esc, needle)

	var before map[string]string
	if err := json.Unmarshal([]byte(body), &before); err != nil {
		t.Fatalf("the input is not valid JSON: %v", err)
	}

	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		var after map[string]string
		if err := json.Unmarshal(out, &after); err != nil {
			t.Fatalf("%s produced a body that no longer parses: %v: %s", name, err, out)
		}
		if after["esc"] != before["esc"] {
			t.Errorf("%s changed the meaning of the escaped string:\nbefore %q\nafter  %q",
				name, before["esc"], after["esc"])
		}
	}
	t.Logf("forward wrote it as %s", fwd)

	// The return path must leave a string it does not replace byte for byte
	// as it was, which is what keeps a signature and a base64 blob intact.
	if !bytes.Contains(ret, []byte(esc)) {
		t.Errorf("the return path rewrote a string it did not replace: %s", ret)
	}
}

// The same string, but now the value to replace sits inside it, so the
// string itself is re-encoded in both directions.
func TestJSONEdge_ReplacementInsideAnEscapedString(t *testing.T) {
	body := fmt.Sprintf(`{"esc":"%s tail:%s"}`, escaped(), needle)

	var before map[string]string
	if err := json.Unmarshal([]byte(body), &before); err != nil {
		t.Fatalf("the input is not valid JSON: %v", err)
	}
	want, changed := hide(payload.Path{"esc"}, before["esc"])
	if !changed {
		t.Fatalf("the test value is not inside the string")
	}

	fwd, _, err := outbound(body)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	ret, _, err := inbound(body)
	if err != nil {
		t.Fatalf("return: %v", err)
	}
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if !json.Valid(out) {
			t.Fatalf("%s produced invalid JSON: %s", name, out)
		}
		var after map[string]string
		if err := json.Unmarshal(out, &after); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if after["esc"] != want {
			t.Errorf("%s lost part of the escaped string around the replacement:\nwant %q\ngot  %q",
				name, want, after["esc"])
		}
	}
}

// Bytes that are no character. The JSON grammar accepts any byte above the
// control range inside a string, so a tool that cuts its output in the
// middle of a character produces a body like this. The forward path decodes
// it, and Go's decoder replaces what it cannot read.
func TestJSONEdge_RawInvalidUTF8(t *testing.T) {
	body := append([]byte(`{"raw":"a`), 0xff, 0xfe)
	body = append(body, []byte(fmt.Sprintf(`b","hit":%q}`, needle))...)
	if !json.Valid(body) {
		t.Skip("the scanner already rejects the body, nothing to see here")
	}

	fwd, changed, err := payload.Walk(body, payload.WalkOptions{}, hide)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	ret, n, err := payload.ReplaceStrings(body, payload.DefaultDeny(), hide)
	if err != nil {
		t.Fatalf("return: %v", err)
	}
	t.Logf("forward changed=%v keeps the bytes=%v", changed, bytes.Contains(fwd, []byte{0xff, 0xfe}))
	t.Logf("return replaced=%d keeps the bytes=%v", n, bytes.Contains(ret, []byte{0xff, 0xfe}))
	if !bytes.Contains(fwd, []byte{0xff, 0xfe}) {
		t.Logf("the forward path rewrote the unreadable bytes to the replacement character, "+
			"the same mechanism as the lone surrogate: %q", fwd)
	}
}

// A body that is not an object at all. Both functions have to say so rather
// than work on half a body, because on the forward path the answer decides
// whether the request is blocked.
func TestJSONEdge_BodyIsNotAnObject(t *testing.T) {
	cases := map[string]string{
		"array":  fmt.Sprintf(`[{"a":%q}]`, needle),
		"string": fmt.Sprintf(`%q`, needle),
		"number": `42`,
		"null":   `null`,
		"empty":  ``,
	}
	for name, body := range cases {
		_, _, errFwd := outbound(body)
		_, _, errRet := inbound(body)
		t.Logf("%-6s forward=%v return=%v", name, errFwd, errRet)
		if errFwd == nil {
			t.Errorf("%s: the forward path accepted a body that is not an object", name)
		}
		if errRet == nil {
			t.Errorf("%s: the return path accepted a body that is not an object", name)
		}
	}
}
