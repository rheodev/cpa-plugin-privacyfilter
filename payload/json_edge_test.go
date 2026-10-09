package payload_test

// Two questions the previous run raised:
//  1. does a body with trailing whitespace reach the forward path at all,
//     given that on_error is block there?
//  2. what happens to a lone surrogate, which is legal JSON but not legal
//     UTF-8, when the body is re-serialized?

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// A real HTTP body often ends in a newline. If ReplaceStrings rejects it,
// every such request is blocked on the forward path.
func TestReplaceStrings_TrailingWhitespace(t *testing.T) {
	cases := map[string]string{
		"newline":       `{"a":"zeus.lan"}` + "\n",
		"crlf":          `{"a":"zeus.lan"}` + "\r\n",
		"space":         `{"a":"zeus.lan"} `,
		"leading space": ` {"a":"zeus.lan"}`,
		"tab around":    "\t" + `{"a":"zeus.lan"}` + "\t",
		"clean":         `{"a":"zeus.lan"}`,
	}
	for name, body := range cases {
		out, n, err := payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), replaceHost)
		t.Logf("%-14s -> replaced=%d err=%v out=%q", name, n, err, string(out))
		if err != nil {
			t.Errorf("%s: a body with surrounding whitespace was rejected: %v", name, err)
		}
	}
}

// A lone surrogate survives in JSON but has no UTF-8 encoding. Go's encoder
// turns it into the replacement character; the walk keeps the bytes of every
// string that does not change, so the surrogate stays as it came.
func TestWalk_LoneSurrogate(t *testing.T) {
	body := `{"keep":"\ud800","hit":"zeus.lan"}`
	out, changed, err := payload.Walk([]byte(body), payload.WalkOptions{}, replaceHost)
	if err != nil {
		t.Logf("rejected: %v", err)
		return
	}
	t.Logf("changed=%v out=%s", changed, out)
	switch {
	case strings.Contains(string(out), `\ud800`):
		t.Logf("lone surrogate preserved")
	case strings.Contains(string(out), "�"), strings.Contains(string(out), `�`):
		t.Errorf("the lone surrogate was rewritten to the replacement character: %s", out)
	default:
		t.Errorf("unexpected handling of the lone surrogate: %s", out)
	}
}

// Control characters must stay escaped, or the body becomes invalid JSON.
func TestWalk_ControlCharacters(t *testing.T) {
	body := `{"ctl":"a\u0001b\u001fc","hit":"zeus.lan"}`
	out, _, err := payload.Walk([]byte(body), payload.WalkOptions{}, replaceHost)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if strings.ContainsAny(string(out), "\x01\x1f") {
		t.Errorf("control characters were emitted raw, the body is no longer valid JSON: %q", out)
	}
	t.Logf("out=%s", out)
}
