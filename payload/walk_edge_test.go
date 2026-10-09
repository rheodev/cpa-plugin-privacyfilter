package payload_test

// Follow-ups on two observations from the first payload run: the walk
// reorders object keys when it re-serializes, and it accepts trailing bytes
// after the closing brace.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func replaceHost(p payload.Path, v string) (string, bool) {
	if strings.Contains(v, "zeus.lan") {
		return strings.ReplaceAll(v, "zeus.lan", "h-0123456789ab"), true
	}
	return v, false
}

// Re-serialization must at least be deterministic: the same input has to
// produce the same bytes every time, or every request differs from the last.
func TestWalk_ReserializationIsDeterministic(t *testing.T) {
	body := []byte(`{"zeta":"zeus.lan","alpha":1,"mid":{"z":"x","a":"y"},"beta":[{"q":1,"b":2}]}`)
	var first string
	for i := 0; i < 20; i++ {
		out, changed, err := payload.Walk(body, payload.WalkOptions{}, replaceHost)
		if err != nil || !changed {
			t.Fatalf("Walk: err=%v changed=%v", err, changed)
		}
		if i == 0 {
			first = string(out)
			continue
		}
		if string(out) != first {
			t.Fatalf("run %d differs:\n got %s\nfirst %s", i, out, first)
		}
	}
	t.Logf("stable output: %s", first)
	if strings.Index(first, `"alpha"`) > strings.Index(first, `"zeta"`) {
		t.Logf("key order preserved")
	} else {
		t.Logf("KEY ORDER CHANGED: input started with \"zeta\", output starts with %.20s", first)
	}
}

// Bytes after the closing brace: white space is kept whether or not
// something changes, anything else is not a JSON document and is refused
// before the visitor runs.
func TestWalk_TrailingBytesAfterObject(t *testing.T) {
	cases := []string{
		`{"a":"zeus.lan"}trailing`,
		`{"a":"zeus.lan"} `,
		`{"a":"zeus.lan"}` + "\n",
		`{"a":"zeus.lan"}{"b":"second"}`,
	}
	for _, body := range cases {
		out, changed, err := payload.Walk([]byte(body), payload.WalkOptions{}, replaceHost)
		if err != nil {
			t.Logf("%-32q -> err=%v", body, err)
			continue
		}
		lost := !strings.HasSuffix(string(out), strings.TrimPrefix(body, `{"a":"zeus.lan"}`))
		t.Logf("%-32q -> changed=%v out=%q trailing lost=%v", body, changed, string(out), lost)
		if changed && lost {
			t.Errorf("replacement dropped the bytes after the object: %q became %q", body, out)
		}
	}
}

// The same question for ReplaceStrings, which is what the forward path calls.
func TestReplaceStrings_TrailingBytes(t *testing.T) {
	body := []byte(`{"a":"zeus.lan"}trailing`)
	out, n, err := payload.ReplaceStrings(body, payload.DefaultDeny(), replaceHost)
	t.Logf("out=%q replaced=%d err=%v", string(out), n, err)
	if err == nil && n > 0 && !strings.HasSuffix(string(out), "trailing") {
		t.Errorf("ReplaceStrings dropped trailing bytes: %q", out)
	}
}
