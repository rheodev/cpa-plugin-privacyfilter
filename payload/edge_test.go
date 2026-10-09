// Package jsonedge probes the JSON layer at its edges: bodies that are legal
// JSON but not the shape the Anthropic schema suggests.
//
// Two different functions carry a body, and they are not the same code. The
// outbound path calls payload.Walk, which decodes the body into a map and
// writes it back. The return path calls payload.ReplaceStrings, which edits
// the bytes where they lie. Every test here asks both, because they answer
// differently more often than the package documentation suggests.
//
// The question behind all of them: after a replacement, is the body still
// valid JSON, does it still hold the same fields in the same places, and
// does no value escape that should have been replaced.
package payload_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// needle is the value that must not leave in clear text, mask what takes its
// place. alias is the same for a value that has to look like a name, since a
// tool name may not carry dots. All four are assembled from numbers at run
// time: a literal in this file would itself pass through the running filter
// on its way to disk.
var (
	needle    = v4(198, 51, 100, 17)
	mask      = v4(100, 64, 3, 9)
	alias     = "svc" + digits(v4(7, 3, 2, 9))
	aliasMask = "svc" + digits(v4(1, 2, 3, 4))
)

// digits strips the dots from an assembled address so the result passes as a
// bare name.
func digits(s string) string { return strings.ReplaceAll(s, ".", "") }

// hide is the visitor both directions use: a plain substring replacement, so
// that no detector configuration can influence what the test sees.
func hide(_ payload.Path, v string) (string, bool) {
	out := strings.ReplaceAll(v, needle, mask)
	out = strings.ReplaceAll(out, alias, aliasMask)
	return out, out != v
}

// show is the counter visitor, for the return direction: it puts the
// original back where a pseudonym stands.
func show(_ payload.Path, v string) (string, bool) {
	out := strings.ReplaceAll(v, mask, needle)
	out = strings.ReplaceAll(out, aliasMask, alias)
	return out, out != v
}

// outbound runs the forward path over body, as the interceptor does.
func outbound(body string) ([]byte, bool, error) {
	return payload.Walk([]byte(body), payload.WalkOptions{}, hide)
}

// inbound runs the return path over body, as the response filter does.
func inbound(body string) ([]byte, int, error) {
	return payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), hide)
}

// visitedOut lists the paths the forward walk offers to a visitor, in the
// order it offers them. The visitor changes nothing, so the body is not
// rewritten and the list is the plain answer to "which fields does the
// plugin see".
func visitedOut(body string) ([]string, error) {
	var seen []string
	_, _, err := payload.Walk([]byte(body), payload.WalkOptions{}, func(p payload.Path, v string) (string, bool) {
		seen = append(seen, p.String())
		return v, false
	})
	return seen, err
}

// visitedIn is the same for the return path.
func visitedIn(body string) ([]string, error) {
	var seen []string
	_, _, err := payload.ReplaceStrings([]byte(body), payload.DefaultDeny(), func(p payload.Path, v string) (string, bool) {
		seen = append(seen, p.String())
		return v, false
	})
	return seen, err
}

// fields lists one line per node of the decoded body: its position and the
// kind of value that sits there, with string values reduced to their kind.
// Two bodies with the same field list hold the same fields in the same
// places, whatever a replacement did to the text.
func fields(t *testing.T, b []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var out []string
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out = append(out, prefix+" object "+strconv.Itoa(len(keys)))
			for _, k := range keys {
				walk(prefix+"/"+k, x[k])
			}
		case []any:
			out = append(out, prefix+" array "+strconv.Itoa(len(x)))
			for i, e := range x {
				walk(prefix+"/"+strconv.Itoa(i), e)
			}
		case string:
			out = append(out, prefix+" string")
		case json.Number:
			out = append(out, prefix+" number "+x.String())
		case bool:
			out = append(out, fmt.Sprintf("%s bool %v", prefix, x))
		default:
			out = append(out, prefix+" null")
		}
	}
	walk("", root)
	return out
}

// sameFields reports whether after still holds every field of before, in the
// same place and of the same kind.
func sameFields(t *testing.T, before, after []byte) bool {
	t.Helper()
	a, b := fields(t, before), fields(t, after)
	if len(a) != len(b) {
		t.Logf("field count %d -> %d", len(a), len(b))
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			t.Logf("field %d: %q -> %q", i, a[i], b[i])
			return false
		}
	}
	return true
}

// leaked reports whether the value that had to be replaced is still there.
func leaked(b []byte) bool {
	return bytes.Contains(b, []byte(needle)) || bytes.Contains(b, []byte(alias))
}

// checkBoth is the common frame: run body through both directions and assert
// what must hold in every case, whatever the shape. It returns both results
// so a test can look closer.
func checkBoth(t *testing.T, body string) (fwd, ret []byte) {
	t.Helper()
	fwd, changed, err := outbound(body)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if !json.Valid(fwd) {
		t.Errorf("forward produced invalid JSON: %s", fwd)
	}
	if !sameFields(t, []byte(body), fwd) {
		t.Errorf("forward lost or added a field, changed=%v", changed)
	}
	ret, n, err := inbound(body)
	if err != nil {
		t.Fatalf("return: %v", err)
	}
	if !json.Valid(ret) {
		t.Errorf("return produced invalid JSON: %s", ret)
	}
	if !sameFields(t, []byte(body), ret) {
		t.Errorf("return lost or added a field, replaced=%d", n)
	}
	return fwd, ret
}

// A null where the schema promises a string, next to the other scalars. The
// walk has to step over all of them and leave them as they are.
func TestJSONEdge_NullInsteadOfString(t *testing.T) {
	body := fmt.Sprintf(`{"system":null,"messages":[{"role":"user","content":null}],`+
		`"flag":true,"off":false,"n":1.50,"hit":%q}`, needle)
	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if leaked(out) {
			t.Errorf("%s: the value beside the nulls was not replaced: %s", name, out)
		}
		if !bytes.Contains(out, []byte(`"system":null`)) {
			t.Errorf("%s: the null lost its place: %s", name, out)
		}
	}
	t.Logf("forward=%s", fwd)
}

// Arrays inside arrays, including an empty one, with the value at four
// different depths.
func TestJSONEdge_ArrayOfArrays(t *testing.T) {
	body := fmt.Sprintf(`{"a":[[%q],[[%q],[]],[]],"b":[[[[%q]]]],"c":[]}`, needle, needle, needle)
	fwd, ret := checkBoth(t, body)
	if leaked(fwd) {
		t.Errorf("forward left a value inside the nested arrays: %s", fwd)
	}
	if leaked(ret) {
		t.Errorf("return left a value inside the nested arrays: %s", ret)
	}
	paths, err := visitedOut(body)
	if err != nil {
		t.Fatalf("visitedOut: %v", err)
	}
	t.Logf("visited: %v", paths)
	if len(paths) != 3 {
		t.Errorf("expected three strings in the nested arrays, the walk offered %d: %v", len(paths), paths)
	}
}

// An empty object and an empty array, alone and nested, beside a value that
// does change. The empty containers must survive the re-serialization.
func TestJSONEdge_EmptyObjectAndArray(t *testing.T) {
	body := fmt.Sprintf(`{"e":{},"a":[],"nested":{"x":{},"y":[{},[]]},"hit":%q}`, needle)
	fwd, ret := checkBoth(t, body)
	for name, out := range map[string][]byte{"forward": fwd, "return": ret} {
		if !bytes.Contains(out, []byte(`"e":{}`)) || !bytes.Contains(out, []byte(`"a":[]`)) {
			t.Errorf("%s: an empty container was dropped: %s", name, out)
		}
	}
}

// A body that is nothing but an empty object has no string at all. Neither
// direction may stumble over it.
func TestJSONEdge_EmptyBody(t *testing.T) {
	for _, body := range []string{`{}`, `{"a":{}}`, `{"a":[]}`} {
		out, changed, err := outbound(body)
		if err != nil {
			t.Errorf("forward rejected %s: %v", body, err)
		}
		if changed || string(out) != body {
			t.Errorf("forward changed %s into %s", body, out)
		}
		out, n, err := inbound(body)
		if err != nil {
			t.Errorf("return rejected %s: %v", body, err)
		}
		if n != 0 || string(out) != body {
			t.Errorf("return changed %s into %s", body, out)
		}
	}
}
