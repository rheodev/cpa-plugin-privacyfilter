package harm

// JSON on two levels. The body of the response is JSON the plugin owns: it
// decodes a string, restores inside it and encodes it again, so whatever the
// original contains cannot break the transport. The second level is JSON the
// model wrote inside such a string - a configuration file it hands to a
// writing tool, a line of output it asks a tool to parse - and there nobody
// escapes anything.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// answerBody wraps one assistant text in a Messages response, built through
// the encoder so no literal has to survive the trip to disk.
func answerBody(t *testing.T, text string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"id":   "msg_1",
		"type": "message",
		"role": "assistant",
		"content": []any{
			map[string]any{"type": "text", "text": text},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return body
}

// The control: whatever the original carries, the body the client receives
// is still valid JSON and the string it decodes to is the restored text. The
// plugin re-encodes, so the transport is never the problem.
func TestHarm_ResponseBodyStaysValidJSON(t *testing.T) {
	values := map[string]string{
		"double quote": "Firma " + quote + "Nordwind" + quote,
		"backslash":    "C:" + bs + "temp" + bs + "notes",
		"newline":      "Meier GmbH\nBahnhofstrasse 1",
		"tab":          "Kunde\tNord",
	}
	for name, value := range values {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, value)
		body := answerBody(t, "Der Pfad ist "+aliasValue+".")

		r := tab.Restorer()
		out, n, err := payload.ReplaceStrings(body, payload.DefaultDeny(), func(_ payload.Path, s string) (string, bool) {
			return r.Restore(s, false)
		})
		if err != nil {
			t.Errorf("%s: ReplaceStrings: %v", name, err)
			continue
		}
		if n != 1 {
			t.Errorf("%s: expected one string to change, got %d", name, n)
		}
		if !json.Valid(out) {
			t.Errorf("%s: the body is no longer valid JSON: %s", name, out)
			continue
		}
		var got struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Errorf("%s: Unmarshal: %v", name, err)
			continue
		}
		if len(got.Content) != 1 || !strings.Contains(got.Content[0].Text, value) {
			t.Errorf("%s: the decoded text does not carry the original: %q", name, got.Content[0].Text)
		}
	}
}

// The level the plugin does not own. The model writes a JSON document as the
// content of a file, sees a pseudonym of letters, digits and a dash and has
// no reason to escape anything. The restorer drops the original in
// unescaped, and the document the client writes to disk is a different one -
// invalid where the backslash starts no escape sequence, and valid but
// changed where it starts one that JSON knows.
func TestHarm_OriginalBreaksJSONTheModelWrote(t *testing.T) {
	skipOpenFinding(t)
	type probe struct {
		name  string
		value string
		// silent says the document still parses and yields something other
		// than the original, which is the case nothing reports.
		silent bool
	}
	probes := []probe{
		{"backslash before a known escape", "C:" + bs + "temp" + bs + "notes", true},
		{"backslash before an unknown one", "C:" + bs + "projekte", false},
		{"double quote in a name", "Firma " + quote + "Nordwind" + quote, false},
		{"newline in an address", "Meier GmbH\nBahnhofstrasse 1", false},
		{"apostrophe in a name", "Sean O'Connor", false},
	}
	for _, p := range probes {
		tab := lab.Table()
		aliasValue := tab.Lookup(detect.KindPathSegment, p.value)

		// The document as the model writes it, and as the client stores it.
		modelDoc := "{" + quote + "owner" + quote + ": " + quote + aliasValue + quote + "}"
		userDoc := lab.Back(modelDoc, tab)

		var parsed struct {
			Owner string `json:"owner"`
		}
		err := json.Unmarshal([]byte(userDoc), &parsed)
		switch {
		case err != nil:
			t.Logf("%-32s the file is not JSON any more: %v", p.name, err)
			if p.silent {
				t.Errorf("%s: expected a document that still parses, got %v", p.name, err)
			}
		case parsed.Owner != p.value:
			t.Logf("%-32s parses, and the value changed:\n   wanted %q\n   stored %q", p.name, p.value, parsed.Owner)
			t.Errorf("%s: the tool that reads this file gets %q where the user's value is %q",
				p.name, parsed.Owner, p.value)
		default:
			t.Logf("%-32s unharmed: %q", p.name, parsed.Owner)
			if !p.silent && strings.ContainsAny(p.value, quote+bs+"\n") {
				t.Errorf("%s: expected damage from %q, none happened", p.name, p.value)
			}
		}
	}
}

// The escaped form exists and is right, so the finding above is not a
// missing feature but a boundary: Restore escapes when the caller says the
// text is still in JSON string encoding, which is what the stream does for
// partial_json. A text field is not in that encoding, so its caller passes
// false, and JSON the model wrote inside that text is beyond reach.
func TestHarm_EscapedRestoreIsTheOtherCaller(t *testing.T) {
	value := "C:" + bs + "temp"
	tab := lab.Table()
	aliasValue := tab.Lookup(detect.KindPathSegment, value)
	r := tab.Restorer()

	plain, _ := r.Restore(aliasValue, false)
	escaped, _ := r.Restore(aliasValue, true)
	if plain != value {
		t.Errorf("unescaped restore changed the value: %q", plain)
	}
	if escaped == plain {
		t.Errorf("escaped and unescaped restore are the same, expected the backslash doubled: %q", escaped)
	}
	// The escaped form is exactly what a JSON string literal needs.
	var got string
	if err := json.Unmarshal([]byte(quote+escaped+quote), &got); err != nil {
		t.Errorf("the escaped form is not a JSON string body: %v", err)
	} else if got != value {
		t.Errorf("the escaped form decodes to %q, wanted %q", got, value)
	}
	t.Logf("plain %q escaped %q", plain, escaped)
}
