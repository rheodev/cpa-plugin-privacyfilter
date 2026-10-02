package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func TestSegmentTokens(t *testing.T) {
	customer := "kunde-x"
	cases := map[string]string{
		"mkdir -p hallo/unter && echo fertig.": "mkdir -p hallo unter echo fertig",
		"cat ~/" + customer + "/notes.md":      "cat ~ " + customer + " notes.md",
		"mail@example.org (x) 192.0.2.1":       "mail@example.org x 192.0.2.1",
		"":                                     "",
		"... /// ()":                           "",
		"Ärger im Büro":                        "Ärger im Büro",
		"[x](../Kunden%20Akten/notes.md)":      "x Kunden Akten notes.md", // the encoded space divides like a real one
		"%20a%20%20b":                          "a b",
	}
	for text, want := range cases {
		if got := strings.Join(detect.SegmentTokens(text), " "); got != want {
			t.Errorf("SegmentTokens(%q) = %q, want %q", text, got, want)
		}
	}
}
