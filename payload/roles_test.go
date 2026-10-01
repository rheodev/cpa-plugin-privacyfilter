package payload_test

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

func TestRoles(t *testing.T) {
	body := []byte(`{"model":"m","messages":[` +
		`{"role":"user","content":"a"},` +
		`{"content":[{"type":"text","text":"b"}],"role":"assistant"},` +
		`"text",` +
		`{"role":5},` +
		`{}` +
		`],"system":"s"}`)
	want := []string{"user", "assistant", "", "", ""}
	got := payload.Roles(body)
	if len(got) != len(want) {
		t.Fatalf("Roles = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Roles[%d] = %q, want %q (all: %q)", i, got[i], want[i], got)
		}
	}
	for _, body := range []string{`{"system":"s"}`, `{"messages":"none"}`, `{"messages":[]}`} {
		if got := payload.Roles([]byte(body)); len(got) != 0 {
			t.Errorf("Roles(%s) = %q, want none", body, got)
		}
	}
}
