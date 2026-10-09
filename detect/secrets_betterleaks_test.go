//go:build betterleaks

package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
)

func TestSecrets_FindsToken(t *testing.T) {
	d, err := detect.NewSecrets(detect.SecretsConfig{})
	if err != nil {
		t.Fatalf("NewSecrets: %v", err)
	}
	if d.Name() != "betterleaks" {
		t.Fatalf("Name = %q", d.Name())
	}
	token := fixtures.FakeToken()
	text := "export GITHUB_TOKEN=" + token + " # und nochmal " + token + " am Ende"
	got := d.Scan(text)
	assertDisjointSorted(t, text, got)
	if len(got) != 2 {
		t.Fatalf("Scan = %+v, want the token twice", got)
	}
	for _, m := range got {
		if m.Kind != detect.KindSecret || m.Value != token || m.Source != "betterleaks" {
			t.Fatalf("match = %+v", m)
		}
	}
	if got := d.Scan(fixtures.Benign); len(got) != 0 {
		t.Fatalf("benign text produced %+v", got)
	}
}

func TestSecrets_BadRulesFileIsAnError(t *testing.T) {
	_, err := detect.NewSecrets(detect.SecretsConfig{RulesTOML: "/nonexistent/rules.toml"})
	if err == nil || !strings.Contains(err.Error(), "betterleaks rules") {
		t.Fatalf("NewSecrets with a missing rules file = %v, want an error", err)
	}
}
