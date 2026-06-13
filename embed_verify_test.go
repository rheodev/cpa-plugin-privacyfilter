package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewFilter_UsesEmbeddedRules simulates a store install: an empty plugin
// directory with no rules/gitleaks.toml sidecar. newFilter must still load the
// embedded rules (loaded rules > 0), proving the filter works without a sidecar.
func TestNewFilter_UsesEmbeddedRules(t *testing.T) {
	emptyDir := t.TempDir()

	f, err := newFilter(emptyDir, defaultConfig())
	if err != nil {
		t.Fatalf("newFilter() with embedded rules error = %v", err)
	}
	rules, _ := f.Stats()
	if rules == 0 {
		t.Fatal("expected embedded rules to be loaded, got 0 rules")
	}
	t.Logf("loaded %d embedded rules without sidecar file", rules)

	// Temp files written during materialization must be cleaned up.
	matches, err := filepath.Glob(filepath.Join(os.TempDir(), "privacyfilter-gitleaks-*.toml"))
	if err != nil {
		t.Fatalf("glob temp rules: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp rules file was not cleaned up: %v", matches)
	}
}
