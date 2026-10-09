package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseConfig_Defaults(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatalf("parseConfig(nil) error = %v", err)
	}

	if got := cfg.Mode(); got != ModeRedact {
		t.Fatalf("Mode() = %q, want %q", got, ModeRedact)
	}
	if cfg.IsPseudonymize() {
		t.Fatal("IsPseudonymize() = true, want false for default config")
	}
	if cfg.SaltSecretPath != "" {
		t.Fatalf("SaltSecretPath = %q, want empty", cfg.SaltSecretPath)
	}
	if len(cfg.Terms) != 0 {
		t.Fatalf("Terms = %v, want empty", cfg.Terms)
	}

	wantPatterns := PatternFlags{
		IPv4:        true,
		IPv6:        true,
		CIDR:        true,
		MAC:         true,
		Email:       true,
		IBAN:        true,
		URL:         false,
		UUID:        true,
		HexID:       true,
		Fingerprint: true,
		Serial:      true,
	}
	if cfg.Patterns != wantPatterns {
		t.Fatalf("Patterns = %+v, want %+v", cfg.Patterns, wantPatterns)
	}

	if cfg.Path.Enabled {
		t.Fatal("Path.Enabled = true, want false")
	}
	if !cfg.Path.ReplaceUnknown {
		t.Fatal("Path.ReplaceUnknown = false, want true")
	}
	if len(cfg.Path.Preserve) != 0 {
		t.Fatalf("Path.Preserve = %v, want empty", cfg.Path.Preserve)
	}
	if cfg.Path.Filenames != PathFilenamesTerms {
		t.Fatalf("Path.Filenames = %q, want %q", cfg.Path.Filenames, PathFilenamesTerms)
	}

	if !cfg.Packyme.Enabled {
		t.Fatal("Packyme.Enabled = false, want true")
	}

	if cfg.Secrets.Enabled {
		t.Fatal("Secrets.Enabled = true, want false")
	}
	if cfg.Secrets.RulesTOML != "" {
		t.Fatalf("Secrets.RulesTOML = %q, want empty", cfg.Secrets.RulesTOML)
	}

	if !cfg.Restore.Stream {
		t.Fatal("Restore.Stream = false, want true")
	}

	if cfg.Limits.MaxBodyBytes != 33554432 {
		t.Fatalf("Limits.MaxBodyBytes = %d, want 33554432", cfg.Limits.MaxBodyBytes)
	}
	if cfg.Limits.MappingTTL != "30m" {
		t.Fatalf("Limits.MappingTTL = %q, want \"30m\"", cfg.Limits.MappingTTL)
	}
	if d, err := time.ParseDuration(cfg.Limits.MappingTTL); err != nil || d != 30*time.Minute {
		t.Fatalf("time.ParseDuration(Limits.MappingTTL) = %v, %v, want 30m, nil", d, err)
	}

	if got := cfg.OnError; got != OnErrorBlock {
		t.Fatalf("OnError = %q, want %q", got, OnErrorBlock)
	}

	// Defaulting must not touch the three pre-existing keys.
	if cfg.GitleaksTOML != "" {
		t.Fatalf("GitleaksTOML = %q, want empty", cfg.GitleaksTOML)
	}
	if len(cfg.SkipModels) != 0 {
		t.Fatalf("SkipModels = %v, want empty", cfg.SkipModels)
	}
	if len(cfg.SkipFormats) != 0 {
		t.Fatalf("SkipFormats = %v, want empty", cfg.SkipFormats)
	}
}

func TestParseConfig_EmptyInputEqualsNilInput(t *testing.T) {
	cfg, err := parseConfig([]byte("   \n"))
	if err != nil {
		t.Fatalf("parseConfig(whitespace) error = %v", err)
	}
	if cfg.Mode() != ModeRedact {
		t.Fatalf("Mode() = %q, want %q", cfg.Mode(), ModeRedact)
	}
}

func TestParseConfig_ExistingThreeKeysUnchanged(t *testing.T) {
	raw := `
skip_models:
  - gpt-4
skip_formats:
  - openai
`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	if len(cfg.SkipModels) != 1 || cfg.SkipModels[0] != "gpt-4" {
		t.Fatalf("skip_models = %v, want [gpt-4]", cfg.SkipModels)
	}
	if len(cfg.SkipFormats) != 1 || cfg.SkipFormats[0] != "openai" {
		t.Fatalf("skip_formats = %v, want [openai]", cfg.SkipFormats)
	}
	// Untouched keys keep their defaults even though the document is not empty.
	if cfg.Mode() != ModeRedact {
		t.Fatalf("Mode() = %q, want %q", cfg.Mode(), ModeRedact)
	}
	if !cfg.Packyme.Enabled {
		t.Fatal("Packyme.Enabled = false, want true (default should survive a partial document)")
	}
	if cfg.Limits.MaxBodyBytes != 33554432 {
		t.Fatalf("Limits.MaxBodyBytes = %d, want 33554432 (default should survive a partial document)", cfg.Limits.MaxBodyBytes)
	}
}

func TestParseConfig_FullPseudonymizeBlock(t *testing.T) {
	raw := `
enabled: true
priority: 100
mode: pseudonymize
salt_secret_path: pseudonym.secret
skip_models: []
skip_formats: []
terms:
  - {value: "athene.lan", kind: host}
  - {value: "10.13.0.0/16", kind: cidr}
  - {value: "Ingrid Muster", kind: person}
  - {regex: 'helios-[a-z]+-\d+', kind: host}
patterns:
  ipv4: true
  ipv6: true
  cidr: true
  mac: true
  email: true
  iban: true
  url: false
path:
  enabled: false
  replace_unknown: true
  preserve: []
  filenames: all
packyme:
  enabled: true
secrets:
  enabled: false
  rules_toml: ""
restore:
  stream: true
limits:
  max_body_bytes: 33554432
  mapping_ttl: 10m
on_error: block
`
	cfg, err := parseConfig([]byte(raw))
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}

	if !cfg.IsPseudonymize() {
		t.Fatal("IsPseudonymize() = false, want true")
	}
	if cfg.SaltSecretPath != "pseudonym.secret" {
		t.Fatalf("SaltSecretPath = %q, want \"pseudonym.secret\"", cfg.SaltSecretPath)
	}

	if len(cfg.Terms) != 4 {
		t.Fatalf("len(Terms) = %d, want 4", len(cfg.Terms))
	}
	wantTerms := []TermEntry{
		{Value: "athene.lan", Kind: "host"},
		{Value: "10.13.0.0/16", Kind: "cidr"},
		{Value: "Ingrid Muster", Kind: "person"},
		{Regex: `helios-[a-z]+-\d+`, Kind: "host"},
	}
	for i, want := range wantTerms {
		got := cfg.Terms[i]
		if got != want {
			t.Fatalf("Terms[%d] = %+v, want %+v", i, got, want)
		}
	}

	if cfg.OnError != OnErrorBlock {
		t.Fatalf("OnError = %q, want %q", cfg.OnError, OnErrorBlock)
	}
	if cfg.Limits.MappingTTL != "10m" {
		t.Fatalf("Limits.MappingTTL = %q, want \"10m\"", cfg.Limits.MappingTTL)
	}
}

func TestParseConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name:    "unknown mode",
			raw:     "mode: shred\n",
			wantErr: "invalid mode",
		},
		{
			name:    "unknown on_error",
			raw:     "on_error: ignore\n",
			wantErr: "invalid on_error",
		},
		{
			name: "term with neither value nor regex",
			raw: `
terms:
  - {kind: host}
`,
			wantErr: "got neither",
		},
		{
			name: "term with both value and regex",
			raw: `
terms:
  - {value: "athene.lan", regex: "a.*", kind: host}
`,
			wantErr: "got both",
		},
		{
			name:    "unknown path.filenames",
			raw:     "path:\n  filenames: some\n",
			wantErr: "invalid path.filenames",
		},
		{
			name:    "mapping_ttl does not parse as a duration",
			raw:     "limits:\n  mapping_ttl: \"not-a-duration\"\n",
			wantErr: "mapping_ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig([]byte(tt.raw))
			if err == nil {
				t.Fatal("parseConfig() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseConfig() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfigShouldSkip_StillWorks(t *testing.T) {
	cfg := defaultConfig()
	cfg.SkipModels = []string{"gpt-4", "claude-3"}
	cfg.SkipFormats = []string{"openai"}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "anthropic") {
		t.Fatal("should not skip unknown model/format")
	}
}
