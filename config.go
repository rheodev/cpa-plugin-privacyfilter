package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privacyfilter/filter"

	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "privacyfilter"
const pluginName = "privacyfilter"

// Mode selects the replacement strategy on the forward path. ModeRedact is
// the default and reproduces the original plugin's behaviour byte for byte;
// ModePseudonymize switches to reversible pseudonyms and enables the return
// path. See umbauplan.md, chapter "Verhältnis zum Original".
type Mode string

const (
	ModeRedact       Mode = "redact"
	ModePseudonymize Mode = "pseudonymize"
)

// OnError selects the forward-path behaviour when detection or JSON parsing
// fails. OnErrorBlock, the default, terminates the request via Terminate;
// OnErrorPassthrough forwards the body unfiltered. The return path always
// passes through on error, regardless of this setting.
type OnError string

const (
	OnErrorBlock       OnError = "block"
	OnErrorPassthrough OnError = "passthrough"
)

// TermEntry is one entry of the terms[] configuration list: a literal or a
// regular expression, together with the kind its hits are rendered as.
//
// TermEntry mirrors detect.Term field for field, but config.go must not
// import package detect, so Kind stays a plain string here instead of
// detect.Kind. The integrator that wires this plugin to the detect package
// converts each TermEntry into a detect.Term when building the detector
// (Kind string into detect.Kind); detect.NewTerms itself rejects an unknown
// kind, an empty term, or a term with both Value and Regex set, so this
// package only rejects a term with neither or both, see validate.
type TermEntry struct {
	// Value is a literal to look for. Exactly one of Value and Regex is set.
	Value string `yaml:"value"`
	// Regex is a Go regular expression (RE2 syntax). Exactly one of Value and
	// Regex is set.
	Regex string `yaml:"regex"`
	// Kind names the kind assigned to every hit of this term, for example
	// "host", "domain", "cidr" or "person". It maps to detect.Kind.
	Kind string `yaml:"kind"`
	// IgnoreCase makes a literal match regardless of letter case. It has no
	// effect on Regex; write (?i) there instead.
	IgnoreCase bool `yaml:"ignore_case"`
}

// validate checks the one rule config.go can check without package detect:
// exactly one of Value and Regex is set. The kind is checked at registration.
func (t TermEntry) validate() error {
	hasValue := t.Value != ""
	hasRegex := t.Regex != ""
	switch {
	case hasValue && hasRegex:
		return fmt.Errorf("exactly one of value or regex must be set, got both")
	case !hasValue && !hasRegex:
		return fmt.Errorf("exactly one of value or regex must be set, got neither")
	}
	return nil
}

// PatternFlags switches the structural detectors on and off, one category at
// a time. It mirrors detect.PatternsConfig field for field; the integrator
// maps it into that struct because config.go must not import package detect.
type PatternFlags struct {
	IPv4  bool `yaml:"ipv4"`
	IPv6  bool `yaml:"ipv6"`
	CIDR  bool `yaml:"cidr"`
	MAC   bool `yaml:"mac"`
	Email bool `yaml:"email"`
	IBAN  bool `yaml:"iban"`
	// URL is off by default until path pseudonyms exist; see the plan,
	// milestone 3.
	URL bool `yaml:"url"`
	// The machine identifiers, all on by default: UUIDs, bare hex ids
	// (machine-id, WWN), SSH key fingerprints and labelled serial numbers.
	UUID        bool `yaml:"uuid"`
	HexID       bool `yaml:"hexid"`
	Fingerprint bool `yaml:"fingerprint"`
	Serial      bool `yaml:"serial"`
}

// AuditConfig switches the local audit log of pseudonymize mode, see
// audit.go. Path empty means off. The file receives every mapping table in
// clear text, so it is a diagnostic to switch on for a check and off again.
type AuditConfig struct {
	// Path of the audit file. A relative path resolves next to the plugin's
	// shared object, like terms_file.
	Path string `yaml:"path"`
	// MaxBytes rotates the file to ".1" once it is larger than this. Zero
	// means the default of 10 MiB.
	MaxBytes int64 `yaml:"max_bytes"`
}

// PathConfig configures segment-wise path pseudonymization; see
// umbauplan.md, chapter "Pfade segmentweise". Enabled defaults to false
// until the stream restore has been confirmed on the live system, because
// a half-restored path in a tool call does more harm than a leaked one.
type PathConfig struct {
	Enabled bool `yaml:"enabled"`
	// ReplaceUnknown, when true, replaces every path segment outside the
	// built-in preserve list. When false, only segments that also appear in
	// the term list are replaced.
	ReplaceUnknown bool `yaml:"replace_unknown"`
	// Preserve adds to the built-in list of ordinary path segments that are
	// never replaced (home, usr, etc, var, ...). The built-in list itself is
	// maintained by the integrator, not here.
	Preserve []string `yaml:"preserve"`
	// Filenames decides what happens to the last segment of a path when it
	// has a file extension. PathFilenamesTerms, the default, leaves it to
	// the term layer: a file name is replaced only where a term matches
	// inside it. PathFilenamesAll replaces every file name outside the
	// preserve list, like a directory.
	Filenames string `yaml:"filenames"`
}

// PackymeConfig switches the packyme/privacy-filter detection layer.
type PackymeConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SecretsConfig switches the betterleaks detection layer. It has an effect
// only in binaries built with the betterleaks build tag; ValidationOptions
// stays disabled regardless of this setting, see umbauplan.md, chapter
// "betterleaks".
type SecretsConfig struct {
	Enabled bool `yaml:"enabled"`
	// RulesTOML is an optional path to custom gitleaks-style rules loaded by
	// betterleaks; empty uses its built-in rules.
	RulesTOML string `yaml:"rules_toml"`
}

// RestoreConfig configures the return path.
type RestoreConfig struct {
	// Stream enables pseudonym restoration for streamed responses. The
	// non-streamed response is always restored in pseudonymize mode; this
	// flag only affects InterceptStreamChunk.
	Stream bool `yaml:"stream"`
}

// LimitsConfig bounds body size and mapping table lifetime.
type LimitsConfig struct {
	// MaxBodyBytes rejects request bodies larger than this many bytes.
	MaxBodyBytes int `yaml:"max_body_bytes"`
	// MappingTTL is a Go duration string, for example "30m". It is measured
	// from the last use of a conversation's table; every request, response
	// and stream chunk counts, so a running conversation keeps its table
	// and a quiet one loses it after this time. validate parses it with
	// time.ParseDuration and rejects the config if it does not parse; the
	// integrator can then parse it again without an error check.
	MappingTTL string `yaml:"mapping_ttl"`
}

type privacyFilterConfig struct {
	GitleaksTOML string   `yaml:"gitleaks_toml"`
	SkipModels   []string `yaml:"skip_models"`
	SkipFormats  []string `yaml:"skip_formats"`
	// Replacement and ReplacementLabels are the labels of redact mode, as
	// in the original plugin: one label for every finding, or one per
	// entity type of the library, which take precedence. Their types refuse
	// what YAML would otherwise coerce into a string, a number or a boolean,
	// and an empty label; an absent or null key leaves the built-in labels.
	// Pseudonymize mode reads the library's findings, not its rendering, so
	// the labels have no effect there.
	Replacement       replacementLabel  `yaml:"replacement"`
	ReplacementLabels replacementLabels `yaml:"replacement_labels"`

	// RawMode backs the Mode accessor below. The field cannot be named Mode
	// itself: Go does not allow a method and a field of the same name on the
	// same type, and the plan requires an accessor named cfg.Mode().
	RawMode Mode `yaml:"mode"`
	// SaltSecretPath is the configured value of salt_secret_path. Empty means
	// the default file name (pseudo.DefaultSecretFile, "pseudonym.secret")
	// resolved next to the plugin's shared object; a relative value is
	// resolved the same way gitleaks_toml is today. Resolution itself is the
	// integrator's job (pseudo.ResolveSecretPath), config.go only carries the
	// raw string so it stays free of a pseudo import.
	SaltSecretPath string `yaml:"salt_secret_path"`

	// Terms decodes the terms[] list, see TermEntry.
	Terms []TermEntry `yaml:"terms"`
	// TermsFile is an optional path to a file with further entries, one per
	// line; see termsfile.go for the format. A relative path resolves next to
	// the plugin's shared object. Entries from the file are appended to Terms
	// at registration.
	TermsFile string `yaml:"terms_file"`
	// Patterns decodes the patterns block, see PatternFlags.
	Patterns PatternFlags `yaml:"patterns"`
	// Path decodes the path block, see PathConfig.
	Path PathConfig `yaml:"path"`
	// Packyme decodes the packyme block, see PackymeConfig.
	Packyme PackymeConfig `yaml:"packyme"`
	// Secrets decodes the secrets block, see SecretsConfig.
	Secrets SecretsConfig `yaml:"secrets"`
	// Restore decodes the restore block, see RestoreConfig.
	Restore RestoreConfig `yaml:"restore"`
	// Limits decodes the limits block, see LimitsConfig.
	Limits LimitsConfig `yaml:"limits"`
	// Audit decodes the audit block, see AuditConfig.
	Audit AuditConfig `yaml:"audit"`

	// OnError is the configured forward-path error behaviour. Unlike Mode it
	// needs no accessor method, so the field keeps the schema's name.
	OnError OnError `yaml:"on_error"`
}

// replacementLabel prevents YAML's string decoder from coercing booleans and
// numbers into labels. A null field is left unset by the YAML decoder.
type replacementLabel string

func (label *replacementLabel) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("replacement label must be a string")
	}
	if strings.TrimSpace(node.Value) == "" {
		return fmt.Errorf("replacement label must not be empty or whitespace-only")
	}
	*label = replacementLabel(node.Value)
	return nil
}

type replacementLabels map[string]string

func (labels *replacementLabels) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("replacement_labels must be a mapping")
	}
	if len(node.Content) == 0 {
		return nil
	}
	values := make(map[string]string, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("replacement_labels keys must be strings")
		}
		if key.Value == "" || strings.TrimSpace(key.Value) != key.Value {
			return fmt.Errorf("replacement_labels key %q must be nonempty without edge whitespace", key.Value)
		}
		if _, exists := values[key.Value]; exists {
			return fmt.Errorf("duplicate replacement_labels key %q", key.Value)
		}
		var label replacementLabel
		if err := label.UnmarshalYAML(value); err != nil {
			return fmt.Errorf("replacement_labels[%q]: %w", key.Value, err)
		}
		values[key.Value] = string(label)
	}
	*labels = values
	return nil
}

// defaultConfig returns the configuration that applies when a key is absent
// from the YAML document. Every default below matches umbauplan.md, chapter
// "Konfiguration"; mode: redact and the unset new blocks together reproduce
// the original plugin's behaviour exactly, since parseConfig only changes
// forward-path behaviour when mode is pseudonymize.
func defaultConfig() privacyFilterConfig {
	return privacyFilterConfig{
		RawMode: ModeRedact,
		Patterns: PatternFlags{
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
		},
		Path: PathConfig{
			Enabled:        false,
			ReplaceUnknown: true,
			Filenames:      PathFilenamesTerms,
		},
		Packyme: PackymeConfig{
			Enabled: true,
		},
		Secrets: SecretsConfig{
			Enabled: false,
		},
		Restore: RestoreConfig{
			Stream: true,
		},
		Limits: LimitsConfig{
			MaxBodyBytes: 33554432,
			MappingTTL:   "30m",
		},
		OnError: OnErrorBlock,
	}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
		}
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Values of path.filenames.
const (
	PathFilenamesTerms = "terms"
	PathFilenamesAll   = "all"
)

// validate rejects a configuration parseConfig must not hand to the rest of
// the plugin. It checks only what config.go itself owns: the two enums, and
// the shape of a term entry. Everything with a dedicated constructor
// downstream (an unknown Kind, an invalid regex, a malformed CIDR, ...) is
// validated there instead, so this function does not import those packages.
func (cfg *privacyFilterConfig) validate() error {
	switch cfg.RawMode {
	case ModeRedact, ModePseudonymize:
	default:
		return fmt.Errorf("privacyfilter: invalid mode %q, want %q or %q", cfg.RawMode, ModeRedact, ModePseudonymize)
	}

	switch cfg.OnError {
	case OnErrorBlock, OnErrorPassthrough:
	default:
		return fmt.Errorf("privacyfilter: invalid on_error %q, want %q or %q", cfg.OnError, OnErrorBlock, OnErrorPassthrough)
	}

	switch cfg.Path.Filenames {
	case PathFilenamesTerms, PathFilenamesAll:
	default:
		return fmt.Errorf("privacyfilter: invalid path.filenames %q, want %q or %q", cfg.Path.Filenames, PathFilenamesTerms, PathFilenamesAll)
	}

	for i, t := range cfg.Terms {
		if err := t.validate(); err != nil {
			return fmt.Errorf("privacyfilter: terms[%d]: %w", i, err)
		}
	}

	if _, err := time.ParseDuration(cfg.Limits.MappingTTL); err != nil {
		return fmt.Errorf("privacyfilter: invalid limits.mapping_ttl %q: %w", cfg.Limits.MappingTTL, err)
	}

	return nil
}

// Mode returns the configured replacement mode. After a parseConfig call
// that returned a nil error, it is always ModeRedact or ModePseudonymize.
func (cfg *privacyFilterConfig) Mode() Mode {
	return cfg.RawMode
}

// IsPseudonymize reports whether Mode is ModePseudonymize. It is a
// convenience for the common branch: `if cfg.IsPseudonymize() { ... }`.
func (cfg *privacyFilterConfig) IsPseudonymize() bool {
	return cfg.RawMode == ModePseudonymize
}

// resolveGitleaksPath resolves the configured gitleaks rule file. The return is
// split into a path (may be empty) and an embedded flag: when the path is empty
// and embedded is true, the caller should load the rules baked into the binary.
func (cfg *privacyFilterConfig) resolveGitleaksPath(pluginDir string) (path string, embedded bool) {
	if cfg.GitleaksTOML == "" {
		builtin := filepath.Join(pluginDir, "rules", "gitleaks.toml")
		if _, err := os.Stat(builtin); err == nil {
			return builtin, false
		}
		// No sidecar file: fall back to the rules compiled into the binary.
		return "", true
	}
	if filepath.IsAbs(cfg.GitleaksTOML) {
		return cfg.GitleaksTOML, false
	}
	return filepath.Join(pluginDir, cfg.GitleaksTOML), false
}

func (cfg *privacyFilterConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		trimmed := strings.TrimSpace(m)
		if strings.EqualFold(trimmed, model) || strings.EqualFold(trimmed, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

func newFilter(pluginDir string, cfg privacyFilterConfig) (*filter.Filter, error) {
	tomlPath, embedded := cfg.resolveGitleaksPath(pluginDir)

	// The filter loads its rules from a file path. When no sidecar file is
	// present (the common case for store installs), materialize the embedded
	// rules into a temporary file. Compiled rules live in memory, so the temp
	// file is removed right after the filter is constructed.
	if embedded {
		tmp, errTmp := os.CreateTemp("", "privacyfilter-gitleaks-*.toml")
		if errTmp != nil {
			return nil, fmt.Errorf("create temp rules file: %w", errTmp)
		}
		tmpPath := tmp.Name()
		if _, errWrite := tmp.Write(embeddedGitleaks); errWrite != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return nil, fmt.Errorf("write temp rules file: %w", errWrite)
		}
		if errClose := tmp.Close(); errClose != nil {
			os.Remove(tmpPath)
			return nil, fmt.Errorf("close temp rules file: %w", errClose)
		}
		defer func() { _ = os.Remove(tmpPath) }()
		tomlPath = tmpPath
	}

	f, err := filter.New(tomlPath, filter.Config{
		Replacement:       string(cfg.Replacement),
		ReplacementLabels: map[string]string(cfg.ReplacementLabels),
	})
	if err != nil {
		var source string
		switch {
		case embedded:
			source = "embedded rules"
		case cfg.GitleaksTOML != "":
			source = fmt.Sprintf("gitleaks_toml %q", tomlPath)
		default:
			source = fmt.Sprintf("sidecar rules file %q", tomlPath)
		}
		return nil, fmt.Errorf("failed to create privacy filter from %s: %w", source, err)
	}
	rules, skipped := f.Stats()
	pluginLog(context.Background(), logLevelInfo, fmt.Sprintf("privacy filter loaded: %d rules, %d skipped", rules, skipped), map[string]any{
		"rules":         rules,
		"skipped_rules": skipped,
	})
	return f, nil
}
