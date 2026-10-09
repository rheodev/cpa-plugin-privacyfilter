package detect

import "errors"

// ErrSecretsUnavailable is returned by NewSecrets when the binary was built
// without the build tag "betterleaks".
var ErrSecretsUnavailable = errors.New("detect: secret scanner not compiled in (build tag betterleaks)")

// SecretsConfig configures the optional credential scanner.
type SecretsConfig struct {
	// RulesTOML is an optional path to a rules file in gitleaks format. Empty
	// uses the scanner's built-in rules.
	RulesTOML string
}

// NewSecrets builds the credential scanner on top of betterleaks. Only the
// field Secret of each finding is used; the span is located by a literal
// search for that secret in the text, every occurrence reported. Live
// validation of findings against their providers stays disabled in every
// build, because it would send the very credentials this plugin exists to
// keep at home.
//
// Without the build tag "betterleaks" this function always returns
// ErrSecretsUnavailable, and the plugin refuses a configuration that enables
// the scanner.
func NewSecrets(cfg SecretsConfig) (Detector, error) {
	return newSecrets(cfg)
}
