//go:build betterleaks

package detect

import (
	"context"
	"fmt"
	"strings"

	"github.com/betterleaks/betterleaks/config"
	bldetect "github.com/betterleaks/betterleaks/detect"
)

// secretsDetector is the betterleaks-backed credential scanner. The
// detector is built once at registration and shared by every request;
// betterleaks scans fragments concurrently in its own CLI, so DetectString
// is safe to call from several requests at once.
type secretsDetector struct {
	d *bldetect.Detector
}

var _ Detector = (*secretsDetector)(nil)

// newSecrets loads the rules, compiles what the constructor would compile
// and builds the detector with validation switched off.
//
// The compile steps run here first because betterleaks' constructor ends
// the process on a compile error instead of returning it, and a plugin must
// never take the proxy down over a bad rules file. Both steps are
// idempotent, so the constructor repeating them costs nothing.
func newSecrets(cfg SecretsConfig) (Detector, error) {
	var (
		c   *config.Config
		err error
	)
	if cfg.RulesTOML != "" {
		c, err = config.LoadFile(cfg.RulesTOML)
	} else {
		c, err = config.Default()
	}
	if err != nil {
		return nil, fmt.Errorf("detect: betterleaks rules: %w", err)
	}
	if err := c.CompileFilters(nil); err != nil {
		return nil, fmt.Errorf("detect: betterleaks filters: %w", err)
	}
	if _, err := c.CompileValidation(); err != nil {
		return nil, fmt.Errorf("detect: betterleaks validation expressions: %w", err)
	}
	// Enabled stays false in every build: validation sends the credentials
	// it found to their providers over HTTP, which is the one thing this
	// plugin exists to prevent.
	d := bldetect.NewDetectorContext(context.Background(), c, bldetect.ValidationOptions{Enabled: false})
	if d == nil {
		return nil, fmt.Errorf("detect: betterleaks detector could not be built")
	}
	return &secretsDetector{d: d}, nil
}

// Name implements Detector.
func (s *secretsDetector) Name() string { return "betterleaks" }

// Scan implements Detector. Only the Secret of a finding is used; where
// betterleaks reports no separate secret, the whole match is. The span is
// found by a literal search, every occurrence reported, because the
// finding carries line and column but no byte offsets.
func (s *secretsDetector) Scan(text string) []Match {
	if text == "" {
		return nil
	}
	findings := s.d.DetectString(text)
	if len(findings) == 0 {
		return nil
	}
	var out []Match
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		secret := f.Secret
		if secret == "" {
			secret = f.Match
		}
		if secret == "" || seen[secret] {
			continue
		}
		seen[secret] = true
		for off := 0; off < len(text); {
			i := strings.Index(text[off:], secret)
			if i < 0 {
				break
			}
			start, end := off+i, off+i+len(secret)
			if spanAligned(text, start, end) {
				out = append(out, Match{Start: start, End: end, Value: secret, Kind: KindSecret, Source: "betterleaks"})
			}
			off = end
		}
	}
	return out
}
