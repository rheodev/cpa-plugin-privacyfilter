package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"privacyfilter/filter"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "privacyfilter"
const pluginName = "privacyfilter"

type privacyFilterConfig struct {
	GitleaksTOML string   `yaml:"gitleaks_toml"`
	SkipModels   []string `yaml:"skip_models"`
	SkipFormats  []string `yaml:"skip_formats"`
}

func defaultConfig() privacyFilterConfig {
	return privacyFilterConfig{}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
		}
	}
	return cfg, nil
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

	f, err := filter.New(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create privacy filter: %w", err)
	}
	rules, skipped := f.Stats()
	log.Infof("privacy filter loaded: %d rules, %d skipped", rules, skipped)
	return f, nil
}
