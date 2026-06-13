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

func (cfg *privacyFilterConfig) resolveGitleaksPath(pluginDir string) string {
	if cfg.GitleaksTOML == "" {
		builtin := filepath.Join(pluginDir, "rules", "gitleaks.toml")
		if _, err := os.Stat(builtin); err == nil {
			return builtin
		}
		return ""
	}
	if filepath.IsAbs(cfg.GitleaksTOML) {
		return cfg.GitleaksTOML
	}
	return filepath.Join(pluginDir, cfg.GitleaksTOML)
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
	tomlPath := cfg.resolveGitleaksPath(pluginDir)
	f, err := filter.New(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create privacy filter: %w", err)
	}
	rules, skipped := f.Stats()
	log.Infof("privacy filter loaded: %d rules, %d skipped", rules, skipped)
	return f, nil
}
