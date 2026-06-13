package main

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var pluginVersion = "0.2.0"

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}

	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
	}

	f, errFilter := newFilter(pluginDir, cfg)
	if errFilter != nil {
		return pluginapi.Plugin{}, errFilter
	}
	p.filter = f

	return pluginapi.Plugin{
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "rheodev",
			GitHubRepository: "https://github.com/rheodev/cpa-plugin-privacyfilter",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "gitleaks_toml",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Path to gitleaks.toml rules file. Empty uses built-in rules.",
				},
				{
					Name:        "skip_models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Model names to skip redaction for.",
				},
				{
					Name:        "skip_formats",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Source format names to skip redaction for.",
				},
			},
		},
		Capabilities: pluginapi.Capabilities{
			RequestInterceptor: p,
		},
	}, nil
}
