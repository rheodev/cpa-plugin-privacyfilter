package main

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var pluginVersion = "0.4.0-dev"

// maxMappingTables bounds the number of live mapping tables. It is not
// configurable: the tables are freed by the request.complete event, the TTL is
// the safety net, and this is the last line of defence against a host that
// sends neither.
const maxMappingTables = 1024

// runtimeState is the part of the plugin that outlives a plugin instance:
// the mapping tables and the stream holdback, both keyed by RequestID.
//
// The host rebuilds the plugin on every configuration reload, which a token
// refresh triggers every few minutes, and it does so while requests are in
// flight. A request that entered the request interceptor of the old
// instance stores its table after the new instance already exists, and its
// stream is then dispatched to the new one. Moving tables from the old store
// to the new at registration cannot close that gap; the store the stream
// reads must be the store the request wrote. So there is one runtimeState
// per loaded library, created with the first registration and handed to
// every instance after it. Only the TTL follows the newest configuration.
type runtimeState struct {
	store   *mapping.Store
	streams *streams
}

func newRuntimeState() *runtimeState {
	return &runtimeState{
		store:   mapping.NewStore(mapping.StoreConfig{MaxTables: maxMappingTables}),
		streams: newStreams(),
	}
}

// buildPlugin parses the configuration and builds one plugin instance. rt is
// the shared runtime state the instance joins; nil builds a fresh one, which
// is what tests want and what the ABI never passes.
func buildPlugin(configYAML []byte, pluginDir string, rt *runtimeState) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}
	// The host names the plugin directory as it stands in its own
	// configuration, "plugins/linux/amd64" relative to its working
	// directory. Every file the plugin resolves against it, the secret above
	// all, must be found from there and nowhere else, so the directory is
	// made absolute once, here, before anything is resolved against it.
	if pluginDir != "" && !filepath.IsAbs(pluginDir) {
		abs, errAbs := filepath.Abs(pluginDir)
		if errAbs != nil {
			return pluginapi.Plugin{}, fmt.Errorf("privacyfilter: plugin directory %q: %w", pluginDir, errAbs)
		}
		pluginDir = abs
	}
	if rt == nil {
		rt = newRuntimeState()
	}

	p := &privacyFilterPlugin{
		cfg:       cfg,
		pluginDir: pluginDir,
		rt:        rt,
	}

	// In ModeRedact a failure here aborts the registration, as it does in
	// the original plugin. In ModePseudonymize it does not: the host would
	// come up without the filter, log one line and forward every request
	// in clear text, and nobody would see it. So the plugin registers with
	// the error and blocks every request with it instead, until the
	// configuration is fixed and the proxy restarted; the user sees the
	// error in the client at the first request.
	f, errFilter := newFilter(pluginDir, cfg)
	if errFilter != nil {
		if !cfg.IsPseudonymize() {
			return pluginapi.Plugin{}, errFilter
		}
		p.blocked = errFilter
	}
	p.filter = f

	if cfg.IsPseudonymize() && p.blocked == nil {
		p.blocked = p.initPseudonymize()
	}
	switch {
	case p.blocked != nil:
		log.Errorf("privacyfilter registered in blocking state, every request is answered with this error until the configuration is fixed and the proxy restarted: %v", p.blocked)
	case cfg.IsPseudonymize():
		log.Infof("privacyfilter registered: mode=%s, %d terms, patterns [%s], packyme=%t, paths=%t, secrets=%t, stream=%t, on_error=%s",
			cfg.Mode(), p.termCount, enabledPatterns(cfg.Patterns), cfg.Packyme.Enabled, cfg.Path.Enabled, cfg.Secrets.Enabled, cfg.Restore.Stream, cfg.OnError)
	default:
		log.Infof("privacyfilter registered: mode=%s, the pseudonymize configuration is inactive", cfg.Mode())
	}

	return pluginapi.Plugin{
		Metadata:     pluginMetadata(),
		Capabilities: capabilitiesFor(p),
	}, nil
}

// pluginMetadata describes the plugin and its configuration keys to the
// host. The first five keys are the original plugin's, in its order; the
// rest belong to pseudonymize mode. A reconfigure the host rejects is
// answered with this metadata too, see handlePrivacyFilterRegister.
func pluginMetadata() pluginapi.Metadata {
	return pluginapi.Metadata{
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
				Name:        "replacement",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Global redaction label. Unset uses built-in labels; per-type labels take precedence.",
			},
			{
				Name:        "replacement_labels",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Redaction labels keyed by entity type ID (email, secret, phone, id, bank_card, ip, or future types).",
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
			{
				Name:        "mode",
				Type:        pluginapi.ConfigFieldTypeEnum,
				EnumValues:  []string{string(ModeRedact), string(ModePseudonymize)},
				Description: "redact reproduces the original one-way behaviour (default); pseudonymize replaces values with reversible pseudonyms and restores them on the way back.",
			},
			{
				Name:        "salt_secret_path",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Path to the HMAC secret file for pseudonymize mode. Empty uses pseudonym.secret next to the plugin's shared object; a relative path resolves the same way gitleaks_toml does.",
			},
			{
				Name:        "terms",
				Type:        pluginapi.ConfigFieldTypeArray,
				Description: "Maintained list of literals or regexes to treat as confidential, each with a kind ({value|regex, kind, ignore_case}). Takes precedence over every other detection layer.",
			},
			{
				Name:        "terms_file",
				Type:        pluginapi.ConfigFieldTypeString,
				Description: "Optional file with further terms, one per line (<literal> [kind] [ignore_case], or a YAML flow entry like {regex: ..., kind: host}). A relative path resolves next to the plugin's shared object. cmd/termsgen writes this format.",
			},
			{
				Name:        "patterns",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Toggles for the structural detectors: ipv4, ipv6, cidr, mac, email, iban, url, uuid, hexid (machine-id, WWN), fingerprint (SSH SHA256), serial (labelled serial numbers). All default to true except url. ipv4, ipv6 and email also govern what the packyme layer reports.",
			},
			{
				Name:        "path",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Segment-wise path pseudonymization: enabled (default false until the stream restore is confirmed live), replace_unknown (default true), preserve (segments added to the built-in list of ordinary directory names), filenames (terms: a file name is replaced only where a term matches inside it, the default; all: every file name outside the preserve list).",
			},
			{
				Name:        "packyme",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Toggle for the packyme/privacy-filter detection layer: enabled (default true).",
			},
			{
				Name:        "secrets",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Toggle for the betterleaks detection layer: enabled (default false) and rules_toml. Only has an effect in binaries built with the betterleaks tag.",
			},
			{
				Name:        "restore",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Return-path options: stream (default true) enables pseudonym restoration for streamed responses.",
			},
			{
				Name:        "limits",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "max_body_bytes (default 33554432, 32 MiB) and mapping_ttl (default 30m, a Go duration string, measured from the last use of a conversation's mapping table; a quiet conversation loses its table after this time).",
			},
			{
				Name:        "audit",
				Type:        pluginapi.ConfigFieldTypeObject,
				Description: "Local audit log of pseudonymize mode: path (empty = off; relative resolves next to the shared object) and max_bytes (default 10 MiB, then rotated to .1). Records every mapping table and every restored pseudonym in clear text, mode 0600; switch on for a check, off again after.",
			},
			{
				Name:        "on_error",
				Type:        pluginapi.ConfigFieldTypeEnum,
				EnumValues:  []string{string(OnErrorBlock), string(OnErrorPassthrough)},
				Description: "Forward-path behaviour when detection or parsing fails: block (default) terminates the request, passthrough forwards the body unfiltered. The return path always passes through on error.",
			},
		},
	}
}

// capabilitiesFor declares what the plugin does for the host. In ModeRedact
// only the request interceptor is announced, exactly as the original plugin
// does, so the host never calls the return path there. In ModePseudonymize
// the response interceptor restores originals and the lifecycle hook releases
// the mapping tables; with restore.stream the stream interceptor restores
// streamed responses. The handlers of the return path guard on p.store and
// p.streams rather than on the mode, so a call the host makes against the
// announced capabilities is a no-op in ModeRedact instead of a nil
// dereference.
func capabilitiesFor(p *privacyFilterPlugin) pluginapi.Capabilities {
	caps := pluginapi.Capabilities{RequestInterceptor: p}
	if p.cfg.IsPseudonymize() && p.blocked == nil {
		caps.ResponseInterceptor = p
		caps.RequestLifecyclePlugin = p
		if p.streams != nil {
			caps.StreamChunkInterceptor = p
		}
	}
	return caps
}

// initPseudonymize builds everything ModePseudonymize needs once, at
// registration: the HMAC secret, the detection layers in their order of
// precedence, the deny list and the store for the mapping tables. Every failure
// here puts the plugin into the blocking state, because a plugin that cannot
// pseudonymize must not silently forward plain text, and a failed registration
// would do exactly that. The layers are shared by all requests; only the
// Composite around them and the generator are per conversation.
func (p *privacyFilterPlugin) initPseudonymize() error {
	secretPath := pseudo.ResolveSecretPath(p.pluginDir, p.cfg.SaltSecretPath)
	secret, errSecret := pseudo.LoadSecret(secretPath)
	if errSecret != nil {
		return fmt.Errorf("privacyfilter: mode %s needs a readable secret of at least %d bytes at %s: %w",
			ModePseudonymize, pseudo.MinSecretLen, secretPath, errSecret)
	}
	p.secret = secret

	entries := p.cfg.Terms
	for i, t := range entries {
		if kind := detect.Kind(t.Kind); !kind.Valid() {
			return fmt.Errorf("privacyfilter: terms[%d]: invalid kind %q, want one of %s", i, t.Kind, detect.KindNames())
		}
		if class := termUnsafe(t); class != "" {
			return fmt.Errorf("privacyfilter: terms[%d]: %w", i, unsafeTermError(class))
		}
	}
	if termsPath := resolveTermsFilePath(p.pluginDir, p.cfg.TermsFile); termsPath != "" {
		fromFile, lines, errFile := loadTermsFileLines(termsPath)
		if errFile != nil {
			return fmt.Errorf("privacyfilter: terms_file: %w", errFile)
		}
		for i, t := range fromFile {
			if errEntry := t.validate(); errEntry != nil {
				return fmt.Errorf("privacyfilter: terms_file %s line %d: %w", termsPath, lines[i], errEntry)
			}
			if kind := detect.Kind(t.Kind); !kind.Valid() {
				return fmt.Errorf("privacyfilter: terms_file %s line %d: invalid kind %q, want one of %s", termsPath, lines[i], t.Kind, detect.KindNames())
			}
			// The value of a term is written back into every text the
			// client goes on to run, parse or store. A quote, a shell
			// metacharacter, a comment mark, a percent sign, a slash or a
			// control character in it turns the line the model wrote into a
			// different one for the shell, the crontab, the configuration
			// file or the patch that receives it; see the package harm under
			// internal/testlab. Such a value is refused at start, with the
			// line but without the value.
			if class := termUnsafe(t); class != "" {
				return fmt.Errorf("privacyfilter: terms_file %s line %d: %w", termsPath, lines[i], unsafeTermError(class))
			}
		}
		entries = mergeTerms(entries, fromFile)
		log.Infof("privacyfilter: %d terms loaded from %s, %d in total after merging", len(fromFile), termsPath, len(entries))
	}
	p.termCount = len(entries)
	// A literal term that equals an entry of the built-in name list, or the
	// given name of one, would be its own pseudonym and never be replaced.
	// Such entries are left out of the list for this plugin instead; the
	// term is then detected and rendered like any other person, and every
	// other person pseudonym stays as it was. The count is logged, not the
	// names, which are the user's terms.
	literals := make([]string, 0, len(entries))
	for _, t := range entries {
		if t.Value != "" {
			literals = append(literals, t.Value)
		}
	}
	renderers, dropped := pseudo.RenderersExcludingNames(literals)
	if len(dropped) > 0 {
		log.Warnf("privacyfilter: %d entries of the built-in name list equal a term and are left out of the person pseudonyms", len(dropped))
	}
	p.renderers = renderers

	// The networks of the term list keep their structure in the pseudonyms;
	// a cidr term that is no plain network (wildcards) is left to the
	// renderer.
	p.networks = p.networks[:0]
	for _, t := range entries {
		if t.Value != "" && detect.Kind(t.Kind) == detect.KindCIDR {
			if n, err := netip.ParsePrefix(t.Value); err == nil {
				p.networks = append(p.networks, n)
			}
		}
	}

	// A literal that lies in the range a kind draws its pseudonyms from, an
	// address out of 100.64.0.0/10 or a MAC with the locally administered
	// prefix, is replaced like any other value: the forward pass excludes
	// what the conversation's table knows, not what looks like a pseudonym.
	// The table in turn never hands such a literal out as the pseudonym of
	// another value, see isTermLiteral and mapping.Table.SetAvoid. The one
	// value that cannot be replaced is a network that covers the whole range
	// its pseudonyms are drawn from: masked into the range it is itself,
	// on every attempt, and the table would spin. shape answers for every
	// conversation, since the renderers do not depend on the salt.
	shape := pseudo.NewGenerator(secret, nil, renderers).WithNetworks(p.networks)
	p.termLiterals = make(map[string]bool, len(entries))
	terms := make([]detect.Term, 0, len(entries))
	for i, t := range entries {
		kind := detect.Kind(t.Kind)
		if t.Value != "" {
			p.termLiterals[t.Value] = true
		}
		if t.Value != "" && kind == detect.KindCIDR &&
			shape.Pseudonym(kind, t.Value, 0) == t.Value && shape.Pseudonym(kind, t.Value, 1) == t.Value {
			return fmt.Errorf("privacyfilter: terms[%d]: %q covers the range its pseudonyms are drawn from and would map onto itself; leave it out", i, t.Value)
		}
		terms = append(terms, detect.Term{
			Value:      t.Value,
			Regex:      t.Regex,
			Kind:       kind,
			IgnoreCase: t.IgnoreCase,
		})
	}
	// WordBoundary is on unconditionally: without it "lan" would match inside
	// "plan" and a term list of short hostnames would shred ordinary prose.
	termsLayer, errTerms := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: terms})
	if errTerms != nil {
		return fmt.Errorf("privacyfilter: term list: %w", errTerms)
	}

	patternsLayer, errPatterns := detect.NewPatterns(detect.PatternsConfig{
		IPv4:        p.cfg.Patterns.IPv4,
		IPv6:        p.cfg.Patterns.IPv6,
		CIDR:        p.cfg.Patterns.CIDR,
		MAC:         p.cfg.Patterns.MAC,
		Email:       p.cfg.Patterns.Email,
		IBAN:        p.cfg.Patterns.IBAN,
		URL:         p.cfg.Patterns.URL,
		UUID:        p.cfg.Patterns.UUID,
		HexID:       p.cfg.Patterns.HexID,
		Fingerprint: p.cfg.Patterns.Fingerprint,
		Serial:      p.cfg.Patterns.Serial,
	})
	if errPatterns != nil {
		return fmt.Errorf("privacyfilter: structural patterns: %w", errPatterns)
	}

	// Order is precedence: the maintained list wins over the structural
	// patterns, those over packyme, then the path segments, and the
	// credential scanner comes last.
	layers := []detect.Detector{termsLayer, patternsLayer}
	if p.cfg.Packyme.Enabled {
		// The pattern toggles reach into this layer too: the library has
		// none of its own, and a user who switches ipv4 off expects no
		// address to be replaced by any layer.
		layers = append(layers, detect.NewPackyme(p.filter, detect.PackymeConfig{
			IPv4:  p.cfg.Patterns.IPv4,
			IPv6:  p.cfg.Patterns.IPv6,
			Email: p.cfg.Patterns.Email,
		}))
	}
	if p.cfg.Path.Enabled {
		known := make(map[string]bool, len(entries))
		for _, t := range entries {
			if t.Value != "" {
				known[t.Value] = true
			}
		}
		pathsLayer, errPaths := detect.NewPaths(detect.PathsConfig{
			ReplaceUnknown: p.cfg.Path.ReplaceUnknown,
			Preserve:       p.cfg.Path.Preserve,
			Known:          known,
			AllFilenames:   p.cfg.Path.Filenames == PathFilenamesAll,
		})
		if errPaths != nil {
			return fmt.Errorf("privacyfilter: path layer: %w", errPaths)
		}
		layers = append(layers, pathsLayer)
	}
	if p.cfg.Secrets.Enabled {
		secretsLayer, errSecrets := detect.NewSecrets(detect.SecretsConfig{RulesTOML: p.cfg.Secrets.RulesTOML})
		if errSecrets != nil {
			return fmt.Errorf("privacyfilter: secrets.enabled is set: %w", errSecrets)
		}
		layers = append(layers, secretsLayer)
	}
	p.layers = layers
	p.terms = termsLayer
	p.deny = payload.DefaultDeny()

	audit, errAudit := newAuditLog(p.pluginDir, p.cfg.Audit.Path, p.cfg.Audit.MaxBytes)
	if errAudit != nil {
		return errAudit
	}
	p.audit = audit
	if audit != nil {
		log.Warnf("privacyfilter: audit log on, every mapping table is written in clear text to %s", audit.path)
	}

	// validate already rejected an unparsable duration, so this cannot fail
	// after parseConfig returned without an error.
	ttl, errTTL := time.ParseDuration(p.cfg.Limits.MappingTTL)
	if errTTL != nil {
		return fmt.Errorf("privacyfilter: limits.mapping_ttl %q: %w", p.cfg.Limits.MappingTTL, errTTL)
	}
	// The store and the stream states are shared with every other instance
	// of this library, see runtimeState; the instance only points at them,
	// and the newest configuration decides the TTL for all held tables.
	p.rt.store.SetTTL(ttl)
	p.store = p.rt.store
	if p.cfg.Restore.Stream {
		p.streams = p.rt.streams
	}

	return nil
}

// enabledPatterns names the switched-on structural categories for the
// registration log line, in a fixed order.
func enabledPatterns(flags PatternFlags) string {
	var on []string
	for _, c := range []struct {
		name    string
		enabled bool
	}{
		{"ipv4", flags.IPv4},
		{"ipv6", flags.IPv6},
		{"cidr", flags.CIDR},
		{"mac", flags.MAC},
		{"email", flags.Email},
		{"iban", flags.IBAN},
		{"url", flags.URL},
		{"uuid", flags.UUID},
		{"hexid", flags.HexID},
		{"fingerprint", flags.Fingerprint},
		{"serial", flags.Serial},
	} {
		if c.enabled {
			on = append(on, c.name)
		}
	}
	if len(on) == 0 {
		return "none"
	}
	return strings.Join(on, " ")
}
