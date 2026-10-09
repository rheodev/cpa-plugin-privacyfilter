package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var _ pluginapi.ResponseInterceptor = (*privacyFilterPlugin)(nil)

// errRestorePanic marks a recovered panic on the return path.
var errRestorePanic = errors.New("privacyfilter: recovered panic on the return path")

// InterceptResponse is the return path for a non-streaming Messages
// response. It looks up the mapping table the forward pass stored under the
// RequestID, replaces every pseudonym in the strings the deny list allows by
// its original, and leaves thinking blocks, ids and everything else byte for
// byte as the upstream sent it.
//
// Errors on this path are never fatal: a missing table, a body that does not
// parse or an unknown format are logged and the response is passed through
// unchanged. The worst outcome is a pseudonym on the user's screen, and that
// beats a broken response. The capability is only registered in
// ModePseudonymize, so in ModeRedact this method is never called.
func (p *privacyFilterPlugin) InterceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest) (pluginapi.ResponseInterceptResponse, error) {
	resp := pluginapi.ResponseInterceptResponse{}
	if p.store == nil || p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		return resp, nil
	}
	if len(req.Body) == 0 || req.RequestID == "" {
		return resp, nil
	}
	if req.SourceFormat != payload.FormatClaude {
		// The forward pass does not gate on the format, so a request of
		// another format was pseudonymized and now goes back unrestored.
		// That is a visible defect for the user, not a diagnostic.
		log.Warnf("privacyfilter: response for format %q passed through with pseudonyms, only %q is restored", req.SourceFormat, payload.FormatClaude)
		return resp, nil
	}

	table, errTable := p.store.Get(req.RequestID)
	if errTable != nil {
		if errors.Is(errTable, mapping.ErrTableNotFound) {
			log.Warnf("privacyfilter: no mapping table for the response, passing it through with pseudonyms (status=%d)", req.StatusCode)
		} else {
			log.Warnf("privacyfilter: mapping table lookup failed: %v", errTable)
		}
		return resp, nil
	}

	out, restored, unknown, err := restoreResponseBody(req.Body, table, p.deny)
	if err != nil {
		log.Warnf("privacyfilter: response not restored, passing it through: %v", err)
		return resp, nil
	}
	fields := log.Fields{
		"source_format": req.SourceFormat,
		"restored":      restored,
		"distinct":      table.Len(),
		"body_bytes":    len(req.Body),
		"unknown":       len(unknown),
		"unknown_hits":  countHits(unknown),
	}
	p.audit.unknown(req.RequestID, unknown)
	if restored > 0 {
		resp.Body = out
	}
	switch {
	case restored > 0:
		log.WithFields(fields).Info("privacyfilter: response restored")
	case len(unknown) > 0:
		// The model wrote tokens in the plugin's shape that no table row
		// explains, an invented name or a pseudonym quoted from a file.
		// They go to the client as they are; the restorer never guesses.
		log.WithFields(fields).Info("privacyfilter: response carried pseudonym shapes without a table row")
	default:
		// Nothing to say at Info: the table may be empty, or the model did
		// not repeat any of the values. The body goes back as it came.
		if log.IsLevelEnabled(log.DebugLevel) {
			log.WithFields(fields).Debug("privacyfilter: response carried no pseudonym")
		}
	}
	return resp, nil
}

// restoreResponseBody replaces pseudonyms in every string of a Messages
// response body that deny allows and returns the new body, the number of
// strings that changed, and by token how often the restored strings still
// carry a token in the plugin's own shape, which no table row explains;
// see pseudo.ShapedTokens. Panics in the payload or mapping code are
// turned into errors so the host never fuses the plugin because of one
// odd response.
func restoreResponseBody(body []byte, table *mapping.Table, deny *payload.DenyList) (out []byte, restored int, unknown map[string]int, err error) {
	defer recoverInto(&err, errRestorePanic)
	r := table.Restorer()
	unknown = map[string]int{}
	out, restored, err = payload.ReplaceStrings(body, deny, func(_ payload.Path, text string) (string, bool) {
		// The decoded string is plain text, not a JSON fragment, so the
		// originals go in unescaped; ReplaceStrings re-encodes the value.
		text, changed := r.Restore(text, false)
		for _, tok := range pseudo.ShapedTokens(text) {
			unknown[tok]++
		}
		return text, changed
	})
	return out, restored, unknown, err
}

// countHits sums the counts of a token map.
func countHits(m map[string]int) int {
	n := 0
	for _, c := range m {
		n += c
	}
	return n
}

// recoverInto turns a panic into an error wrapped around sentinel, keeping
// the panic value in the message so the log says what went wrong. It is
// meant to be deferred; both directions of the plugin use it.
func recoverInto(err *error, sentinel error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%w: %v", sentinel, r)
	}
}
