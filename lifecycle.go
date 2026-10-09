package main

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var _ pluginapi.RequestLifecyclePlugin = (*privacyFilterPlugin)(nil)

// HandleRequestComplete releases the binding of a finished request to its
// conversation's mapping table. The host sends exactly one completion per
// request that reached interception, asynchronously and after the response
// or the last stream chunk has been delivered, so nothing on the return
// path still needs the binding. The table itself stays with the
// conversation for the requests still to come and is dropped by the store
// once the conversation has been quiet for mapping_ttl.
func (p *privacyFilterPlugin) HandleRequestComplete(ctx context.Context, done pluginapi.RequestCompletion) error {
	if p.store == nil || done.RequestID == "" {
		return nil
	}
	table, hits, _ := p.store.Complete(done.RequestID)
	if p.streams != nil {
		// The tokens a stream delivered in the plugin's shape without a
		// table row go to the audit log in front of the closing line; a
		// whole response wrote its own when it was restored.
		p.audit.unknown(done.RequestID, p.streams.finish(done.RequestID, done.Stream))
	}
	if p.audit != nil {
		p.audit.complete(done.RequestID, done, table, hits)
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"outcome":  string(done.Outcome),
			"stream":   done.Stream,
			"tables":   p.store.Len(),
			"requests": p.store.Bound(),
		}).Debug("privacyfilter: request released from its mapping table")
	}
	return nil
}
