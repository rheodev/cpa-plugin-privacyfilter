package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

// auditLog is the local record of what the pseudonymize mode did, for the
// operator's eyes only. The ordinary log carries counts and never a value;
// this file carries the values: for every request the mapping table as
// "kind, original, pseudonym", at completion which pseudonyms the return
// path swapped back and how often, and which tokens in the plugin's own
// shape it delivered without a row behind them. It is therefore a clear-text
// copy of everything the plugin protects and exists only while the
// operator wants to check the plugin's work; the file is created with mode
// 0600 and rotated once to ".1" when it exceeds maxBytes.
//
// Every write opens, appends and closes the file. That costs a few system
// calls per request and saves a file descriptor per plugin instance, which
// matters because the host rebuilds the instance on every configuration
// reload and never tells the old one to close anything.
type auditLog struct {
	path     string
	maxBytes int64
}

// newAuditLog resolves path against pluginDir, like terms_file, and returns
// nil when path is empty. The directory must exist; the file is created on
// the first write. Opening once here checks that the path is writable, so
// a typo fails registration instead of silently logging nothing.
func newAuditLog(pluginDir, path string, maxBytes int64) (*auditLog, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(pluginDir, path)
	}
	if maxBytes <= 0 {
		maxBytes = defaultAuditMaxBytes
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("privacyfilter: audit.path: %w", err)
	}
	if errClose := f.Close(); errClose != nil {
		return nil, fmt.Errorf("privacyfilter: audit.path: %w", errClose)
	}
	return &auditLog{path: path, maxBytes: maxBytes}, nil
}

// defaultAuditMaxBytes is the rotation threshold when audit.max_bytes is
// absent: 10 MiB, a few thousand requests of a coding session.
const defaultAuditMaxBytes = 10 << 20

// request records one forward pass: a header line with the request id,
// source format, salt source and sizes, then one "map" line per row this
// request added to the conversation's table, sorted by kind and original so
// two runs over the same request produce the same block. A row an earlier
// request of the conversation added is in that request's block already.
func (a *auditLog) request(requestID string, res forwardResult, sourceFormat string, bodyBytes int) {
	if a == nil {
		return
	}
	id := auditID(requestID)
	var b strings.Builder
	now := time.Now().Format(time.RFC3339)
	fmt.Fprintf(&b, "%s\trequest\t%s\tformat=%s\tsession=%s\tbody=%d\tout=%d\tdistinct=%d\ttable=%d\tkept=%d\n",
		now, id, auditField(sourceFormat), res.session.Source, bodyBytes, len(res.out), len(res.added), res.table.Len(), sumCounts(res.kept))
	entries := append([]mapping.Entry(nil), res.added...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Kind != entries[j].Kind {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Original < entries[j].Original
	})
	for _, e := range entries {
		fmt.Fprintf(&b, "%s\tmap\t%s\t%s\t%s\t%s\n", now, id, e.Kind, auditField(e.Original), auditField(e.Pseudonym))
	}
	a.write(b.String())
}

// complete records the end of a request: one "restored" line per pseudonym
// the return path swapped back while the request was bound, with its count,
// sorted by pseudonym, and a closing "complete" line with the outcome and
// the totals. A request whose response never repeated a pseudonym gets the
// closing line alone.
func (a *auditLog) complete(requestID string, done pluginapi.RequestCompletion, table *mapping.Table, hits map[string]int) {
	if a == nil {
		return
	}
	id := auditID(requestID)
	var b strings.Builder
	now := time.Now().Format(time.RFC3339)
	keys := make([]string, 0, len(hits))
	for k := range hits {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	total := 0
	for _, k := range keys {
		total += hits[k]
		original := ""
		if table != nil {
			if e, ok := table.Original(k); ok {
				original = e.Original
			}
		}
		fmt.Fprintf(&b, "%s\trestored\t%s\t%s\t%s\t%d\n", now, id, auditField(k), auditField(original), hits[k])
	}
	fmt.Fprintf(&b, "%s\tcomplete\t%s\toutcome=%s\tstream=%t\trestored_distinct=%d\trestored_total=%d\n",
		now, id, done.Outcome, done.Stream, len(keys), total)
	a.write(b.String())
}

// unknown records the tokens a response or a stream delivered in the
// plugin's own shape without a table row behind them, one "unknown" line
// per token with its count, sorted by token. Such a token is no value of
// the user's: it is a name the model invented in the shape, a pseudonym it
// recalled with slipped digits, or one of another conversation quoted from
// a file, and the line against the "map" lines of the session is what lets
// the operator tell these apart. Nothing is written when there is none.
func (a *auditLog) unknown(requestID string, tokens map[string]int) {
	if a == nil || len(tokens) == 0 {
		return
	}
	id := auditID(requestID)
	var b strings.Builder
	now := time.Now().Format(time.RFC3339)
	keys := make([]string, 0, len(tokens))
	for k := range tokens {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s\tunknown\t%s\t%s\t%d\n", now, id, auditField(k), tokens[k])
	}
	a.write(b.String())
}

// write appends s, rotating the file to ".1" first when it has grown past
// maxBytes. Failures are logged once per write and never reach the request.
func (a *auditLog) write(s string) {
	if st, err := os.Stat(a.path); err == nil && st.Size() > a.maxBytes {
		if errRotate := os.Rename(a.path, a.path+".1"); errRotate != nil {
			log.Warnf("privacyfilter: audit log not rotated: %v", errRotate)
		}
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Warnf("privacyfilter: audit log not written: %v", err)
		return
	}
	if _, err := f.WriteString(s); err != nil {
		log.Warnf("privacyfilter: audit log not written: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Warnf("privacyfilter: audit log not closed: %v", err)
	}
}

// auditID is the request id for the file, "-" when the host sent none.
func auditID(requestID string) string {
	if requestID == "" {
		return "-"
	}
	return requestID
}

// auditField writes a value so one line stays one line: values with a tab,
// a line break, a control character or a leading or trailing space are
// quoted in Go syntax, everything else goes out as it is.
func auditField(s string) string {
	if s == "" {
		return `""`
	}
	if s != strings.TrimSpace(s) {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return strconv.Quote(s)
		}
	}
	return s
}
