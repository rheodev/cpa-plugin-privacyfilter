package pseudo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// SessionHeader is the header Claude Code sends with every request of a
// conversation. The host reads it first, and so does this package.
const SessionHeader = "X-Claude-Code-Session-Id"

// SessionSource says where a session identifier came from.
type SessionSource string

const (
	// SourceHeader: the identifier came from SessionHeader.
	SourceHeader SessionSource = "header"
	// SourceMetadata: the identifier is the suffix of metadata.user_id after
	// "_session_", matched with the pattern _session_([a-f0-9-]+)$.
	SourceMetadata SessionSource = "metadata"
	// SourceHead: neither was present; the identifier is HeadHash(body).
	SourceHead SessionSource = "head"
	// SourceBound: the pass worked on the table an earlier pass of the
	// same request had bound, under the key that table was opened with,
	// and did not read the identifier again. The second request hook.
	SourceBound SessionSource = "bound"
)

// sessionSuffix is the pattern the host uses on metadata.user_id.
var sessionSuffix = regexp.MustCompile(`_session_([a-f0-9-]+)$`)

// Session identifies one conversation for salt derivation and for the
// mapping table: the conversation identifier, where it came from, and the
// caller scope of the host.
type Session struct {
	ID     string
	Source SessionSource
	// Caller is the host's caller scope, a SHA-256 over the credential the
	// client authenticated with, taken from the metadata of the request;
	// empty when the host sent none, which is a proxy without inbound
	// authentication. See CallerScope.
	Caller string
}

// Key returns what the salt and the mapping table are keyed by. The
// conversation identifier is the client's claim: a header, a field of the
// body or the head of the conversation, all of which another client can
// send as well. The caller scope is the host's, derived from the credential
// it authenticated, so a claimed identifier can only ever reach a table of
// the same caller. Without a caller scope the identifier alone is the key,
// as it was before the scope existed, so a host without inbound
// authentication derives the same salts as ever.
func (s Session) Key() string {
	if s.Caller == "" {
		return s.ID
	}
	return s.Caller + "\x00" + s.ID
}

// MetadataCallerScope is the key under which the host hands the caller
// scope to a plugin in the metadata of a request: CallerScopeMetadataKey of
// the host's executor package, a SHA-256 over the authenticated proxy
// credential. The value is repeated here because importing that package
// would pull the host's translators into the shared library.
const MetadataCallerScope = "caller_scope"

// CallerScope returns the caller scope of a request's metadata, trimmed, or
// "" when the host sent none or something other than a string.
func CallerScope(metadata map[string]any) string {
	v, _ := metadata[MetadataCallerScope].(string)
	return strings.TrimSpace(v)
}

// IdentifySession finds the conversation identifier in the order the host
// uses: header, then metadata.user_id, then the fallback hash over the head
// of the conversation. It never returns an empty ID; when body is not JSON
// the head hash is computed over the empty head, which still yields a
// deterministic value. body is not modified.
func IdentifySession(headers http.Header, body []byte) Session {
	if headers != nil {
		if v := strings.TrimSpace(headers.Get(SessionHeader)); v != "" {
			return Session{ID: v, Source: SourceHeader}
		}
	}
	if m := sessionSuffix.FindStringSubmatch(userID(body)); m != nil {
		return Session{ID: m[1], Source: SourceMetadata}
	}
	return Session{ID: HeadHash(body), Source: SourceHead}
}

// userID returns metadata.user_id of an Anthropic Messages body, or "" when
// the body is not JSON or has no such field.
func userID(body []byte) string {
	var req struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return ""
	}
	return req.Metadata.UserID
}

// HeadHash returns the lower-case hex SHA-256 over the head of an Anthropic
// Messages request: the value of "system" and the "content" of the first
// element of "messages" whose "role" is "user". Both parts are re-encoded
// with encoding/json before hashing, so whitespace and key order in the
// incoming body do not matter, and are separated by a zero byte. Absent
// parts contribute the empty string. The hash does not include the model,
// tools or metadata, so a change of model mid-conversation keeps the salt.
func HeadHash(body []byte) string {
	var req struct {
		System   json.RawMessage   `json:"system"`
		Messages []json.RawMessage `json:"messages"`
	}
	var system, content []byte
	if err := json.Unmarshal(body, &req); err == nil {
		system = canonicalJSON(req.System)
		for _, raw := range req.Messages {
			var msg struct {
				Role    string          `json:"role"`
				Content json.RawMessage `json:"content"`
			}
			if err := json.Unmarshal(raw, &msg); err != nil || msg.Role != "user" {
				continue
			}
			content = canonicalJSON(msg.Content)
			break
		}
	}
	h := sha256.New()
	h.Write(system)
	h.Write(separator)
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON re-encodes raw so that whitespace and the order of object
// keys no longer show. An absent or unreadable part contributes nothing.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return out
}

// DeriveSalt computes HMAC-SHA256(secret, "salt" || "\x00" || sessionID).
// The result never leaves the process; only pseudonyms derived from it do.
func DeriveSalt(secret []byte, sessionID string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("salt"))
	m.Write(separator)
	m.Write([]byte(sessionID))
	return m.Sum(nil)
}
