// Package payload knows the shape of the request and response bodies: which
// strings of a request may be rewritten, which must be left alone, and where
// the text lives in an Anthropic stream event.
//
// The forward pass walks every string in the JSON body and skips only what
// the deny list names. The original plugin did the opposite and filtered two
// fields; everything else, including the system prompt, tool results and
// tool arguments, went out untouched. The deny list exists for fields whose
// change would break the request (ids, signatures, base64 data) or that
// carry no secret (role, type, model).
package payload

import (
	"encoding/json"
	"errors"
	"strings"
)

// defaultMaxBodyBytes is the body limit of the plan, used when
// WalkOptions.MaxBodyBytes is zero.
const defaultMaxBodyBytes = 32 << 20

// ErrNotImplemented marks a contract stub that has no implementation yet.
var ErrNotImplemented = errors.New("payload: not implemented")

// ErrBodyTooLarge is returned by Walk when the body exceeds the configured
// limit. In block mode the request is then terminated.
var ErrBodyTooLarge = errors.New("payload: body exceeds size limit")

// ErrNotJSON is returned by Walk when the body does not parse as a JSON
// object. In block mode the request is then terminated.
var ErrNotJSON = errors.New("payload: body is not a JSON object")

// Path locates a string inside the JSON tree. Elements are object keys or
// decimal array indexes, so messages[2].content[0].text is
// Path{"messages", "2", "content", "0", "text"}. Paths are used by the deny
// list and reported to the Visitor. A key that is visited itself is reported
// under the path of its member, the same path its value has.
type Path []string

// String renders the path in dotted form with bracketed indexes, as in the
// example above, for logs and tests.
func (p Path) String() string {
	var b strings.Builder
	for i, elem := range p {
		switch {
		case i == 0:
			b.WriteString(elem)
		case isIndex(elem):
			b.WriteByte('[')
			b.WriteString(elem)
			b.WriteByte(']')
		default:
			b.WriteByte('.')
			b.WriteString(elem)
		}
	}
	return b.String()
}

// Visitor is called for every string value that is not denied, and for
// every object key below the input of a tool block. It returns the
// replacement and whether the string changed. Returning changed == false
// leaves the original bytes in place; the body is then rewritten only if at
// least one visitor call changed something.
type Visitor func(path Path, value string) (out string, changed bool)

// WalkOptions bounds one walk.
type WalkOptions struct {
	// MaxBodyBytes rejects larger bodies with ErrBodyTooLarge. Zero means
	// 32 MiB, the default of the plan.
	MaxBodyBytes int
	// Deny is the deny list to apply; nil means DefaultDeny.
	Deny *DenyList
}

// Walk reads body as a JSON object, calls visit for every string value
// whose path the deny list does not cover and for every object key below
// the input of a tool block, and returns the body with the replacements
// spliced in. When no visitor call reports a change, Walk returns body
// itself (same backing array) and changed == false, so redact mode can keep
// its current "nil means unchanged" behaviour and no bytes move.
//
// Walk is ReplaceStrings with the forward path's limit and errors: the same
// scanner, the same deny list, the same rules, so a body is filtered the
// same way in both directions. Nothing is decoded and re-encoded except the
// strings that change. Every other byte survives as the client sent it: key
// order, white space, number notation, escape sequences, a lone surrogate
// in a string the filter has no business with, and a key that appears twice
// in one object is seen and kept both times. A string that changes is
// re-encoded from its decoded form, which normalizes its escapes; a lone
// surrogate inside such a string becomes the replacement character, as it
// would in any decoder.
//
// The body has to be one JSON document with an object at the root. White
// space around it is kept; anything else after the object is ErrNotJSON,
// because a body that is not one document is not a request the upstream
// would take either.
func Walk(body []byte, opts WalkOptions, visit Visitor) (out []byte, changed bool, err error) {
	limit := opts.MaxBodyBytes
	if limit <= 0 {
		limit = defaultMaxBodyBytes
	}
	if len(body) > limit {
		return nil, false, ErrBodyTooLarge
	}
	if !json.Valid(body) {
		return nil, false, ErrNotJSON
	}
	if i := skipWS(body, 0); i >= len(body) || body[i] != '{' {
		return nil, false, ErrNotJSON
	}
	if visit == nil {
		return body, false, nil
	}
	deny := opts.Deny
	if deny == nil {
		deny = DefaultDeny()
	}
	out, n, err := rewrite(body, deny, visit)
	if err != nil {
		return nil, false, err
	}
	return out, n > 0, nil
}
