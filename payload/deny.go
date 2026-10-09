package payload

import "strings"

// DenyList decides which strings Walk leaves alone. It has two kinds of
// rules: leaf rules match the key of the string itself, subtree rules match
// an ancestor object and exclude everything below it.
type DenyList struct {
	// Keys are object keys whose string value is never visited, wherever the
	// key appears. Array indexes never match a key.
	Keys map[string]bool
	// Paths are dotted paths, without indexes, that are never visited; an
	// entry "metadata.user_id" matches Path{"metadata","user_id"}. Array
	// indexes in the actual path are skipped when matching, so
	// "messages.content" would match messages[3].content[0]. The entry is
	// compared element by element, so a single key that carries a dot in its
	// own name - Path{"metadata.user_id"}, an everyday shape in a
	// configuration object - is not matched by a rule meant for the way down
	// to it.
	Paths map[string]bool
	// BlockTypes are values of a "type" key that exclude the whole object
	// that carries them, for example "thinking" excludes the entire thinking
	// block with its text and signature.
	BlockTypes map[string]bool
	// ToolNameParents are object keys under which a "name" key is denied:
	// tools[].name, tool_use.name. A "name" elsewhere, such as in the text of
	// a message, is not a tool name and is visited. The same keys mark the
	// "input" of a tool block, below which no rule of the list applies.
	ToolNameParents map[string]bool
}

// DefaultDeny returns the deny list for the Anthropic Messages format. It
// covers, at least:
//
//	keys:        model, role, type, id, tool_use_id, stop_reason,
//	             stop_sequence, cache_control, media_type, container,
//	             authorization_token
//	paths:       metadata.user_id, source.data (base64 image and document
//	             data), anthropic_version, service_tier, delta.signature,
//	             input_schema.required, stop_sequences, betas
//	block types: thinking and redacted_thinking, and the stream deltas that
//	             carry their fragments, thinking_delta and signature_delta
//	tool names:  the "name" of tools[] and mcp_servers[] entries, of
//	             tool_choice, and of tool_use, server_tool_use and
//	             mcp_tool_use blocks
//
// The system prompt, every message text, tool_result contents, tool_use
// input and tool descriptions are visited.
//
// Two of the rules are bound to a place rather than to a name. The signature
// of a thinking block is covered by the block type, not by the key name, so a
// "signature" that arrives elsewhere - a mail footer in a tool result, the
// signer of a commit - is filtered like any other text. And below the "input"
// of a tool block no rule of this list applies at all: those keys belong to
// the tool, so an argument that happens to be called "type" or to look like
// source.data means nothing here. The content of a tool_result keeps the
// rules, because there the schema really does hold: an image a tool returns
// carries its bytes under source.data like any other.
//
// One exception carves a hole into source.data: a document source may carry
// its content as plain text, {"type":"text","media_type":"text/plain",
// "data":"..."}, and that data is ordinary user text that must not leave the
// machine untouched. It is therefore visited when the source object's own
// "type" is "text"; a source of type "base64" stays denied.
func DefaultDeny() *DenyList {
	return &DenyList{
		Keys: map[string]bool{
			"model":         true,
			"role":          true,
			"type":          true,
			"id":            true,
			"tool_use_id":   true,
			"stop_reason":   true,
			"stop_sequence": true,
			"cache_control": true,
			"media_type":    true,
			// The identifier of a code execution container and the credential
			// of an MCP server are handed back to the provider verbatim; a
			// pseudonym in either would address something that is not there.
			"container":           true,
			"authorization_token": true,
		},
		Paths: map[string]bool{
			"metadata.user_id":  true,
			"source.data":       true,
			"anthropic_version": true,
			"service_tier":      true,
			// The signature of a thinking fragment in the stream. In a body
			// the block type covers it; in a delta there is no block to carry
			// a type, so the place has to name it.
			"delta.signature": true,
			// Names that are defined elsewhere in the same body and have to
			// keep pointing there: required names a key of
			// input_schema.properties, and object keys are never visited.
			"input_schema.required": true,
			// Sequences and feature flags the provider matches literally.
			"stop_sequences": true,
			"betas":          true,
		},
		BlockTypes: map[string]bool{
			"thinking":          true,
			"redacted_thinking": true,
			// The stream carries the same two blocks as fragments. Their
			// signature is bound to the exact text, so neither direction may
			// touch a fragment either.
			"thinking_delta":  true,
			"signature_delta": true,
		},
		ToolNameParents: map[string]bool{
			"tools":           true,
			"tool_use":        true,
			"server_tool_use": true,
			"mcp_tool_use":    true,
			// tool_choice.name points at a tools[] entry and mcp_servers[]
			// entries are addressed by name, so both follow the tool name.
			"tool_choice": true,
			"mcp_servers": true,
		},
	}
}

// Denied reports whether the string at path inside a body is excluded.
// enclosingTypes are the "type" values of the objects on the way down, outer
// first, so a subtree rule can be applied without a second pass.
func (d *DenyList) Denied(path Path, enclosingTypes []string) bool {
	if d == nil || len(path) == 0 {
		return false
	}

	// Place before name: below the "input" of a tool block the keys are the
	// tool's own and no rule of this list applies. This has to come first,
	// because an argument that carries a key "type" with the value "thinking"
	// would otherwise exclude its own subtree.
	if insideToolInput(path, enclosingTypes, d.ToolNameParents) {
		return false
	}

	// Subtree rule: one block type anywhere above excludes everything below
	// it, text and signature alike.
	for _, t := range enclosingTypes {
		if d.BlockTypes[t] {
			return true
		}
	}

	leaf := path[len(path)-1]
	if !isIndex(leaf) && d.Keys[leaf] {
		return true
	}

	// A document source of type "text" carries user text in its "data", not
	// base64, so it is visited before the dotted rule can deny it. The
	// innermost enclosing type is the source object's own "type", which is
	// what tells this case from an image source of type "base64".
	if leaf == "data" && len(path) >= 2 && path[len(path)-2] == "source" &&
		len(enclosingTypes) > 0 && enclosingTypes[len(enclosingTypes)-1] == "text" {
		return false
	}

	// Dotted rule: the path with its array indexes removed, matched against
	// the entry element by element, at every depth. The tail is what lets a
	// single entry "source.data" cover the image data of any content block
	// without naming the way down to it, and the element-wise comparison is
	// what keeps a lone key named "source.data" out of that rule.
	if len(d.Paths) > 0 {
		parts := make([]string, 0, len(path))
		for _, elem := range path {
			if !isIndex(elem) {
				parts = append(parts, elem)
			}
		}
		for rule := range d.Paths {
			if matchesTail(parts, rule) {
				return true
			}
		}
	}

	// Tool names: either the enclosing collection says so, as in tools[].name,
	// or the enclosing object carries a block type that does, as in a tool_use
	// block. The second case only applies when the "name" sits directly in an
	// array element, which is where content blocks live; that keeps
	// tool_use.input.name, an ordinary argument, out of the deny list.
	if leaf == "name" && len(d.ToolNameParents) > 0 {
		for i := len(path) - 2; i >= 0; i-- {
			if isIndex(path[i]) {
				continue
			}
			if d.ToolNameParents[path[i]] {
				return true
			}
			break
		}
		if len(path) >= 2 && isIndex(path[len(path)-2]) && len(enclosingTypes) > 0 {
			if d.ToolNameParents[enclosingTypes[len(enclosingTypes)-1]] {
				return true
			}
		}
	}

	return false
}

// VisitsKeys reports whether the object key of the member at path is offered
// to the visitor as text. Everywhere in the Anthropic schema a key is a word
// of the schema and is left alone; below the input of a tool block the keys
// are the tool's own, and there a key is as often a name as a value is: a
// map of hosts to their state, of files to their content, of containers to
// their networks. Such a key leaves in clear when it is not visited, and a
// pseudonym the model writes as a key is never resolved. The key is offered
// under the path of its member, which is what the deny list and the visitor
// see for the value as well.
func (d *DenyList) VisitsKeys(path Path, enclosingTypes []string) bool {
	if d == nil || len(path) == 0 {
		return false
	}
	return insideToolInput(path, enclosingTypes, d.ToolNameParents)
}

// matchesTail reports whether the dotted rule matches the tail of parts, one
// element per dot-separated piece. No piece may span a dot of the path, which
// is what tells the two elements of Path{"metadata","user_id"} from the
// single element Path{"metadata.user_id"}.
func matchesTail(parts []string, rule string) bool {
	n := 1 + strings.Count(rule, ".")
	if n > len(parts) {
		return false
	}
	rest := rule
	for _, elem := range parts[len(parts)-n:] {
		var piece string
		piece, rest, _ = strings.Cut(rest, ".")
		if elem != piece {
			return false
		}
	}
	return true
}

// insideToolInput reports whether path points below the "input" of a tool
// block. The object that carries the "input" is either named by an enclosing
// key, as in a flat tool_use.input, or it is an array element whose block
// type says what it is, which is where content blocks live.
func insideToolInput(path Path, enclosingTypes []string, parents map[string]bool) bool {
	if len(parents) == 0 {
		return false
	}
	for i := 1; i+1 < len(path); i++ {
		if path[i] != "input" {
			continue
		}
		if !isIndex(path[i-1]) {
			if parents[path[i-1]] {
				return true
			}
			continue
		}
		for _, t := range enclosingTypes {
			if parents[t] {
				return true
			}
		}
	}
	return false
}
