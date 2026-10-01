package main

import (
	"net/netip"
	"strconv"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// authorship tells, for one request, the values the model wrote itself from
// the values it was shown. A value the model wrote first is with the
// provider in clear text already: the model named a directory in a mkdir,
// put an address into a test script, chose a file name. Replacing such a
// value when a tool result echoes it protects nothing and costs the model
// its bearings: it sees its own directory come back as d-… and takes that
// shape for the way names look here, which is where the invented
// pseudonyms of the lab report come from. So a value the model wrote first
// is left as it is for the rest of the conversation.
//
// "First" is decided in the order of the conversation: the system prompt,
// then the messages as they stand in the body. A value the user's side
// carried in an earlier message was shown to the model as a pseudonym; what
// the model wrote back the client restored, and the clear text in the
// model's turn is the client's doing, not the model's. Such a value is in
// the conversation's table before its turn is reached, or in the
// conversation's memory when the table has expired in between, and stays
// replaced. Two things are never left in clear whoever wrote them: a value
// the term list names, inside a longer value as well, and an address inside
// a network the list names, because a model guesses a gateway address more
// easily than a customer's directory.
//
// The forward pass therefore walks the body twice: a reading pass that
// detects every string once and notes who had each value first, and the
// rewriting pass that uses the matches of the first and leaves the exempt
// ones standing. A directory name the model types in a command has no path
// shape, so for the path kinds every token of the model's output counts,
// not only the detected ones.
type authorship struct {
	gen   *pseudo.Generator
	mem   *mapping.Memory
	table *mapping.Table
	terms detect.Detector
	nets  []netip.Prefix
	roles []string

	// firstUser and firstModel hold, per value, the index of the message
	// in which it first stood on the user's side or in the model's output;
	// systemIndex is the system prompt and everything outside the
	// messages.
	firstUser  map[valueKey]int
	firstModel map[valueKey]int
	// authored is the decision of this request, see decide.
	authored map[valueKey]bool
	// scans caches the matches per text, so the rewriting pass detects
	// nothing a second time. Detection is deterministic over a text, and
	// the table grows only in the rewriting pass.
	scans map[string][]detect.Match
}

// valueKey is the identity of a detected value, as in the mapping table.
type valueKey struct {
	kind  detect.Kind
	value string
}

// systemIndex orders the system prompt, and every string outside the
// messages, in front of the first message.
const systemIndex = -1

func newAuthorship(gen *pseudo.Generator, mem *mapping.Memory, table *mapping.Table, terms detect.Detector, nets []netip.Prefix, roles []string) *authorship {
	return &authorship{
		gen:        gen,
		mem:        mem,
		table:      table,
		terms:      terms,
		nets:       nets,
		roles:      roles,
		firstUser:  make(map[valueKey]int),
		firstModel: make(map[valueKey]int),
		authored:   make(map[valueKey]bool),
		scans:      make(map[string][]detect.Match),
	}
}

// matches returns the detector's matches over text, from the cache after
// the first call.
func (a *authorship) matches(det detect.Detector, text string) []detect.Match {
	if m, ok := a.scans[text]; ok {
		return m
	}
	m := det.Scan(text)
	a.scans[text] = m
	return m
}

// place returns the index of the message the path belongs to and whether
// that message is the model's own output.
func (a *authorship) place(path payload.Path) (index int, model bool) {
	if len(path) >= 2 && path[0] == "messages" {
		if i, err := strconv.Atoi(path[1]); err == nil && i >= 0 {
			return i, i < len(a.roles) && a.roles[i] == "assistant"
		}
	}
	return systemIndex, false
}

// observe is the reading pass over one string: it detects, and notes for
// every value where it stood first. In the model's output the hits of the
// term list are passed over, because a term is never the model's to give
// away, and every token that could be a path segment or a file name is
// noted as well.
func (a *authorship) observe(det detect.Detector, path payload.Path, text string) {
	matches := a.matches(det, text)
	index, model := a.place(path)
	if !model {
		for _, m := range matches {
			noteFirst(a.firstUser, valueKey{m.Kind, m.Value}, index)
		}
		return
	}
	for _, m := range matches {
		if m.Source == "terms" {
			continue
		}
		noteFirst(a.firstModel, valueKey{m.Kind, m.Value}, index)
	}
	for _, tok := range detect.SegmentTokens(text) {
		noteFirst(a.firstModel, valueKey{detect.KindPathSegment, tok}, index)
		noteFirst(a.firstModel, valueKey{detect.KindFileName, tok}, index)
	}
}

func noteFirst(m map[valueKey]int, k valueKey, index int) {
	if old, ok := m[k]; !ok || index < old {
		m[k] = index
	}
}

// decide settles, after the reading pass, which values the model wrote
// first: those it had before the user's side, that the table does not
// hold, and that the memory of the conversation has not seen replaced. The
// last two are what keeps a value the model repeats from an earlier turn,
// restored by the client, from counting as its own.
func (a *authorship) decide() {
	for k, im := range a.firstModel {
		if iu, ok := a.firstUser[k]; ok && iu < im {
			continue
		}
		if a.table != nil && a.table.Has(k.kind, k.value) {
			continue
		}
		if a.mem != nil && a.mem.Seen(a.key(k)) {
			continue
		}
		a.authored[k] = true
	}
}

// exempt reports whether the rewriting pass leaves m standing, and marks
// the value in the memory of the conversation when it does, so that a
// compaction of the history, which repeats the value on the user's side,
// does not turn it into a pseudonym later. A hit of the term list, a value
// with a term inside it and an address in a listed network are never
// exempt.
func (a *authorship) exempt(m detect.Match) bool {
	if a == nil || m.Source == "terms" {
		return false
	}
	k := valueKey{m.Kind, m.Value}
	key := a.key(k)
	if !a.authored[k] && !(a.mem != nil && a.mem.Authored(key)) {
		return false
	}
	if a.insideNetworks(m) || (a.terms != nil && len(a.terms.Scan(m.Value)) > 0) {
		return false
	}
	if a.mem != nil {
		a.mem.MarkAuthored(key)
	}
	return true
}

// seen records in the memory of the conversation that m was replaced, so
// the value is known as the plugin's even after its table has expired.
func (a *authorship) seen(m detect.Match) {
	if a == nil || a.mem == nil {
		return
	}
	a.mem.MarkSeen(a.key(valueKey{m.Kind, m.Value}))
}

// key derives the memory key of a value: the conversation's own digest,
// so the memory holds no clear text and no key of one conversation means
// anything in another.
func (a *authorship) key(k valueKey) string {
	return string(a.gen.Digest(k.kind, k.value, 0)[:mapping.MemoryKeyLen])
}

// insideNetworks reports whether m is an address or a network inside one
// of the networks the term list names.
func (a *authorship) insideNetworks(m detect.Match) bool {
	switch m.Kind {
	case detect.KindIPv4, detect.KindIPv6:
		addr, err := netip.ParseAddr(m.Value)
		if err != nil {
			return false
		}
		for _, n := range a.nets {
			if n.Contains(addr) {
				return true
			}
		}
	case detect.KindCIDR:
		pfx, err := netip.ParsePrefix(m.Value)
		if err != nil {
			return false
		}
		for _, n := range a.nets {
			if n.Contains(pfx.Addr()) || pfx.Contains(n.Addr()) {
				return true
			}
		}
	}
	return false
}
