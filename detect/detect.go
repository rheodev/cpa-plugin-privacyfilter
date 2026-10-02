// Package detect finds confidential values in text and reports them as
// byte spans. It is the detection layer of the pseudonymize mode: several
// independent detectors scan the same text, and Merge collapses their hits
// into one disjoint list that the replacement step can apply from left to
// right.
//
// Every detector must be a pure function of the scanned text. The same
// message appears in every request of a conversation, and the thinking-block
// signatures of the Claude API bind the exact prefix that produced them;
// a detector whose output depends on time, randomness, or map iteration
// order would break that prefix between two requests.
//
// Offsets are byte offsets into the UTF-8 text and always fall on rune
// boundaries.
package detect

import (
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrNotImplemented marks a contract stub that has no implementation yet.
// It disappears once the packages are filled in; tests never expect it.
var ErrNotImplemented = errors.New("detect: not implemented")

// Kind classifies a match. The kind selects the pseudonym renderer and is
// part of the HMAC input, so two kinds never share a pseudonym even when the
// original values are equal. The string values are the ones accepted in the
// plugin configuration under terms[].kind.
type Kind string

const (
	KindIPv4        Kind = "ipv4"
	KindIPv6        Kind = "ipv6"
	KindCIDR        Kind = "cidr"
	KindMAC         Kind = "mac"
	KindEmail       Kind = "email"
	KindHost        Kind = "host"
	KindDomain      Kind = "domain"
	KindPathSegment Kind = "path_segment"
	KindFileName    Kind = "filename"
	KindPerson      Kind = "person"
	KindIBAN        Kind = "iban"
	KindURL         Kind = "url"
	// The machine identifiers: a UUID in the 8-4-4-4-12 form (disk and
	// partition UUIDs, product UUIDs, GUIDs), a bare hex identifier of 32
	// digits or of "0x" and 16 digits (machine-id, a disk's WWN), an SSH key
	// fingerprint in the SHA256:<base64> form, and a serial number that
	// follows a label such as "Serial Number:" or "ID_SERIAL=".
	KindUUID        Kind = "uuid"
	KindHexID       Kind = "hexid"
	KindFingerprint Kind = "fingerprint"
	KindSerial      Kind = "serial"
	// KindSecret covers credentials and every hit whose type has no dedicated
	// renderer; it is rendered as an opaque token nobody computes with.
	KindSecret Kind = "secret"
)

// Kinds lists the declared kinds in the order of their declaration, for
// error messages and documentation.
func Kinds() []Kind {
	return []Kind{
		KindIPv4, KindIPv6, KindCIDR, KindMAC, KindEmail, KindHost, KindDomain,
		KindPathSegment, KindFileName, KindPerson, KindIBAN, KindURL,
		KindUUID, KindHexID, KindFingerprint, KindSerial, KindSecret,
	}
}

// KindNames returns the declared kinds as one comma-separated string.
func KindNames() string {
	kinds := Kinds()
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = string(k)
	}
	return strings.Join(names, ", ")
}

// Valid reports whether k is one of the declared kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindIPv4, KindIPv6, KindCIDR, KindMAC, KindEmail, KindHost, KindDomain,
		KindPathSegment, KindFileName, KindPerson, KindIBAN, KindURL,
		KindUUID, KindHexID, KindFingerprint, KindSerial, KindSecret:
		return true
	}
	return false
}

// Match is one hit inside the scanned text.
type Match struct {
	// Start and End are byte offsets, End exclusive: text[Start:End] == Value.
	Start, End int
	// Value is the matched original text, exactly as it appears.
	Value string
	// Kind selects the pseudonym renderer.
	Kind Kind
	// excluded marks a match that Composite.Exclude accepted. It keeps its
	// place in Merge, so a match of a later layer that overlaps it is
	// suppressed exactly as it would be by a reported match, and it is
	// dropped from the result afterwards. That is what keeps a second
	// forward pass over pseudonymized text a no-op: a lower layer that
	// matches a wider span around a value, as a credential rule matches
	// "Host-Key SHA256:…", loses to the structural hit on the value itself
	// on the first pass, and must lose to the pseudonym on the second.
	excluded bool
	// Source names the detector that produced the match, for logs and tests
	// (for example "terms", "patterns", "packyme", "betterleaks").
	Source string
}

// Len returns the span length in bytes.
func (m Match) Len() int { return m.End - m.Start }

// Overlaps reports whether the two spans share at least one byte. Touching
// spans (m.End == o.Start) do not overlap.
func (m Match) Overlaps(o Match) bool {
	return m.Start < o.End && o.Start < m.End
}

// Detector scans a text and returns its hits in any order. Implementations
// must be safe for concurrent use and deterministic: the same text yields the
// same matches on every call.
type Detector interface {
	// Name identifies the detector; it is copied into Match.Source.
	Name() string
	// Scan returns every hit in text. Returned spans may overlap each other;
	// Merge resolves that. Scan never returns a span outside [0, len(text)]
	// or one that splits a rune.
	Scan(text string) []Match
}

// Merge collapses the hits of several detectors into one disjoint list.
//
// The layers are given in order of precedence: a match from an earlier layer
// wins against every match of a later layer it overlaps. Inside one layer the
// longer match wins, and among equal lengths the one with the smaller Start.
// The result is sorted by Start, contains no overlapping spans, and is
// identical for identical input. Merge never modifies its arguments.
func Merge(layers ...[]Match) []Match {
	total, maxEnd := 0, 0
	for _, l := range layers {
		total += len(l)
		for _, m := range l {
			if m.Start >= 0 && m.Start < m.End && m.End > maxEnd {
				maxEnd = m.End
			}
		}
	}
	if total == 0 {
		return nil
	}
	f := newSpanFilter(total, maxEnd)
	// One layer at a time, so every hit of an earlier layer is already
	// accepted when a later layer is offered. Inside a layer the candidates
	// are tried longest first; ties go to the smaller Start. SliceStable on a
	// copy keeps the order of full ties at the caller's order, which makes the
	// result a pure function of the input and leaves the arguments untouched.
	for _, layer := range layers {
		if len(layer) == 0 {
			continue
		}
		cand := make([]Match, 0, len(layer))
		for _, m := range layer {
			if m.Start < 0 || m.Start >= m.End {
				continue
			}
			cand = append(cand, m)
		}
		sort.SliceStable(cand, func(i, j int) bool {
			if a, b := cand[i].Len(), cand[j].Len(); a != b {
				return a > b
			}
			return cand[i].Start < cand[j].Start
		})
		for _, m := range cand {
			f.offer(m)
		}
	}
	return f.result()
}

// spanFilterBitsetMin is the number of candidates from which the coverage
// bitset is worth its allocation. Below it the sorted insertion moves a few
// hundred bytes per candidate and needs no extra memory; above it the shift
// per insertion is what dominates the run time.
const spanFilterBitsetMin = 64

// spanFilter is the greedy disjointness rule behind Merge: candidates are
// offered in order of precedence, and one that overlaps an already accepted
// span is dropped. Two strategies implement the same rule. For few candidates
// the accepted list is kept sorted by Start, where the two neighbours of the
// insertion point are the only ones that can overlap. From spanFilterBitsetMin
// candidates on, a bitset marks the covered bytes, the overlap test reads it
// word by word, and the result is sorted once at the end; that keeps a log
// dump with a hundred thousand hits linear in the number of matches instead of
// quadratic. Both paths accept exactly the same candidates and return them
// sorted by Start.
type spanFilter struct {
	cover []uint64 // nil while the sorted insertion is used
	acc   []Match
}

// newSpanFilter prepares a filter for count candidates whose spans all end at
// or before maxEnd.
func newSpanFilter(count, maxEnd int) *spanFilter {
	f := &spanFilter{acc: make([]Match, 0, count)}
	if count >= spanFilterBitsetMin && maxEnd > 0 {
		f.cover = make([]uint64, (maxEnd+63)/64)
	}
	return f
}

// offer accepts m unless it overlaps a span accepted before, and reports
// whether it was accepted.
func (f *spanFilter) offer(m Match) bool {
	if f.cover == nil {
		var ok bool
		f.acc, ok = insertDisjoint(f.acc, m)
		return ok
	}
	if m.Start < 0 || m.Start >= m.End || m.End > len(f.cover)*64 {
		return false
	}
	if !f.free(m.Start, m.End) {
		return false
	}
	f.mark(m.Start, m.End)
	f.acc = append(f.acc, m)
	return true
}

// result returns the accepted matches sorted by Start. The starts are unique,
// because the accepted spans are disjoint and non-empty, so the order is total
// and the result a pure function of the offered candidates.
func (f *spanFilter) result() []Match {
	if len(f.acc) == 0 {
		return nil
	}
	if f.cover != nil {
		sort.Slice(f.acc, func(i, j int) bool { return f.acc[i].Start < f.acc[j].Start })
	}
	return f.acc
}

// free reports whether no byte of [start, end) is covered yet.
func (f *spanFilter) free(start, end int) bool {
	lo, hi := start/64, (end-1)/64
	if lo == hi {
		return f.cover[lo]&spanMask(uint(start%64), uint((end-1)%64)) == 0
	}
	if f.cover[lo]&spanMask(uint(start%64), 63) != 0 {
		return false
	}
	for w := lo + 1; w < hi; w++ {
		if f.cover[w] != 0 {
			return false
		}
	}
	return f.cover[hi]&spanMask(0, uint((end-1)%64)) == 0
}

// mark records [start, end) as covered.
func (f *spanFilter) mark(start, end int) {
	lo, hi := start/64, (end-1)/64
	if lo == hi {
		f.cover[lo] |= spanMask(uint(start%64), uint((end-1)%64))
		return
	}
	f.cover[lo] |= spanMask(uint(start%64), 63)
	for w := lo + 1; w < hi; w++ {
		f.cover[w] = ^uint64(0)
	}
	f.cover[hi] |= spanMask(0, uint((end-1)%64))
}

// spanMask returns the bits lo to hi of one word, both ends included.
func spanMask(lo, hi uint) uint64 {
	return (^uint64(0) << lo) & (^uint64(0) >> (63 - hi))
}

// insertDisjoint inserts m into acc, which is kept sorted by Start and free of
// overlaps, and reports whether it was inserted. An overlapping m is dropped.
// Because acc is disjoint and sorted, the two neighbours of the insertion
// point are the only ones that can overlap m.
func insertDisjoint(acc []Match, m Match) ([]Match, bool) {
	i := sort.Search(len(acc), func(k int) bool { return acc[k].Start >= m.Start })
	if i > 0 && acc[i-1].End > m.Start {
		return acc, false
	}
	if i < len(acc) && m.End > acc[i].Start {
		return acc, false
	}
	acc = append(acc, Match{})
	copy(acc[i+1:], acc[i:])
	acc[i] = m
	return acc, true
}

// isRuneBoundary reports whether byte offset i starts a rune of text.
func isRuneBoundary(text string, i int) bool {
	if i <= 0 || i >= len(text) {
		return i == 0 || i == len(text)
	}
	return text[i]&0xC0 != 0x80
}

// spanAligned reports whether [start, end) is a non-empty span of text whose
// ends fall on rune boundaries.
func spanAligned(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	return isRuneBoundary(text, start) && isRuneBoundary(text, end)
}

// isWordRune reports whether r is a word character for the boundary rule:
// letters and digits. Dot, hyphen and underscore are deliberately not word
// characters, so "athene.lan", "nuc-lan" and "nuc_old" split into parts:
// a host name glued to a suffix with an underscore, as in a variable name,
// a unit name or an archive name, is still that host and must be found.
// The price is that "lan" matches inside "vlan_lan"; it does not match
// inside "plan", because letters still bind.
func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// hasWordBoundaries reports whether [start, end) is delimited on both sides by
// a non-word rune or by the edge of text. A percent-escape in front, the
// "%20" of an encoded path, delimits as well although it ends in a hex
// digit; see PercentEscapeEnds.
func hasWordBoundaries(text string, start, end int) bool {
	if start > 0 && !PercentEscapeEnds(text[:start]) {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); isWordRune(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); isWordRune(r) {
			return false
		}
	}
	return true
}

// isTokenRune reports whether r can be part of a structural token: letters and
// digits, the same set as isWordRune. Both rules exist because the term
// list once treated the underscore as binding; they are kept apart so a
// change to one does not silently change the other.
func isTokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// hasTokenBoundaries reports whether [start, end) is delimited on both sides by
// a rune that is neither a letter nor a digit, by a percent-escape in front,
// or by the edge of text. It is the boundary rule of the structural layer;
// hasWordBoundaries is the stricter rule of the maintained list.
func hasTokenBoundaries(text string, start, end int) bool {
	if start > 0 && !PercentEscapeEnds(text[:start]) {
		if r, _ := utf8.DecodeLastRuneInString(text[:start]); isTokenRune(r) {
			return false
		}
	}
	if end < len(text) {
		if r, _ := utf8.DecodeRuneInString(text[end:]); isTokenRune(r) {
			return false
		}
	}
	return true
}

// Composite runs several detectors over the same text, in order of
// precedence, and merges their hits. Exclude, when set, drops every match
// whose Value it accepts; the plugin passes the Knows method of the
// conversation's mapping table, so a pseudonym the plugin itself produced is
// left alone (idempotence over the history of a conversation) while a real
// value that merely has the shape of one, such as a node address out of the
// carrier-grade NAT range, is replaced like any other. An excluded match
// still takes part in the precedence: it shields its span from the matches
// of later layers, see Match.excluded.
type Composite struct {
	Layers  []Detector
	Exclude func(value string) bool
}

var _ Detector = (*Composite)(nil)

// NewComposite builds a Composite. The first detector has the highest
// precedence. The maintained term list always comes first in the plugin.
func NewComposite(exclude func(value string) bool, layers ...Detector) *Composite {
	return &Composite{Layers: layers, Exclude: exclude}
}

// Name implements Detector.
func (c *Composite) Name() string { return "composite" }

// promoteContaining returns the matches of later layers that strictly
// contain a match of an earlier layer, so that Merge accepts them ahead of
// every layer. Without it the precedence of the term list breaks a longer
// value apart: a term that names the customer wins over the directory
// "customer-4711" the path layer would have replaced whole, and the case
// number leaves in clear text; a domain term wins over the e-mail address
// around it and the local part leaves; a short term inside a dotted quad
// leaves the remaining octets standing. A value that carries a confidential
// part is confidential as a whole and is replaced as one match of the
// containing kind. Four rules keep the precedence otherwise intact. A match
// over exactly the same span is not promoted, so the earlier layer still
// decides the kind of a value both report. An excluded inner match, a
// pseudonym of an earlier pass, does not promote, because the value around
// it is already the plugin's own output and must stay as it is. A match of
// KindSecret is never promoted: the credential rules of the original
// detection cut loose spans such as "Host-Key <fingerprint>. ", and an
// opaque token in place of a structured value would take from the model
// what the kind of the inner match preserves. And the containing match must
// stand on token boundaries in the text, or it is a partial hit itself.
//
// The earlier matches are sorted by Start once, and for every later match
// only the earlier ones that begin inside its span are looked at, so the
// cost is linear in the length of the text for the detectors of this
// plugin.
func promoteContaining(text string, layers [][]Match) []Match {
	var promoted []Match
	var earlier []Match
	for li := 1; li < len(layers); li++ {
		if len(layers[li-1]) > 0 {
			for _, n := range layers[li-1] {
				if !n.excluded && n.Start >= 0 && n.Start < n.End {
					earlier = append(earlier, n)
				}
			}
			sort.SliceStable(earlier, func(i, j int) bool { return earlier[i].Start < earlier[j].Start })
		}
		if len(earlier) == 0 {
			continue
		}
		for _, m := range layers[li] {
			if m.excluded || m.Kind == KindSecret || m.Start < 0 || m.Start >= m.End || m.End > len(text) {
				continue
			}
			if !hasTokenBoundaries(text, m.Start, m.End) {
				continue
			}
			if containsEarlier(earlier, m) {
				promoted = append(promoted, m)
			}
		}
	}
	return promoted
}

// containsEarlier reports whether m strictly contains one of the matches in
// earlier, which are sorted by Start.
func containsEarlier(earlier []Match, m Match) bool {
	i := sort.Search(len(earlier), func(i int) bool { return earlier[i].Start >= m.Start })
	for ; i < len(earlier) && earlier[i].Start < m.End; i++ {
		n := earlier[i]
		if n.End <= m.End && n.Len() < m.Len() {
			return true
		}
	}
	return false
}

// Scan implements Detector: it scans with every layer, applies Exclude, and
// returns Merge over the layers in order.
func (c *Composite) Scan(text string) []Match {
	if c == nil || len(c.Layers) == 0 {
		return nil
	}
	layers := make([][]Match, 0, len(c.Layers))
	excluded := 0
	for _, d := range c.Layers {
		if d == nil {
			continue
		}
		hits := d.Scan(text)
		if c.Exclude != nil && len(hits) > 0 {
			// A copy, because Merge leaves its arguments alone and a
			// detector may hand out a slice it keeps.
			marked := make([]Match, len(hits))
			copy(marked, hits)
			for i := range marked {
				if c.Exclude(marked[i].Value) {
					marked[i].excluded = true
					excluded++
				}
			}
			hits = marked
		}
		layers = append(layers, hits)
	}
	merged := Merge(append([][]Match{promoteContaining(text, layers)}, layers...)...)
	if excluded == 0 {
		return merged
	}
	out := merged[:0]
	for _, m := range merged {
		if !m.excluded {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
