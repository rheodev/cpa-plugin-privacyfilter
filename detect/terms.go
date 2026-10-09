package detect

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Term is one entry of the maintained list: a literal or a regular
// expression, together with the kind its hits are rendered as.
type Term struct {
	// Value is a literal to look for. Exactly one of Value and Regex is set.
	Value string
	// Regex is a Go regular expression (RE2 syntax). Exactly one of Value and
	// Regex is set.
	Regex string
	// Kind is the kind assigned to every hit of this term.
	Kind Kind
	// IgnoreCase makes a literal match regardless of letter case. It has no
	// effect on Regex; write (?i) there instead.
	IgnoreCase bool
}

// TermsConfig configures the maintained list. It is the shape the YAML
// section terms[] is decoded into; the plugin's config layer does the
// decoding and passes the result here.
type TermsConfig struct {
	Terms []Term
	// WordBoundary requires a hit to be delimited on both sides by a
	// character that is neither a letter nor a digit, or by the text
	// boundary; the underscore is a boundary. It keeps "lan" from matching
	// inside "plan" while still matching "athene.lan" inside "ssh athene.lan"
	// and "nuc" inside "nuc_old". The rule holds for regular expressions as
	// for literals: an expression that matches inside a longer token would
	// leave a pseudonym the return path never resolves, because a pseudonym
	// glued to a word is no pseudonym there. The plugin sets it.
	WordBoundary bool
}

// NewTerms builds the detector for the maintained list. Literals are matched
// with a multi-pattern search (Aho-Corasick), regular expressions one by one.
// It returns an error for an empty term, a term with both Value and Regex, an
// invalid kind, or a regular expression that does not compile.
//
// Precedence inside the list follows the general Merge rule: the longer hit
// wins, ties go to the earlier one.
func NewTerms(cfg TermsConfig) (Detector, error) {
	d := &termsDetector{wordBoundary: cfg.WordBoundary}
	var exact, folded []string
	for i, t := range cfg.Terms {
		switch {
		case t.Value == "" && t.Regex == "":
			return nil, fmt.Errorf("detect: term %d has neither Value nor Regex", i)
		case t.Value != "" && t.Regex != "":
			return nil, fmt.Errorf("detect: term %d has both Value and Regex", i)
		}
		if !t.Kind.Valid() {
			return nil, fmt.Errorf("detect: term %d has invalid kind %q, want one of %s", i, string(t.Kind), KindNames())
		}
		if t.Regex != "" {
			re, err := regexp.Compile(t.Regex)
			if err != nil {
				return nil, fmt.Errorf("detect: term %d regex %q: %w", i, t.Regex, err)
			}
			d.regexps = append(d.regexps, re)
			d.regexKinds = append(d.regexKinds, t.Kind)
			continue
		}
		if t.IgnoreCase {
			folded = append(folded, caseFold(t.Value))
			d.foldedKinds = append(d.foldedKinds, t.Kind)
		} else {
			exact = append(exact, t.Value)
			d.exactKinds = append(d.exactKinds, t.Kind)
		}
	}
	if len(exact) > 0 {
		d.exact = newAho(exact)
	}
	if len(folded) > 0 {
		d.folded = newAho(folded)
	}
	return d, nil
}

// termsDetector is the compiled maintained list. It holds two automatons: one
// over the literals that respect letter case and one over the case-folded
// forms of the rest, which runs over the folded text. Regular expressions are
// applied one by one.
type termsDetector struct {
	wordBoundary bool

	exact      *ahoCorasick
	exactKinds []Kind

	folded      *ahoCorasick
	foldedKinds []Kind

	regexps    []*regexp.Regexp
	regexKinds []Kind
}

var _ Detector = (*termsDetector)(nil)

// Name implements Detector.
func (d *termsDetector) Name() string { return "terms" }

// Scan implements Detector. Overlapping hits of the list are resolved by
// Merge over the single layer, so the longer literal wins: p14.local beats
// p14, wendler.de beats wendler.
func (d *termsDetector) Scan(text string) []Match {
	if text == "" {
		return nil
	}
	var hits []Match
	add := func(start, end int, kind Kind) {
		if !spanAligned(text, start, end) {
			return
		}
		if d.wordBoundary && !hasWordBoundaries(text, start, end) {
			return
		}
		hits = append(hits, Match{Start: start, End: end, Value: text[start:end], Kind: kind, Source: "terms"})
	}
	if d.exact != nil {
		d.exact.find(text, func(start, end, pattern int) { add(start, end, d.exactKinds[pattern]) })
	}
	if d.folded != nil {
		// caseFold keeps every byte offset, so the spans found in the folded
		// text address the same runes in the original.
		d.folded.find(caseFold(text), func(start, end, pattern int) { add(start, end, d.foldedKinds[pattern]) })
	}
	for i, re := range d.regexps {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			add(loc[0], loc[1], d.regexKinds[i])
		}
	}
	return Merge(hits)
}

// caseFold lowercases s without moving a single byte offset: a rune is only
// replaced when its lower-case form has the same encoded length, which holds
// for ASCII and for the Latin, Greek and Cyrillic letters that matter here.
// The rare rune that would grow or shrink, such as the dotted capital I, is
// left as it is; a term containing one is folded the same way and still
// matches itself.
func caseFold(s string) string {
	needs := false
	for _, r := range s {
		if l := unicode.ToLower(r); l != r && utf8.RuneLen(l) == utf8.RuneLen(r) {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i, r := range s {
		_, size := utf8.DecodeRuneInString(s[i:])
		if l := unicode.ToLower(r); l != r && utf8.RuneLen(l) == size {
			b.WriteRune(l)
			continue
		}
		b.WriteString(s[i : i+size])
	}
	return b.String()
}
