package detect

import (
	"strings"

	"privacyfilter/filter"
)

// PackymeConfig says which of the library's own findings are kept. The
// library has no switches per kind: it always reports IP addresses and
// e-mail addresses next to the credential rules. The toggles of the
// structural patterns are therefore applied to its findings here, so that
// switching ipv4 off means no IPv4 address is replaced by any layer. Hits of
// KindSecret, the credential rules, phone and identity numbers and bank
// cards, are always kept; they are switched off as a whole with the layer.
type PackymeConfig struct {
	IPv4  bool
	IPv6  bool
	Email bool
}

// NewPackyme wraps the existing detection library as one layer. It calls
// Redact and uses only the Entities of the result: Start and End become the
// span, Text becomes Value, and Type is translated with KindFromPackyme. The
// field Redacted is ignored. Findings of a kind that cfg switches off are
// dropped.
//
// The wrapped filter must be the same instance the redact mode uses, so both
// modes see identical hits.
func NewPackyme(f *filter.Filter, cfg PackymeConfig) Detector {
	return &packymeDetector{filter: f, cfg: cfg}
}

// packymeDetector adapts packyme/privacy-filter to the Detector interface.
type packymeDetector struct {
	filter *filter.Filter
	cfg    PackymeConfig
}

var _ Detector = (*packymeDetector)(nil)

// Name implements Detector.
func (p *packymeDetector) Name() string { return "packyme" }

// Scan implements Detector. Redact is called for its Entities alone; the
// redacted text it also produces belongs to the other mode and is dropped
// here. Value is taken from the scanned text rather than from Entity.Text so
// the span and the value can never disagree.
func (p *packymeDetector) Scan(text string) []Match {
	if p == nil || p.filter == nil || text == "" {
		return nil
	}
	res := p.filter.Redact(text)
	if len(res.Entities) == 0 {
		return nil
	}
	hits := make([]Match, 0, len(res.Entities))
	for _, e := range res.Entities {
		if !spanAligned(text, e.Start, e.End) {
			continue
		}
		value := text[e.Start:e.End]
		kind := KindFromPackyme(e.Type)
		// The library files both address families under one type; the text
		// decides which one it is.
		if kind == KindIPv4 && strings.Contains(value, ":") {
			kind = KindIPv6
		}
		if !p.keeps(kind) {
			continue
		}
		hits = append(hits, Match{Start: e.Start, End: e.End, Value: value, Kind: kind, Source: "packyme"})
	}
	return Merge(hits)
}

// keeps applies the kind toggles of PackymeConfig. Every kind the config
// does not name is kept.
func (p *packymeDetector) keeps(kind Kind) bool {
	switch kind {
	case KindIPv4:
		return p.cfg.IPv4
	case KindIPv6:
		return p.cfg.IPv6
	case KindEmail:
		return p.cfg.Email
	}
	return true
}

// Type ids the library writes into Entity.Type (filter/pii.go and
// filter/secrets.go). They are the keys of replacement_labels as well. Every
// credential rule reports PackymeTypeSecret, whatever its rule id; the label
// a type is rendered with in redact mode is not part of Entity.Type.
const (
	PackymeTypeEmail    = "email"
	PackymeTypePhone    = "phone"
	PackymeTypeIdentity = "id"
	PackymeTypeIP       = "ip"
	PackymeTypeBankCard = "bank_card"
	PackymeTypeSecret   = "secret"
)

// KindFromPackyme maps an Entity.Type of the library to a Kind.
// PackymeTypeEmail maps to KindEmail. PackymeTypeIP covers both address
// families in the library; the wrapper decides between KindIPv4 and KindIPv6
// by parsing Entity.Text, which is why the type alone maps to KindIPv4 here
// and the wrapper corrects it for colon-separated addresses. Every other
// type, including phone numbers, identity numbers, bank cards, the credential
// rules and any type a later library adds, maps to KindSecret and is rendered
// as an opaque token.
func KindFromPackyme(entityType string) Kind {
	switch entityType {
	case PackymeTypeEmail:
		return KindEmail
	case PackymeTypeIP:
		return KindIPv4
	}
	return KindSecret
}
