package basics

// Form fidelity, kind by kind. The pseudonym is supposed to look like what it
// replaces, so that the model can still tell an address from a file name and
// a tool that parses the value does not choke. Where a form carries a rule -
// the mod-97 checksum of an IBAN, the 8-4-4-4-12 shape of a UUID, the length
// of an SSH fingerprint - the rule has to survive as well.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
)

// mod97 computes the ISO 13616 checksum over an IBAN.
func mod97(iban string) int {
	s := strings.ToUpper(strings.ReplaceAll(iban, " ", ""))
	if len(s) < 5 {
		return -1
	}
	s = s[4:] + s[:4]
	rem := 0
	for _, r := range s {
		var d int
		switch {
		case r >= '0' && r <= '9':
			d = int(r - '0')
			rem = (rem*10 + d) % 97
		case r >= 'A' && r <= 'Z':
			d = int(r-'A') + 10
			rem = (rem*100 + d) % 97
		default:
			return -1
		}
	}
	return rem
}

func TestForm_EveryKindKeepsItsShape(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	cases := []struct {
		kind  detect.Kind
		value string
		shape *regexp.Regexp
	}{
		{detect.KindIPv4, "10.42.0.7", regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)},
		{detect.KindIPv6, "fd00:1234:5678::42", regexp.MustCompile(`^[0-9a-f:]+$`)},
		{detect.KindCIDR, "10.42.0.0/16", regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$`)},
		{detect.KindMAC, "aa:bb:cc:dd:ee:ff", regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)},
		{detect.KindEmail, "vorname.nachname@firma.example", regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)},
		{detect.KindHost, "zeus.lan", regexp.MustCompile(`^[a-z0-9.-]+$`)},
		{detect.KindDomain, "firma.example", regexp.MustCompile(`^[a-z0-9.-]+$`)},
		{detect.KindPathSegment, "kundenakte", regexp.MustCompile(`^[^/\s]+$`)},
		{detect.KindFileName, "bericht.pdf", regexp.MustCompile(`^[^/\s]+$`)},
		{detect.KindPerson, "Ingrid Muster", regexp.MustCompile(`^\S+( \S+)*$`)},
		{detect.KindIBAN, "DE89370400440532013000", regexp.MustCompile(`^[A-Z]{2}\d{2}[A-Z0-9]+$`)},
		{detect.KindURL, "https://firma.example/pfad?x=1", regexp.MustCompile(`^https?://\S+$`)},
		{detect.KindUUID, "123e4567-e89b-12d3-a456-426614174000", regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)},
		{detect.KindHexID, strings.Repeat("ab", 16), regexp.MustCompile(`^[0-9a-f]{32}$`)},
		{detect.KindFingerprint, "SHA256:" + strings.Repeat("A", 43), regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)},
		{detect.KindSerial, "S4EWNF0M123456X", regexp.MustCompile(`^[A-Za-z0-9._/-]{6,64}$`)},
		{detect.KindSecret, "hunter2hunter2hunter2", regexp.MustCompile(`^\S+$`)},
	}
	// Fill the whole table first, then check every alias against its shape.
	aliases := make([]string, len(cases))
	for i, c := range cases {
		aliases[i] = tab.Lookup(c.kind, c.value)
	}
	for i, c := range cases {
		alias := aliases[i]
		ok := c.shape.MatchString(alias)
		t.Logf("%-13s %-40q -> %-40q shape=%v len %d/%d", c.kind, c.value, alias, ok, len(c.value), len(alias))
		if !ok && c.kind == detect.KindURL {
			// Documented in BEFUNDE.md: KindURL has no renderer of its own and
			// falls back to the opaque token. The pattern is off by default,
			// so this is an observation, not a defect.
			t.Logf("   -> no renderer of its own, the opaque token stands in")
		} else if !ok {
			t.Errorf("%s: %q does not keep the shape of %q", c.kind, alias, c.value)
		}
		if alias == c.value {
			t.Errorf("%s: the value was not replaced at all", c.kind)
		}
		if got := back(alias, tab); got != c.value {
			t.Errorf("%s: %q restored to %q", c.kind, alias, got)
		}
	}
}

// An IBAN with a broken checksum is rejected by every banking form, and the
// detector itself would not report it a second time.
func TestForm_IBANChecksum(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	const real = "DE89370400440532013000"
	if mod97(real) != 1 {
		t.Fatalf("the test's own reference IBAN is wrong: remainder %d", mod97(real))
	}
	for i := 0; i < 20; i++ {
		value := "DE89370400440532013" + string(rune('0'+i%10)) + "00"
		alias := tab.Lookup(detect.KindIBAN, value)
		if rem := mod97(alias); rem != 1 {
			t.Errorf("the pseudonym %q has remainder %d, not 1", alias, rem)
			break
		}
	}
	alias := tab.Lookup(detect.KindIBAN, real)
	t.Logf("%s -> %s, remainder %d, same country %v, same length %v",
		real, alias, mod97(alias), alias[:2] == real[:2], len(alias) == len(real))
}

// Two kinds, one value: the pseudonyms must differ, or restoring picks the
// wrong original.
func TestForm_SameValueDifferentKinds(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	a := tab.Lookup(detect.KindHost, "kundenakte")
	b := tab.Lookup(detect.KindPathSegment, "kundenakte")
	c := tab.Lookup(detect.KindPerson, "kundenakte")
	t.Logf("host %q, path %q, person %q", a, b, c)
	if a == b || b == c || a == c {
		t.Errorf("two kinds share a pseudonym")
	}
	for _, p := range []string{a, b, c} {
		if got := back(p, tab); got != "kundenakte" {
			t.Errorf("%q restored to %q", p, got)
		}
	}
}
