package pseudo

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Renderer turns a digest into a pseudonym of one kind and recognizes its
// own output. Implementations are stateless.
//
// Two properties are mandatory and are tested for every renderer: the output
// never looks like a value another detector would report (an IPv4 pseudonym
// lives in 100.64.0.0/10 and is excluded via IsPseudonym; a hostname
// pseudonym has no dot; a secret pseudonym has the prefix PF_), and the
// output is ASCII without characters that JSON escapes, so a pseudonym reads
// the same in a text field and inside a partial_json fragment.
type Renderer interface {
	// Kind is the kind this renderer serves.
	Kind() detect.Kind
	// Render builds the pseudonym from a DigestLen-byte digest. original is
	// the value being replaced; renderers use it only to carry format over
	// (file extension, prefix length, IBAN country and length, wildcard
	// positions), never its identifying content.
	Render(digest []byte, original string) string
	// Matches reports whether s, as a whole, could be an output of Render.
	Matches(s string) bool
	// MaxLen is an upper bound on len(Render(...)) for any input.
	MaxLen() int
}

// Pseudonym shapes per kind. The hex digits are lower case and taken from the
// start of the digest.
//
//	KindIPv4         100.{64..127}.x.y          (100.64.0.0/10, CGNAT)
//	KindIPv6         fdff:5046:5346:...         (a fixed /48 inside fd00::/8, ULA)
//	KindCIDR         address as above, prefix or mask kept
//	KindMAC          02:xx:xx:xx:xx:xx          (locally administered, unicast)
//	KindHost         h-<12hex>
//	KindDomain       d-<12hex>.invalid          (RFC 2606)
//	KindPathSegment  d-<12hex>
//	KindFileName     f-<12hex><ext>             (extension kept when it looks like one: a dot and up to five letters or digits)
//	KindEmail        u-<12hex>@d-<12hex>.invalid (composed by Generator, see Pseudonym)
//	KindPerson       a name from Names, indexed by the digest; when the
//	                 original has no space (a lone given name, nickname or
//	                 surname) only the given name of the entry is used, and
//	                 the letter case of the original's first character is
//	                 carried over, so "MARKUS" and "markus" both map to the
//	                 same entry but read as the original did
//	KindIBAN         same country and length as the original, digits from the digest, valid mod-97 check
//	KindSecret       PF_<12hex>
//	KindURL          not rendered before milestone 3; falls back to KindSecret
//
// Every shape carries a marker a real value of the same kind does not have,
// because Matches feeds IsPseudonym and a value that looks like a pseudonym
// is never replaced. Two exceptions are deliberate and both need a check in
// the wiring rather than here:
//
//   - KindIPv4 uses the whole CGNAT range 100.64.0.0/10, which is also the
//     range Tailscale and Headscale hand out to their nodes. A real address
//     from that range, and a network inside it, is taken for a pseudonym and
//     leaves the machine unchanged. The range is kept whole because a narrow
//     marker range inside it would collapse every masked IPv4 network to a
//     single pseudonym, which the mapping table cannot resolve by raising the
//     attempt. The wiring must therefore reject a configured KindIPv4 or
//     KindCIDR term that IsPseudonym accepts, before the first request runs.
//   - KindPerson renders an ordinary name from Names, so Matches accepts
//     every entry of that list and every given name in it. A configured
//     term that happens to equal one of them would never be replaced. The
//     wiring therefore builds its renderers with RenderersExcludingNames
//     over the configured literals: the entries they equal are left out of
//     the list for that plugin, Render skips them and Matches no longer
//     accepts them, and the term is replaced like any other. IsName tells
//     whether a value is such an entry.
const (
	PrefixHost        = "h-"
	PrefixDomain      = "d-"
	PrefixPathSegment = "d-"
	PrefixFileName    = "f-"
	PrefixUser        = "u-"
	PrefixSecret      = "PF_"
	SuffixDomain      = ".invalid"
	HexShort          = 12
	HexSecret         = 12
)

// Shape details that are not part of the exported contract but are needed so
// that Matches can tell a pseudonym from a real value of the same kind.
//
//   - maxExtLen bounds the file extension carried over, so MaxLen stays an
//     upper bound for any input; a longer extension is dropped. The bound is
//     deliberately tight, a dot and five bytes of letters and digits, because
//     whatever the renderer keeps leaves the machine in clear text. What
//     follows the last dot of a file name is not always an extension:
//     bericht.Meier-GmbH and export.P2026_4711 are everyday shapes, and there
//     the suffix is the very value that had to be replaced. Five bytes cover
//     the extensions a working tree really holds, from .go to .jsonl, and
//     exclude a customer name or a project number. A suffix that is short,
//     alphanumeric and still confidential, .ACME, cannot be told from .JPEG
//     by its form and is kept; only a list of known extensions would close
//     that, at the price of dropping the suffix of every file the list does
//     not know.
//   - ibanMarker is the fixed head of every pseudonym BBAN. Without it a
//     pseudonym IBAN would be indistinguishable from a real one: the country,
//     the length and the mod-97 check are all shared by construction, so a
//     real IBAN would be taken for a pseudonym, escape detection and leave the
//     machine. Four leading zeros are not a bank code any issuer hands out.
//   - ulaPseudoPrefix is the fixed /48 every IPv6 pseudonym lives in, the same
//     idea as ibanMarker. The whole of fd00::/8 would not do: a real ULA
//     address is not always written compressed, and a SLAAC host address such
//     as an EUI-64 one has eight non-zero groups and is its own canonical
//     form, so it would be taken for a pseudonym and would leave the machine
//     unchanged. Against the fixed /48 a real ULA network collides only if its
//     40 random global-ID bits happen to be exactly these.
const (
	maxExtLen  = 6
	ibanMarker = "0000"
	minIBANLen = 15
	maxIBANLen = 34
)

var (
	cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")
	// ulaPseudoPrefix is inside fd00::/8. The value carries no meaning beyond
	// being fixed and unlikely: the bytes behind fdff read "PFSF" as ASCII.
	// Changing it changes every IPv6 pseudonym, so it is as much part of the
	// contract as Names.
	ulaPseudoPrefix = netip.MustParsePrefix("fdff:5046:5346::/48")
	ulaPseudoHead   = ulaPseudoPrefix.Addr().As16()
)

// DefaultRenderers returns one renderer for every kind that has a dedicated
// shape. Kinds missing from the map are rendered by SecretRenderer.
func DefaultRenderers() map[detect.Kind]Renderer {
	return map[detect.Kind]Renderer{
		detect.KindIPv4:        ipv4Renderer{},
		detect.KindIPv6:        ipv6Renderer{},
		detect.KindCIDR:        cidrRenderer{},
		detect.KindMAC:         macRenderer{},
		detect.KindEmail:       emailRenderer{},
		detect.KindHost:        hostRenderer{},
		detect.KindDomain:      domainRenderer{},
		detect.KindPathSegment: pathSegmentRenderer{},
		detect.KindFileName:    fileNameRenderer{},
		detect.KindPerson:      personRenderer{},
		detect.KindIBAN:        ibanRenderer{},
		detect.KindUUID:        uuidRenderer{},
		detect.KindHexID:       hexIDRenderer{},
		detect.KindFingerprint: fingerprintRenderer{},
		detect.KindSerial:      serialRenderer{},
		detect.KindSecret:      SecretRenderer{},
	}
}

// SecretRenderer renders PF_<12hex>. It is the fallback for every kind
// without its own renderer.
type SecretRenderer struct{}

// Names is the fixed list of invented person names used by the person
// renderer. It contains given name and surname pairs that are common enough
// to read as names and are not those of well-known people. The list is part
// of the contract: changing it changes every person pseudonym, which is a
// change of the secret in effect and needs a new conversation to take
// effect (thinking-block signatures).
var Names = []string{
	"Lennart Bergmann",
	"Katharina Vogler",
	"Jonas Kestner",
	"Annika Dorsch",
	"Fabian Reuther",
	"Miriam Falkner",
	"Sebastian Kohlmann",
	"Carla Steinberg",
	"Julian Hardegen",
	"Nadine Wiegand",
	"Philipp Sorge",
	"Theresa Lindemann",
	"Matthias Brauer",
	"Sophie Kreiner",
	"Dominik Halbach",
	"Elena Ruppert",
	"Bastian Nolte",
	"Franziska Ebner",
	"Simon Kraushaar",
	"Verena Lohmann",
	"Christoph Deppe",
	"Johanna Rieger",
	"Timo Bendrich",
	"Lea Schuricht",
	"Andreas Kaltenbach",
	"Melanie Fuhrmann",
	"Niklas Ostermann",
	"Sandra Wiesner",
	"Florian Kempter",
	"Ines Grabowski",
	"Daniel Rehberg",
	"Helena Brunnert",
	"Marvin Sattler",
	"Clara Tiedemann",
	"Oliver Grenzmann",
	"Paula Wehrle",
	"Kevin Ostrowski",
	"Ruth Kleinschmidt",
	"Malte Sonnenberg",
	"Yvonne Draeger",
	"Gregor Waldner",
	"Isabel Hoffner",
	"Torben Klausner",
	"Marlene Kabisch",
	"Adrian Peiffer",
	"Rosa Lindquist",
	"Emil Warnecke",
	"Greta Nussbaum",
	"Henry Ashcombe",
	"Alice Bramley",
	"Oscar Fenwick",
	"Nora Whitcombe",
	"Edward Garnley",
	"Imogen Lockhart",
	"Nathan Priddy",
	"Rosalind Alderton",
	"Merrick Rathbone",
	"Freya Colston",
	"Owen Tremayne",
	"Harriet Woodfine",
	"Gordon Mabley",
	"Sylvia Renshaw",
	"Duncan Pellow",
	"Bridget Halloway",
	"Alistair Cobbett",
	"Rowena Stanfield",
	"Callum Braithwood",
	"Elsie Marchmont",
	"Rupert Danvers",
	"Tessa Ingoldsby",
	"Warren Fitchley",
	"Delia Ormsby",
}

// nameForms maps the lower-case spelling of every full name and of every
// given name to the spelling as it appears in Names. It is built once and
// only read afterwards, so no map iteration influences any output.
var nameForms = func() map[string]string {
	m := make(map[string]string, 2*len(Names))
	for _, n := range Names {
		m[strings.ToLower(n)] = n
		if i := strings.IndexByte(n, ' '); i > 0 {
			m[strings.ToLower(n[:i])] = n[:i]
		}
	}
	return m
}()

// IsName reports whether s is an entry of Names or the given name of one,
// regardless of letter case. A person pseudonym is an ordinary name, so
// every such string is its own pseudonym as far as the default person
// renderer can tell. A configured term equal to one of them is handled by
// PersonRendererExcluding, not refused.
func IsName(s string) bool {
	_, ok := nameForms[strings.ToLower(strings.TrimSpace(s))]
	return ok
}

// PersonRendererExcluding returns a person renderer whose list lacks every
// entry of Names that one of values equals, by full name or by given name,
// regardless of letter case, and the entries it dropped in list order.
// Values that are no list entry are ignored. The remaining entries keep
// their positions: a digest that selects a dropped entry moves on to the
// next kept one, every other digest renders exactly as with the full list,
// so adding such a term changes no pseudonym but the ones that would have
// collided.
func PersonRendererExcluding(values []string) (Renderer, []string) {
	excluded := map[string]bool{}
	var dropped []string
	for _, v := range values {
		key := strings.ToLower(strings.TrimSpace(v))
		if _, ok := nameForms[key]; !ok {
			continue
		}
		for _, entry := range Names {
			full := strings.ToLower(entry)
			given := full[:strings.IndexByte(full, ' ')]
			if (full == key || given == key) && !excluded[full] {
				excluded[full] = true
				excluded[given] = true
				dropped = append(dropped, entry)
			}
		}
	}
	if len(dropped) == 0 {
		return personRenderer{}, nil
	}
	return personRenderer{excluded: excluded}, dropped
}

// RenderersExcludingNames is DefaultRenderers with the person renderer of
// PersonRendererExcluding(values). It returns the dropped entries as well.
func RenderersExcludingNames(values []string) (map[detect.Kind]Renderer, []string) {
	m := DefaultRenderers()
	r, dropped := PersonRendererExcluding(values)
	m[detect.KindPerson] = r
	return m, dropped
}

// longestName is the byte length of the longest entry of Names.
var longestName = func() int {
	n := 0
	for _, s := range Names {
		if len(s) > n {
			n = len(s)
		}
	}
	return n
}()

// Compile-time checks for the renderers the implementation must provide.
var (
	_ Renderer = SecretRenderer{}
	_ Renderer = ipv4Renderer{}
	_ Renderer = ipv6Renderer{}
	_ Renderer = cidrRenderer{}
	_ Renderer = macRenderer{}
	_ Renderer = emailRenderer{}
	_ Renderer = hostRenderer{}
	_ Renderer = domainRenderer{}
	_ Renderer = pathSegmentRenderer{}
	_ Renderer = fileNameRenderer{}
	_ Renderer = personRenderer{}
	_ Renderer = ibanRenderer{}
)

// Kind implements Renderer.
func (SecretRenderer) Kind() detect.Kind { return detect.KindSecret }

// Render implements Renderer.
func (SecretRenderer) Render(digest []byte, original string) string {
	_ = original
	return PrefixSecret + hex.EncodeToString(digest[:HexSecret/2])
}

// Matches implements Renderer.
func (SecretRenderer) Matches(s string) bool {
	return len(s) == len(PrefixSecret)+HexSecret &&
		strings.HasPrefix(s, PrefixSecret) &&
		isLowerHex(s[len(PrefixSecret):])
}

// MaxLen implements Renderer.
func (SecretRenderer) MaxLen() int { return len(PrefixSecret) + HexSecret }

// --- shared helpers -------------------------------------------------------

// shortHex renders the HexShort lower-case hex digits of a short token from
// the start of the digest, as the shape table says. The bytes of an HMAC are
// independent and uniform, so a window is as good as any fold over the whole
// digest; what decides the collision rate is the width alone. HexShort = 12
// gives 2^48 values, which leaves an expected 7e-5 colliding pairs over
// 200000 distinct originals. This is also why the digest takes attempt as its
// last field: the mapping table raises the counter and asks again when two
// originals do meet on one pseudonym.
func shortHex(d []byte) string {
	return hex.EncodeToString(d[:HexShort/2])
}

// isLowerHex reports whether s is non-empty and consists of lower-case hex
// digits only.
func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isDigits reports whether s is non-empty and consists of decimal digits only.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// cgnatAddr builds the IPv4 pseudonym address inside 100.64.0.0/10.
func cgnatAddr(d []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{100, 64 + d[0]&0x3f, d[1], d[2]})
}

// forceCGNAT puts the ten leading bits of 100.64.0.0/10 back into a, which
// masking to a short prefix would otherwise have cleared.
func forceCGNAT(a netip.Addr) netip.Addr {
	b := a.As4()
	b[0] = 100
	b[1] = b[1]&0x3f | 0x40
	return netip.AddrFrom4(b)
}

// ulaAddr builds the IPv6 pseudonym address inside ulaPseudoPrefix. The five
// groups behind the marker come from the digest and are kept non-zero, so the
// canonical form of a bare pseudonym never compresses.
func ulaAddr(d []byte) netip.Addr {
	var a [16]byte
	for i := 0; i < 16; i++ {
		a[i] = d[i%len(d)]
	}
	copy(a[:6], ulaPseudoHead[:6])
	for i := 6; i < 16; i += 2 {
		if a[i] == 0 && a[i+1] == 0 {
			a[i+1] = 1
		}
	}
	return netip.AddrFrom16(a)
}

// forceULA puts the marker prefix back into a after masking.
func forceULA(a netip.Addr) netip.Addr {
	b := a.As16()
	copy(b[:6], ulaPseudoHead[:6])
	return netip.AddrFrom16(b)
}

// matchesCGNAT reports whether s is the canonical spelling of an IPv4 address
// inside 100.64.0.0/10. Real addresses from that range, Tailscale's among
// them, are covered by it and are never pseudonymized; see the note at the
// shape table.
func matchesCGNAT(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return false
	}
	return cgnatPrefix.Contains(a) && a.String() == s
}

// matchesULA reports whether s is the canonical spelling of an IPv6 address
// inside the marker prefix. The masked address part of a CIDR pseudonym is
// spelled with "::" and a bare pseudonym is not, but both carry the marker,
// so one test serves both.
func matchesULA(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is6() || a.Is4In6() {
		return false
	}
	return ulaPseudoPrefix.Contains(a) && a.String() == s
}

// --- ipv4 -----------------------------------------------------------------

type ipv4Renderer struct{}

func (ipv4Renderer) Kind() detect.Kind { return detect.KindIPv4 }

func (ipv4Renderer) Render(digest []byte, original string) string {
	_ = original
	return cgnatAddr(digest).String()
}

func (ipv4Renderer) Matches(s string) bool { return matchesCGNAT(s) }

func (ipv4Renderer) MaxLen() int { return len("255.255.255.255") }

// --- ipv6 -----------------------------------------------------------------

type ipv6Renderer struct{}

func (ipv6Renderer) Kind() detect.Kind { return detect.KindIPv6 }

func (ipv6Renderer) Render(digest []byte, original string) string {
	_ = original
	return ulaAddr(digest).String()
}

func (ipv6Renderer) Matches(s string) bool { return matchesULA(s) }

func (ipv6Renderer) MaxLen() int { return len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") }

// --- cidr -----------------------------------------------------------------

type cidrRenderer struct{}

func (cidrRenderer) Kind() detect.Kind { return detect.KindCIDR }

// Render builds the CIDR pseudonym from its own digest. Generator.Pseudonym
// uses buildCIDR with the address pseudonym of the address part instead, so
// a network and a host inside it stay related; both spellings satisfy
// Matches.
func (cidrRenderer) Render(digest []byte, original string) string {
	return buildCIDR(original, digest, func(_ detect.Kind, _ string) (netip.Addr, bool) {
		return netip.Addr{}, false
	})
}

func (cidrRenderer) Matches(s string) bool {
	i := strings.LastIndexByte(s, '/')
	if i < 0 {
		return matchesWildcardQuad(s)
	}
	addrPart, suffix := s[:i], s[i+1:]
	if !isDigits(suffix) && !isDottedMask(suffix) {
		return false
	}
	if strings.ContainsRune(addrPart, '*') {
		return matchesWildcardQuad(addrPart)
	}
	return matchesCGNAT(addrPart) || matchesULA(addrPart)
}

func (cidrRenderer) MaxLen() int { return ipv6Renderer{}.MaxLen() + len("/128") }

// matchesWildcardQuad reports whether s has the shape of a wildcard CIDR
// pseudonym: four dot-separated fields, at least one of them "*", the first
// field 100 (or itself a wildcard) and the second inside the CGNAT range.
func matchesWildcardQuad(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 || !strings.ContainsRune(s, '*') {
		return false
	}
	for i, p := range parts {
		if p == "*" {
			continue
		}
		n, ok := octet(p)
		if !ok {
			return false
		}
		switch i {
		case 0:
			if n != 100 {
				return false
			}
		case 1:
			if n < 64 || n > 127 {
				return false
			}
		}
	}
	return true
}

// octet parses a decimal octet without leading zeros.
func octet(s string) (int, bool) {
	if !isDigits(s) || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 255 {
		return 0, false
	}
	return n, true
}

// isDottedMask reports whether s is a contiguous IPv4 net mask such as
// 255.255.0.0.
func isDottedMask(s string) bool {
	_, ok := dottedMaskBits(s)
	return ok
}

// dottedMaskBits converts a contiguous IPv4 net mask into its prefix length.
func dottedMaskBits(s string) (int, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.String() != s {
		return 0, false
	}
	b := a.As4()
	v := binary.BigEndian.Uint32(b[:])
	ones := bits.OnesCount32(v)
	if ones == 0 {
		return 0, v == 0
	}
	if v != ^uint32(0)<<(32-ones) {
		return 0, false
	}
	return ones, true
}

// buildCIDR renders a CIDR pseudonym. addrFor, when it returns ok, supplies
// the pseudonym address of the address part; otherwise the address is derived
// from digest directly.
func buildCIDR(original string, digest []byte, addrFor func(detect.Kind, string) (netip.Addr, bool)) string {
	addrPart, suffix := original, ""
	if i := strings.LastIndexByte(original, '/'); i >= 0 {
		addrPart, suffix = original[:i], original[i+1:]
	}
	if strings.ContainsRune(addrPart, '*') {
		if strings.Count(addrPart, ".") != 3 {
			// A wildcard that is no quad, "*/24" or "10.*/24", has no
			// network shape to keep; the opaque token replaces it whole,
			// suffix included, so the result is a shape IsPseudonym knows.
			return SecretRenderer{}.Render(digest, original)
		}
		return buildWildcardQuad(addrPart, digest) + keptSuffix(suffix, 32)
	}
	src, err := netip.ParseAddr(addrPart)
	if err != nil {
		// Not a network this renderer understands; an opaque token is the
		// safe answer, and IsPseudonym recognizes it through SecretRenderer.
		return SecretRenderer{}.Render(digest, original)
	}
	if src.Is4In6() {
		src = src.Unmap()
	}
	kind := detect.KindIPv4
	if !src.Is4() {
		kind = detect.KindIPv6
	}
	addr, ok := addrFor(kind, addrPart)
	if !ok {
		if kind == detect.KindIPv4 {
			addr = cgnatAddr(digest)
		} else {
			addr = ulaAddr(digest)
		}
	}
	kept := keptSuffix(suffix, addr.BitLen())
	if n, ok := maskLen(suffix, addr); ok {
		if p := netip.PrefixFrom(addr, n); p.IsValid() {
			masked := p.Masked().Addr()
			if addr.Is4() {
				addr = forceCGNAT(masked)
			} else {
				addr = forceULA(masked)
			}
		}
	}
	return addr.String() + kept
}

// keptSuffix returns the "/..." part as it is carried over, or "" when the
// suffix is neither a prefix length valid for a bits-wide address nor a
// dotted mask. bits bounds it because MaxLen must hold for every input, and
// a term from the user's list reaches this function unfiltered: without the
// bound, "10.13.0.0/" followed by fifty digits would be carried over
// verbatim and the pseudonym would outgrow the stream holdback.
func keptSuffix(suffix string, bits int) string {
	if isDigits(suffix) {
		n, err := strconv.Atoi(suffix)
		if err != nil || len(suffix) > 3 || n < 0 || n > bits {
			return ""
		}
		return "/" + suffix
	}
	if bits == 32 && isDottedMask(suffix) {
		return "/" + suffix
	}
	return ""
}

// maskLen turns the carried suffix into a prefix length valid for addr.
func maskLen(suffix string, addr netip.Addr) (int, bool) {
	if isDigits(suffix) {
		n, err := strconv.Atoi(suffix)
		if err != nil || n < 0 || n > addr.BitLen() {
			return 0, false
		}
		return n, true
	}
	if n, ok := dottedMaskBits(suffix); ok && addr.Is4() {
		return n, true
	}
	return 0, false
}

// buildWildcardQuad replaces the numeric octets of a wildcard network and
// leaves the wildcards in place.
func buildWildcardQuad(addrPart string, digest []byte) string {
	parts := strings.Split(addrPart, ".")
	if len(parts) != 4 {
		return SecretRenderer{}.Render(digest, addrPart)
	}
	out := make([]string, 4)
	for i, p := range parts {
		if p == "*" {
			out[i] = "*"
			continue
		}
		switch i {
		case 0:
			out[i] = "100"
		case 1:
			out[i] = strconv.Itoa(64 + int(digest[0]&0x3f))
		case 2:
			out[i] = strconv.Itoa(int(digest[1]))
		default:
			out[i] = strconv.Itoa(int(digest[2]))
		}
	}
	return strings.Join(out, ".")
}

// --- mac ------------------------------------------------------------------

type macRenderer struct{}

func (macRenderer) Kind() detect.Kind { return detect.KindMAC }

func (macRenderer) Render(digest []byte, original string) string {
	_ = original
	var b strings.Builder
	b.WriteString("02")
	for i := 0; i < 5; i++ {
		b.WriteByte(':')
		b.WriteString(hex.EncodeToString(digest[i : i+1]))
	}
	return b.String()
}

func (macRenderer) Matches(s string) bool {
	if len(s) != 17 || !strings.HasPrefix(s, "02:") {
		return false
	}
	for i := 0; i < 6; i++ {
		g := s[i*3 : i*3+2]
		if !isLowerHex(g) {
			return false
		}
		if i < 5 && s[i*3+2] != ':' {
			return false
		}
	}
	return true
}

func (macRenderer) MaxLen() int { return 17 }

// --- host, path segment, domain -------------------------------------------

type hostRenderer struct{}

func (hostRenderer) Kind() detect.Kind { return detect.KindHost }

func (hostRenderer) Render(digest []byte, original string) string {
	_ = original
	return PrefixHost + shortHex(digest)
}

func (hostRenderer) Matches(s string) bool { return matchesToken(s, PrefixHost, "") }

func (hostRenderer) MaxLen() int { return len(PrefixHost) + HexShort }

type pathSegmentRenderer struct{}

func (pathSegmentRenderer) Kind() detect.Kind { return detect.KindPathSegment }

func (pathSegmentRenderer) Render(digest []byte, original string) string {
	_ = original
	return PrefixPathSegment + shortHex(digest)
}

func (pathSegmentRenderer) Matches(s string) bool { return matchesToken(s, PrefixPathSegment, "") }

func (pathSegmentRenderer) MaxLen() int { return len(PrefixPathSegment) + HexShort }

type domainRenderer struct{}

func (domainRenderer) Kind() detect.Kind { return detect.KindDomain }

func (domainRenderer) Render(digest []byte, original string) string {
	_ = original
	return PrefixDomain + shortHex(digest) + SuffixDomain
}

func (domainRenderer) Matches(s string) bool { return matchesToken(s, PrefixDomain, SuffixDomain) }

func (domainRenderer) MaxLen() int { return len(PrefixDomain) + HexShort + len(SuffixDomain) }

// matchesToken reports whether s is prefix, eight lower-case hex digits and
// suffix, and nothing else.
func matchesToken(s, prefix, suffix string) bool {
	if len(s) != len(prefix)+HexShort+len(suffix) {
		return false
	}
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, suffix) {
		return false
	}
	return isLowerHex(s[len(prefix) : len(prefix)+HexShort])
}

// --- file name ------------------------------------------------------------

type fileNameRenderer struct{}

func (fileNameRenderer) Kind() detect.Kind { return detect.KindFileName }

func (fileNameRenderer) Render(digest []byte, original string) string {
	return PrefixFileName + shortHex(digest) + fileExt(original)
}

func (fileNameRenderer) Matches(s string) bool {
	if len(s) < len(PrefixFileName)+HexShort || !strings.HasPrefix(s, PrefixFileName) {
		return false
	}
	if !isLowerHex(s[len(PrefixFileName) : len(PrefixFileName)+HexShort]) {
		return false
	}
	rest := s[len(PrefixFileName)+HexShort:]
	return rest == "" || isFileExt(rest)
}

// isFileExt reports whether rest is an extension as fileExt returns it: a
// dot, at least one character, no second dot, and no more than maxExtLen
// bytes in all.
func isFileExt(rest string) bool {
	if len(rest) < 2 || len(rest) > maxExtLen || rest[0] != '.' {
		return false
	}
	return fileExt("x"+rest) == rest
}

func (fileNameRenderer) MaxLen() int { return len(PrefixFileName) + HexShort + maxExtLen }

// fileExt returns the last extension of name including the dot, or "" when
// there is none, when the name is a dot file, or when the extension is longer
// than maxExtLen or holds characters an extension does not have. Letters and
// digits are all it may hold: an underscore or a dash after the last dot is
// the mark of a name, not of an extension, and keeping it would carry the
// name out of the machine unreplaced.
func fileExt(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 || len(name)-i > maxExtLen {
		return ""
	}
	for j := i + 1; j < len(name); j++ {
		c := name[j]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		default:
			return ""
		}
	}
	return name[i:]
}

// --- email ----------------------------------------------------------------

type emailRenderer struct{}

func (emailRenderer) Kind() detect.Kind { return detect.KindEmail }

// Render builds a self-contained address from one digest. Generator.Pseudonym
// composes the domain part from the domain pseudonym of the real domain
// instead, so two addresses of one domain keep sharing it; both spellings
// satisfy Matches.
func (emailRenderer) Render(digest []byte, original string) string {
	_ = original
	half := len(digest) / 2
	return PrefixUser + shortHex(digest[:half]) + "@" + PrefixDomain + shortHex(digest[half:]) + SuffixDomain
}

// Matches accepts both spellings of Render and, beyond them, every address
// whose domain part is a domain pseudonym, whatever the local part looks like.
// The forward pass composes such an address by itself whenever the term list
// catches the local part and the domain as two separate hits inside one
// address: in "markus@wendler.de" the person term "markus" and the domain term
// "wendler.de" win against the e-mail pattern, because the term layer has
// precedence, and what is left reads "sophie@d-<hex>.invalid". No real address
// carries that domain — .invalid is reserved and the hex token is our own
// shape — so accepting it costs no detection, and without it the next request
// of the conversation would read the composed address as a fresh one and
// replace it a second time. That is the idempotence the forward pass owes the
// thinking-block signatures.
func (emailRenderer) Matches(s string) bool {
	i := strings.IndexByte(s, '@')
	if i <= 0 || strings.IndexByte(s[i+1:], '@') >= 0 {
		return false
	}
	return domainRenderer{}.Matches(s[i+1:])
}

func (emailRenderer) MaxLen() int {
	return len(PrefixUser) + HexShort + 1 + domainRenderer{}.MaxLen()
}

// --- person ---------------------------------------------------------------

type personRenderer struct {
	// excluded holds, in lower case, the full names and the given names of
	// the entries of Names that PersonRendererExcluding dropped. Nil means
	// the full list.
	excluded map[string]bool
}

func (personRenderer) Kind() detect.Kind { return detect.KindPerson }

func (r personRenderer) Render(digest []byte, original string) string {
	i := int(binary.BigEndian.Uint32(digest[:4]) % uint32(len(Names)))
	entry := Names[i]
	for n := 0; r.excluded[strings.ToLower(entry)] && n < len(Names); n++ {
		i = (i + 1) % len(Names)
		entry = Names[i]
	}
	if !strings.ContainsRune(strings.TrimSpace(original), ' ') {
		if i := strings.IndexByte(entry, ' '); i > 0 {
			entry = entry[:i]
		}
	}
	return carryCase(entry, original)
}

func (r personRenderer) Matches(s string) bool {
	lower := strings.ToLower(s)
	written, ok := nameForms[lower]
	if !ok || r.excluded[lower] {
		return false
	}
	return s == written || s == strings.ToUpper(written) || s == strings.ToLower(written)
}

func (personRenderer) MaxLen() int { return longestName }

// carryCase applies the letter case of original to out: all upper case and
// all lower case are carried over, every mixed spelling keeps the entry as
// Names writes it.
func carryCase(out, original string) string {
	upper, lower := false, false
	for _, r := range original {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		}
	}
	switch {
	case upper && !lower:
		return strings.ToUpper(out)
	case lower && !upper:
		return strings.ToLower(out)
	}
	return out
}

// --- iban -----------------------------------------------------------------

type ibanRenderer struct{}

func (ibanRenderer) Kind() detect.Kind { return detect.KindIBAN }

func (ibanRenderer) Render(digest []byte, original string) string {
	country := "XX"
	if len(original) >= 2 && isUpperAlpha(original[:2]) {
		country = original[:2]
	}
	length := len(original)
	if length < minIBANLen || length > maxIBANLen {
		length = 22
	}
	body := make([]byte, 0, length-4)
	body = append(body, ibanMarker...)
	for i := len(ibanMarker); i < length-4; i++ {
		body = append(body, '0'+digest[i%len(digest)]%10)
	}
	check := 98 - mod97(string(body)+country+"00")
	out := make([]byte, 0, length)
	out = append(out, country...)
	out = append(out, '0'+byte(check/10), '0'+byte(check%10))
	out = append(out, body...)
	return string(out)
}

func (ibanRenderer) Matches(s string) bool {
	if len(s) < minIBANLen || len(s) > maxIBANLen {
		return false
	}
	if !isUpperAlpha(s[:2]) || !isDigits(s[2:4]) || !isDigits(s[4:]) {
		return false
	}
	if !strings.HasPrefix(s[4:], ibanMarker) {
		return false
	}
	return mod97(s[4:]+s[:4]) == 1
}

func (ibanRenderer) MaxLen() int { return maxIBANLen }

// --- machine identifiers --------------------------------------------------
//
// The four shapes below keep the form a tool expects and carry a marker a
// real value does not have, in the manner of ibanMarker:
//
//   - uuid: 8-4-4-4-12 lower-case hex with the version nibble set to "f",
//     a version RFC 9562 does not define.
//   - hexid: the digits begin with hexIDMarker, "5046" ("PF" in ASCII). A
//     real machine-id or WWN begins with these four digits with probability
//     1/65536; such a value is taken for a pseudonym and leaves unchanged.
//   - fingerprint: "SHA256:" and 43 characters, the first two "PF", the
//     rest letters and digits. A real fingerprint starts with "PF" with
//     probability 1/4096.
//   - serial: "PF-" and twelve upper-case letters or digits. The hyphen
//     after "PF" keeps the shape apart from vendor serials that begin with
//     the letters PF.

const (
	hexIDMarker       = "5046"
	PrefixFingerprint = "SHA256:PF"
	PrefixSerial      = "PF-"
	fingerprintLen    = 43
	serialLen         = 12
	uuidLen           = 36
)

// expand derives n pseudo-random bytes from digest, for renderers that
// need more than the 32 bytes of the HMAC. Deterministic: the same digest
// always expands to the same bytes.
func expand(digest []byte, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for counter := byte(0); len(out) < n; counter++ {
		h := sha256.New()
		h.Write(digest)
		h.Write([]byte{counter})
		out = h.Sum(out)
	}
	return out[:n]
}

type uuidRenderer struct{}

func (uuidRenderer) Kind() detect.Kind { return detect.KindUUID }

func (uuidRenderer) Render(digest []byte, original string) string {
	_ = original
	h := hex.EncodeToString(digest[:16])
	return h[0:8] + "-" + h[8:12] + "-f" + h[13:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (uuidRenderer) Matches(s string) bool {
	if len(s) != uuidLen || s[14] != 'f' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

func (uuidRenderer) MaxLen() int { return uuidLen }

type hexIDRenderer struct{}

func (hexIDRenderer) Kind() detect.Kind { return detect.KindHexID }

// Render keeps the form of the original: "0x" and 16 digits stays that,
// everything else becomes 32 digits.
func (hexIDRenderer) Render(digest []byte, original string) string {
	h := hex.EncodeToString(digest)
	if len(original) == 18 && strings.HasPrefix(original, "0x") {
		return "0x" + hexIDMarker + h[:12]
	}
	return hexIDMarker + h[:28]
}

func (hexIDRenderer) Matches(s string) bool {
	switch len(s) {
	case 32:
		return strings.HasPrefix(s, hexIDMarker) && isLowerHex(s)
	case 18:
		return strings.HasPrefix(s, "0x"+hexIDMarker) && isLowerHex(s[2:])
	}
	return false
}

func (hexIDRenderer) MaxLen() int { return 32 }

// alnum are the characters the fingerprint pseudonym is drawn from; every
// one of them is a base64 character, so the pseudonym is still a fingerprint
// to anything that parses one. upperAlnum is the serial alphabet.
const (
	alnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func alnumString(digest []byte, n int, alphabet string) string {
	src := expand(digest, n)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[int(src[i])%len(alphabet)]
	}
	return string(b)
}

func isAlnum(s string, alphabet string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

type fingerprintRenderer struct{}

func (fingerprintRenderer) Kind() detect.Kind { return detect.KindFingerprint }

func (fingerprintRenderer) Render(digest []byte, original string) string {
	_ = original
	return PrefixFingerprint + alnumString(digest, fingerprintLen-2, alnum)
}

func (fingerprintRenderer) Matches(s string) bool {
	return len(s) == len("SHA256:")+fingerprintLen &&
		strings.HasPrefix(s, PrefixFingerprint) &&
		isAlnum(s[len(PrefixFingerprint):], alnum)
}

func (fingerprintRenderer) MaxLen() int { return len("SHA256:") + fingerprintLen }

type serialRenderer struct{}

func (serialRenderer) Kind() detect.Kind { return detect.KindSerial }

func (serialRenderer) Render(digest []byte, original string) string {
	_ = original
	return PrefixSerial + alnumString(digest, serialLen, upperAlnum)
}

func (serialRenderer) Matches(s string) bool {
	return len(s) == len(PrefixSerial)+serialLen &&
		strings.HasPrefix(s, PrefixSerial) &&
		isAlnum(s[len(PrefixSerial):], upperAlnum)
}

func (serialRenderer) MaxLen() int { return len(PrefixSerial) + serialLen }

// isUpperAlpha reports whether s is non-empty and holds capital letters only.
func isUpperAlpha(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// mod97 computes the IBAN check remainder over a string of digits and capital
// letters, letters counting as their position value plus nine.
func mod97(s string) int {
	rem := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A') + 10) % 97
		default:
			return -1
		}
	}
	return rem
}
