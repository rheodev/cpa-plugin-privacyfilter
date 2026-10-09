package detect

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// PatternsConfig switches the structural detectors on and off, one category
// at a time. Every category is off unless enabled here; the plugin's config
// layer maps the YAML section patterns to this struct and applies its own
// defaults.
type PatternsConfig struct {
	// IPv4 finds dotted-quad addresses. Addresses inside a CIDR notation are
	// reported once, as KindCIDR, not additionally as KindIPv4.
	IPv4 bool
	// IPv6 finds addresses in the notations of RFC 4291 section 2.2,
	// including the compressed form and IPv4-embedded addresses, and
	// bracketed addresses in URLs without the brackets.
	IPv6 bool
	// CIDR finds address/prefix notations for both families, including the
	// wildcard forms 10.13.*.* and 10.13.0.0/255.255.0.0.
	CIDR bool
	// MAC finds 48-bit hardware addresses with colon or hyphen separators.
	MAC bool
	// Email finds addresses of the form local@domain with at least one dot in
	// the domain part.
	Email bool
	// IBAN finds account numbers of ISO 13616 with a valid mod-97 checksum;
	// candidates with an invalid checksum are not reported.
	IBAN bool
	// URL finds absolute URLs with a scheme. Off by default until path
	// pseudonyms exist; see the plan, milestone 3.
	URL bool
	// UUID finds identifiers in the 8-4-4-4-12 hex form, either case: disk
	// and partition UUIDs, product UUIDs, GUIDs.
	UUID bool
	// HexID finds bare hex identifiers of exactly 32 digits (machine-id) and
	// of "0x" followed by exactly 16 digits (a disk's WWN). Longer runs such
	// as a commit hash are not cut into pieces; they are not reported.
	HexID bool
	// Fingerprint finds SSH key fingerprints as OpenSSH prints them:
	// "SHA256:" and 43 base64 characters.
	Fingerprint bool
	// Serial finds serial numbers by their label: "Serial Number:",
	// "serial:", "S/N:", "Seriennummer:", "ID_SERIAL=", "ID_SERIAL_SHORT=",
	// a JSON key "serial", and the "iSerial <n>" line of lsusb. The value
	// must be six to 64 characters of letters, digits, underscore, dot,
	// slash and hyphen, must end in a letter or digit and must contain a
	// letter and a digit; a bare number after "serial" is a zone serial or
	// a counter, not a device. A serial number without a label is not
	// found; the term list is the place for it.
	Serial bool
}

// NewPatterns builds the structural detector. It reports each hit with the
// kind of its category and Source "patterns". A candidate whose kind is
// disabled is not reported at all, so a disabled category never shadows a
// hit of another layer. Loopback, unspecified and multicast addresses are
// reported like any other address; excluding them is the caller's business
// via Composite.Exclude.
func NewPatterns(cfg PatternsConfig) (Detector, error) {
	return &patternsDetector{cfg: cfg}, nil
}

// The building blocks of the structural expressions. RE2 has no look-around,
// so every candidate is checked afterwards against hasTokenBoundaries, which
// keeps a dotted quad from being cut out of a longer run of digits. The
// expressions of the address and account categories carry no \b of their own:
// RE2 counts the underscore as a word character, so a \b would lose
// "scan_10.13.7.42.log" entirely, and no other position inside the quad offers
// a boundary to fall back to. Mail addresses and URLs keep theirs, because
// their own character classes contain the underscore already.
const (
	reOctet     = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])`
	reOctetWild = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]|\*)`
	reQuad      = reOctet + `(?:\.` + reOctet + `){3}`
	reQuadWild  = reOctetWild + `(?:\.` + reOctetWild + `){3}`
)

var (
	rxIPv4      = regexp.MustCompile(reQuad)
	rxCIDR4     = regexp.MustCompile(reQuad + `/(?:3[0-2]|[12][0-9]|[0-9])`)
	rxCIDR4Mask = regexp.MustCompile(reQuad + `/` + reQuad)
	rxCIDR4Wild = regexp.MustCompile(reQuadWild)
	rxMAC       = regexp.MustCompile(`[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}`)
	rxEmail     = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b`)
	rxIBAN      = regexp.MustCompile(`[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}`)
	rxURL       = regexp.MustCompile(`\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s<>"']+`)
	rxUUID      = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)
	rxHex32     = regexp.MustCompile(`[0-9A-Fa-f]{32}`)
	rxHex0x16   = regexp.MustCompile(`0x[0-9A-Fa-f]{16}`)
	rxFingerpr  = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`)
	// rxSerial finds a serial number by its label. Group 1 is the value. The
	// label forms are the ones smartctl, dmidecode, udevadm, lsblk -J, lsusb
	// -v and hand-written notes use; the separator is ":" or "=", with
	// optional quotes around key and value for the JSON form, and the lsusb
	// form "iSerial <index> <value>" has none.
	rxSerial = regexp.MustCompile(`(?i)(?:"?(?:serial(?:[ _-]?(?:number|no|nr))?|s/n|serialnumber|seriennummer|serien-?nr|id_serial(?:_short)?)"?\s*[:=]\s*"?|iserial\s+[0-9]+\s+)([A-Za-z0-9][A-Za-z0-9_./-]{4,62}[A-Za-z0-9])`)

	// rxV6Run collects maximal runs of the characters an IPv6 address can be
	// written with. The run is then narrowed down and handed to netip, which
	// is the only arbiter of what a valid address is.
	rxV6Run = regexp.MustCompile(`[0-9A-Fa-f:.]+`)
	// rxV6Len matches the prefix length that turns an address into a network.
	rxV6Len = regexp.MustCompile(`^/(?:12[0-8]|1[01][0-9]|[0-9]{1,2})`)
)

// maxV6Text is the length of the longest textual IPv6 address, the
// IPv4-embedded full form; it bounds the search inside one run.
const maxV6Text = 45

// Precedence inside the structural layer. It only decides between candidates
// that cover exactly the same span; a longer candidate always wins first, so
// a network beats the address it starts with without any help from here.
const (
	prioCIDR = iota
	prioMAC
	prioIPv6
	prioEmail
	prioIBAN
	prioUUID
	prioFingerprint
	prioHexID
	prioIPv4
	prioSerial
	prioURL
)

type patCand struct {
	m    Match
	prio int
}

// patternsDetector is the compiled structural layer.
type patternsDetector struct {
	cfg PatternsConfig
}

var _ Detector = (*patternsDetector)(nil)

// Name implements Detector.
func (p *patternsDetector) Name() string { return "patterns" }

// Scan implements Detector.
func (p *patternsDetector) Scan(text string) []Match {
	if text == "" {
		return nil
	}
	var cands []patCand
	add := func(start, end int, kind Kind, prio int) {
		if !spanAligned(text, start, end) {
			return
		}
		cands = append(cands, patCand{
			m:    Match{Start: start, End: end, Value: text[start:end], Kind: kind, Source: "patterns"},
			prio: prio,
		})
	}
	// The boundary rule of this layer. It is the accept callback of collect
	// rather than a filter inside add, so a candidate that only fails on its
	// neighbours does not swallow the ones that start inside it: collect
	// resumes one rune after a rejected start.
	bounded := func(start, end int) bool { return hasTokenBoundaries(text, start, end) }
	// An address is one run of groups, and a run with more groups than an
	// address has is no address: a dotted quad inside "17.18.19.20.21" or
	// eight hex groups inside twelve are windows of something else, a
	// version, a fingerprint, an identifier. The group separator next to a
	// digit of the same run on either side rejects the window; the
	// separator alone, as in "reach 10.0.0.7." or "]:8080", does not.
	dottedRun := func(start, end int) bool {
		return bounded(start, end) && !insideRun(text, start, end, '.', isDigitByte)
	}
	colonRun := func(start, end int) bool { return bounded(start, end) && !insideRun(text, start, end, ':', isHexByte) }

	// An address that identifies nothing is left alone, so the model keeps
	// seeing loopback, the unspecified address, broadcast, multicast,
	// link-local and the documentation ranges for what they are; see
	// specialAddr. A term of the maintained list still wins over this rule.
	ordinary := func(s, e int) bool { return dottedRun(s, e) && !specialAddr(text[s:e]) }
	if p.cfg.CIDR {
		collect(text, rxCIDR4, ordinary, func(s, e int) { add(s, e, KindCIDR, prioCIDR) })
		collect(text, rxCIDR4Mask, ordinary, func(s, e int) { add(s, e, KindCIDR, prioCIDR) })
		collect(text, rxCIDR4Wild,
			func(s, e int) bool { return dottedRun(s, e) && strings.Contains(text[s:e], "*") },
			func(s, e int) { add(s, e, KindCIDR, prioCIDR) })
	}
	if p.cfg.IPv4 {
		collect(text, rxIPv4, ordinary, func(s, e int) { add(s, e, KindIPv4, prioIPv4) })
	}
	if p.cfg.IPv6 || p.cfg.CIDR {
		scanIPv6(text, colonRun, func(s, e int) {
			if specialAddr(text[s:e]) {
				return
			}
			if p.cfg.IPv6 {
				add(s, e, KindIPv6, prioIPv6)
			}
			if p.cfg.CIDR {
				// scanIPv6 already guarantees the boundaries of the address
				// itself; the prefix length moves the end, so that one is
				// checked here.
				if loc := rxV6Len.FindStringIndex(text[e:]); loc != nil && bounded(s, e+loc[1]) {
					add(s, e+loc[1], KindCIDR, prioCIDR)
				}
			}
		})
	}
	if p.cfg.MAC {
		collect(text, rxMAC,
			func(s, e int) bool {
				sep := byte(':')
				if strings.IndexByte(text[s:e], '-') >= 0 {
					sep = '-'
				}
				return bounded(s, e) && !insideRun(text, s, e, sep, isHexByte)
			},
			func(s, e int) { add(s, e, KindMAC, prioMAC) })
	}
	if p.cfg.Email {
		collect(text, rxEmail, bounded, func(s, e int) { add(s, e, KindEmail, prioEmail) })
	}
	if p.cfg.IBAN {
		collect(text, rxIBAN,
			func(s, e int) bool { return bounded(s, e) && ibanValid(text[s:e]) },
			func(s, e int) { add(s, e, KindIBAN, prioIBAN) })
	}
	if p.cfg.URL {
		collect(text, rxURL, bounded, func(s, e int) { add(s, e, KindURL, prioURL) })
	}
	if p.cfg.UUID {
		collect(text, rxUUID, bounded, func(s, e int) { add(s, e, KindUUID, prioUUID) })
	}
	if p.cfg.HexID {
		// The boundary rule keeps both shapes exact: a 40-digit commit hash
		// offers no 32-digit window with a non-hex neighbour on both sides.
		collect(text, rxHex32, bounded, func(s, e int) { add(s, e, KindHexID, prioHexID) })
		collect(text, rxHex0x16, bounded, func(s, e int) { add(s, e, KindHexID, prioHexID) })
	}
	if p.cfg.Fingerprint {
		collect(text, rxFingerpr, bounded, func(s, e int) { add(s, e, KindFingerprint, prioFingerprint) })
	}
	if p.cfg.Serial {
		collectGroup(text, rxSerial, 1,
			func(s, e int) bool { return bounded(s, e) && serialPlausible(text[s:e]) },
			func(s, e int) { add(s, e, KindSerial, prioSerial) })
	}
	return mergeCandidates(cands)
}

// serialPlausible reports whether v reads as a device serial: at least one
// letter and one digit. A bare number after a serial label is a DNS zone
// serial or a counter, a bare word is prose ("serial: console").
// specialAddr reports whether s, an address or a network in CIDR form,
// lies in a range that identifies no machine: loopback, unspecified,
// broadcast, multicast, link-local and the documentation prefixes of RFC
// 5737 and RFC 3849. Replacing those would only mislead the model, which
// would take the loopback address for a carrier-grade NAT address. A zone suffix
// ("%eth0") is ignored for the decision.
func specialAddr(s string) bool {
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// specialPrefixes are built from octets so the source holds no dotted
// quad. In order: limited broadcast, "this" network, TEST-NET-1, -2, -3
// (RFC 5737) and the IPv6 documentation prefix (RFC 3849).
var specialPrefixes = []netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), 32),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 8),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, 0}), 24),
	netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8}), 32),
}

func serialPlausible(v string) bool {
	letter, digit := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letter = true
		}
	}
	return letter && digit
}

// collectGroup is collect for a capture group: re is matched over text, and
// the offsets of group are what accept sees and emit receives. The search
// resumes behind the whole match when the group is accepted, and one rune
// behind the match start when it is not.
func collectGroup(text string, re *regexp.Regexp, group int, accept func(start, end int) bool, emit func(start, end int)) {
	for off := 0; off < len(text); {
		loc := re.FindStringSubmatchIndex(text[off:])
		if loc == nil {
			return
		}
		ms, me := off+loc[0], off+loc[1]
		gs, ge := loc[2*group], loc[2*group+1]
		if ms >= me {
			return
		}
		if gs >= 0 && ge > gs {
			gs, ge = off+gs, off+ge
			if accept == nil || accept(gs, ge) {
				emit(gs, ge)
				off = me
				continue
			}
		}
		_, size := utf8.DecodeRuneInString(text[ms:])
		if size < 1 {
			size = 1
		}
		off = ms + size
	}
}

// mergeCandidates collapses the structural candidates into a disjoint list:
// the longer span wins, among equal spans the category with the higher
// precedence, and the rest is decided by the start offset. That is where the
// promise "a CIDR hit is never additionally reported as IPv4" is kept.
func mergeCandidates(cands []patCand) []Match {
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if a, b := cands[i].m.Len(), cands[j].m.Len(); a != b {
			return a > b
		}
		if cands[i].prio != cands[j].prio {
			return cands[i].prio < cands[j].prio
		}
		return cands[i].m.Start < cands[j].m.Start
	})
	maxEnd := 0
	for _, c := range cands {
		if c.m.End > maxEnd {
			maxEnd = c.m.End
		}
	}
	f := newSpanFilter(len(cands), maxEnd)
	for _, c := range cands {
		f.offer(c.m)
	}
	return f.result()
}

// collect runs re over text and reports every match that accept admits, by
// its offsets. A rejected match does not hide the ones inside it: the search
// continues one rune after the rejected start, not after its end.
func collect(text string, re *regexp.Regexp, accept func(start, end int) bool, emit func(start, end int)) {
	for off := 0; off < len(text); {
		loc := re.FindStringIndex(text[off:])
		if loc == nil {
			return
		}
		s, e := off+loc[0], off+loc[1]
		if s >= e {
			return
		}
		if accept == nil || accept(s, e) {
			emit(s, e)
			off = e
			continue
		}
		_, size := utf8.DecodeRuneInString(text[s:])
		if size < 1 {
			size = 1
		}
		off = s + size
	}
}

// insideRun reports whether the window [start, end) continues a run of
// groups on either side: the separator sep directly outside the window with
// a byte of the group class directly beyond it.
func insideRun(text string, start, end int, sep byte, group func(byte) bool) bool {
	if start >= 2 && text[start-1] == sep && group(text[start-2]) {
		return true
	}
	if end+1 < len(text) && text[end] == sep && group(text[end+1]) {
		return true
	}
	return false
}

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

func isHexByte(b byte) bool {
	return isDigitByte(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// scanIPv6 reports every IPv6 address in text. Candidates come from runs of
// address characters; netip decides what parses. Only runs that carry the
// compressed "::" or the seven colons of the full form are considered, which
// keeps hardware addresses and clock times out of the search entirely. accept
// judges a candidate by its neighbours before it is emitted.
func scanIPv6(text string, accept func(start, end int) bool, emit func(start, end int)) {
	for _, loc := range rxV6Run.FindAllStringIndex(text, -1) {
		run := text[loc[0]:loc[1]]
		if !strings.Contains(run, "::") && strings.Count(run, ":") < 7 {
			continue
		}
		for s := loc[0]; s < loc[1]; {
			if s > 0 {
				if r, _ := utf8.DecodeLastRuneInString(text[:s]); isTokenRune(r) {
					s++
					continue
				}
			}
			hi := loc[1]
			if hi > s+maxV6Text {
				hi = s + maxV6Text
			}
			end := -1
			for e := hi; e > s+1; e-- {
				cand := text[s:e]
				if !strings.Contains(cand, ":") {
					break
				}
				if e < len(text) {
					if r, _ := utf8.DecodeRuneInString(text[e:]); isTokenRune(r) {
						continue
					}
				}
				if addr, err := netip.ParseAddr(cand); err == nil && addr.Is6() && (accept == nil || accept(s, e)) {
					end = e
					break
				}
			}
			if end > 0 {
				emit(s, end)
				s = end
				continue
			}
			s++
		}
	}
}

// ibanValid runs the mod-97 check of ISO 13616 over a candidate that already
// has the right shape: the first four characters move to the end, letters
// become their position in the alphabet plus nine, and the resulting number
// must leave the remainder one.
func ibanValid(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rem := 0
	for i := 0; i < len(s); i++ {
		c := s[(i+4)%len(s)]
		switch {
		case c >= '0' && c <= '9':
			rem = rem*10 + int(c-'0')
		case c >= 'A' && c <= 'Z':
			rem = rem*100 + int(c-'A') + 10
		default:
			return false
		}
		rem %= 97
	}
	return rem == 1
}
