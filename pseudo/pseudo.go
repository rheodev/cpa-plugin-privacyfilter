// Package pseudo turns confidential values into stable, format-preserving
// pseudonyms. A pseudonym is
//
//	render(kind, HMAC-SHA256(secret || salt, kind || "\x00" || value || "\x00" || attempt))
//
// where secret comes from the file pseudonym.secret next to the shared
// object, salt is derived once per conversation (see salt.go), and attempt
// is a decimal counter that the mapping table raises when two different
// values would otherwise collide. Rendering is per kind: an IPv4 address
// becomes another IPv4 address, a hostname a short token, and so on, so a
// coding model can still compute with what it reads (see render.go).
//
// Nothing in this package keeps state between calls, and nothing here
// depends on time or randomness. The same secret, salt, kind, value and
// attempt always give the same pseudonym.
package pseudo

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// ErrNotImplemented marks a contract stub that has no implementation yet.
var ErrNotImplemented = errors.New("pseudo: not implemented")

// DigestLen is the number of bytes every Renderer receives. It equals the
// output size of HMAC-SHA256.
const DigestLen = 32

// separator ends every field of the HMAC input, so no two different field
// splits produce the same message.
var separator = []byte{0}

// Generator produces pseudonyms for one conversation. It is safe for
// concurrent use once built.
type Generator struct {
	key       []byte
	renderers map[detect.Kind]Renderer
	maxLen    int
	// networks are the configured networks, longest prefix first; see
	// WithNetworks.
	networks []netip.Prefix
}

// WithNetworks makes the generator keep the structure of the given
// networks: the pseudonym of a network is a network of the same prefix
// length inside the marker range, and every address inside a configured
// network is rendered into the pseudonym of that network, with only the
// host bits taken from its own digest. A network inside another configured
// network lies inside that one's pseudonym as well. So "host X is in net
// Y", "the gateway is in the same /24" and "X and Z are neighbours" stay
// true for the model, and the model's own arithmetic inside a network
// comes back through the table when it lands on a value the table holds.
//
// Addresses outside every configured network render as before, spread
// over the whole marker range. Wildcard networks are ignored. The list is
// part of what the pseudonyms depend on, like the term list.
func (g *Generator) WithNetworks(nets []netip.Prefix) *Generator {
	g.networks = g.networks[:0]
	for _, n := range nets {
		if n.IsValid() {
			g.networks = append(g.networks, n.Masked())
		}
	}
	sort.SliceStable(g.networks, func(i, j int) bool { return g.networks[i].Bits() > g.networks[j].Bits() })
	return g
}

// containing returns the longest configured network that contains addr
// with fewer bits than limit. limit is the bit length of the address for a
// host lookup, and the prefix length of a network for its parent lookup.
func (g *Generator) containing(addr netip.Addr, limit int) (netip.Prefix, bool) {
	for _, n := range g.networks {
		if n.Bits() < limit && n.Addr().Is4() == addr.Is4() && n.Contains(addr) {
			return n, true
		}
	}
	return netip.Prefix{}, false
}

// netAddr returns the pseudonym address of a configured network: the
// address of its pseudonym network, masked. The prefix bits come from the
// parent network's pseudonym when there is one, the rest from the digest
// of the network itself.
func (g *Generator) netAddr(net netip.Prefix, attempt int) netip.Addr {
	d := g.Digest(detect.KindCIDR, net.String(), attempt)
	var base netip.Addr
	if net.Addr().Is4() {
		base = cgnatAddr(d)
	} else {
		base = ulaAddr(d)
	}
	if parent, ok := g.containing(net.Addr(), net.Bits()); ok {
		base = combineBits(g.netAddr(parent, 0), base, parent.Bits())
	}
	masked := netip.PrefixFrom(base, net.Bits()).Masked().Addr()
	if masked.Is4() {
		return forceCGNAT(masked)
	}
	return forceULA(masked)
}

// hostAddr renders an address that lies inside a configured network: the
// network's pseudonym prefix, then the host bits of base.
func (g *Generator) hostAddr(addr, base netip.Addr) (netip.Addr, bool) {
	net, ok := g.containing(addr, addr.BitLen())
	if !ok {
		return netip.Addr{}, false
	}
	out := combineBits(g.netAddr(net, 0), base, net.Bits())
	if out.Is4() {
		return forceCGNAT(out), true
	}
	return forceULA(out), true
}

// combineBits takes the first bits of prefix and the rest from host.
func combineBits(prefix, host netip.Addr, bits int) netip.Addr {
	if prefix.Is4() {
		p, h := prefix.As4(), host.As4()
		for i := 0; i < 4; i++ {
			p[i] = mixByte(p[i], h[i], bits-8*i)
		}
		return netip.AddrFrom4(p)
	}
	p, h := prefix.As16(), host.As16()
	for i := 0; i < 16; i++ {
		p[i] = mixByte(p[i], h[i], bits-8*i)
	}
	return netip.AddrFrom16(p)
}

// mixByte keeps the first n bits of p and takes the rest from h; n may be
// outside 0..8.
func mixByte(p, h byte, n int) byte {
	switch {
	case n >= 8:
		return p
	case n <= 0:
		return h
	}
	mask := byte(0xff) << (8 - n)
	return p&mask | h&^mask
}

// NewGenerator binds a secret and a salt. The HMAC key is the concatenation
// secret || salt. renderers may be nil, in which case DefaultRenderers is
// used; a kind without a renderer falls back to the secret renderer.
//
// The constructor does not judge the secret: a short one renders like any
// other, and tests build generators over fixed strings. The rule of
// MinSecretLen is applied where a secret enters service, in LoadSecret, and
// a caller that takes a secret from elsewhere checks it with CheckSecret.
func NewGenerator(secret, salt []byte, renderers map[detect.Kind]Renderer) *Generator {
	if renderers == nil {
		renderers = DefaultRenderers()
	}
	key := make([]byte, 0, len(secret)+len(salt))
	key = append(key, secret...)
	key = append(key, salt...)
	g := &Generator{key: key, renderers: renderers, maxLen: SecretRenderer{}.MaxLen()}
	for _, r := range renderers {
		if n := r.MaxLen(); n > g.maxLen {
			g.maxLen = n
		}
	}
	return g
}

// renderer returns the renderer for kind, or the secret renderer when the
// kind has none.
func (g *Generator) renderer(kind detect.Kind) Renderer {
	if r, ok := g.renderers[kind]; ok {
		return r
	}
	return SecretRenderer{}
}

// Pseudonym renders the pseudonym for value under kind. attempt is 0 for the
// first try; the mapping table passes 1, 2, ... when the result collides
// with the pseudonym of a different value.
//
// Two kinds are composed rather than rendered directly, so related values
// stay related in the output:
//
//   - KindEmail: the part after the last "@" is pseudonymized as KindDomain
//     with attempt 0, the local part becomes "u-" plus eight hex digits from
//     the digest of the whole address. An address and its domain therefore
//     share the domain pseudonym.
//   - KindCIDR: the address part is pseudonymized as KindIPv4 or KindIPv6,
//     the prefix length or mask is kept as written, and wildcard octets
//     ("10.13.*.*") stay wildcards.
//   - KindPerson: the value is lower-cased before hashing, so the case
//     variants of one name select the same entry of Names; the renderer then
//     applies the original's case (see render.go). The mapping table still
//     keys entries by the value as written, so each variant restores to
//     exactly what it replaced.
func (g *Generator) Pseudonym(kind detect.Kind, value string, attempt int) string {
	switch kind {
	case detect.KindEmail:
		domain := value
		if i := strings.LastIndexByte(value, '@'); i >= 0 {
			domain = value[i+1:]
		}
		d := g.Digest(kind, value, attempt)
		return PrefixUser + shortHex(d) + "@" + g.Pseudonym(detect.KindDomain, domain, 0)
	case detect.KindCIDR:
		d := g.Digest(kind, value, attempt)
		if len(g.networks) > 0 {
			if net, err := netip.ParsePrefix(value); err == nil {
				for _, known := range g.networks {
					if known == net.Masked() {
						return g.netAddr(known, attempt).String() + keptSuffix(value[strings.LastIndexByte(value, '/')+1:], known.Addr().BitLen())
					}
				}
			}
		}
		return buildCIDR(value, d, func(k detect.Kind, addr string) (netip.Addr, bool) {
			a, err := netip.ParseAddr(g.Pseudonym(k, addr, 0))
			return a, err == nil
		})
	case detect.KindIPv4, detect.KindIPv6:
		if len(g.networks) > 0 {
			if addr, err := netip.ParseAddr(value); err == nil && !addr.Is4In6() && addr.Is4() == (kind == detect.KindIPv4) {
				d := g.Digest(kind, value, attempt)
				base := cgnatAddr(d)
				if addr.Is6() {
					base = ulaAddr(d)
				}
				if out, ok := g.hostAddr(addr, base); ok {
					return out.String()
				}
			}
		}
	case detect.KindPerson:
		d := g.Digest(kind, strings.ToLower(value), attempt)
		return g.renderer(kind).Render(d, value)
	}
	return g.renderer(kind).Render(g.Digest(kind, value, attempt), value)
}

// Digest returns the raw HMAC for kind, value and attempt without rendering.
// It exists for tests and for renderers that need a second digest.
func (g *Generator) Digest(kind detect.Kind, value string, attempt int) []byte {
	m := hmac.New(sha256.New, g.key)
	m.Write([]byte(kind))
	m.Write(separator)
	m.Write([]byte(value))
	m.Write(separator)
	m.Write([]byte(strconv.Itoa(attempt)))
	return m.Sum(nil)
}

// MaxLen returns the longest pseudonym any registered renderer can produce.
// The stream holdback keeps at most MaxLen-1 bytes.
func (g *Generator) MaxLen() int {
	return g.maxLen
}

// CheckSecret applies the rule of LoadSecret to a secret that came from
// elsewhere: ErrSecretTooShort when fewer than MinSecretLen bytes remain
// after trimming, nil otherwise.
func CheckSecret(secret []byte) error {
	if len(bytes.TrimSpace(secret)) < MinSecretLen {
		return ErrSecretTooShort
	}
	return nil
}

// IsPseudonym reports whether s, taken as a whole, has the shape of a
// pseudonym produced by any registered renderer. The detect layer uses it to
// exclude pseudonyms from re-detection, which is what makes the forward pass
// idempotent. It does not consult a mapping table: a string of the right
// shape counts even if it was never generated.
func (g *Generator) IsPseudonym(s string) bool {
	if s == "" {
		return false
	}
	if (SecretRenderer{}).Matches(s) {
		return true
	}
	for _, r := range g.renderers {
		if r.Matches(s) {
			return true
		}
	}
	return false
}
