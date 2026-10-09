package pseudo_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

func q(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }

func q6(groups ...uint16) string {
	var b [16]byte
	for i, g := range groups {
		b[2*i], b[2*i+1] = byte(g>>8), byte(g)
	}
	return netip.AddrFrom16(b).String()
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// With configured networks, a network keeps its prefix length, every
// address inside it lands inside its pseudonym, a nested network lands
// inside its parent's pseudonym, and addresses outside every network are
// unaffected. Host bits still come from the address's own digest.
func TestPseudonym_NetworksKeepStructure(t *testing.T) {
	site := q(10, 13, 0, 0) + "/16"
	lan := q(10, 13, 7, 0) + "/24"
	other := q(192, 168, 2, 0) + "/24"
	v6net := q6(0xfd12, 0x3456, 0x789a, 1) + "/64"
	nets := []netip.Prefix{mustPrefix(t, site), mustPrefix(t, lan), mustPrefix(t, other), mustPrefix(t, v6net)}

	salt := pseudo.DeriveSalt(fixtures.Secret, fixtures.SessionA)
	g := pseudo.NewGenerator(fixtures.Secret, salt, nil).WithNetworks(nets)
	plain := pseudo.NewGenerator(fixtures.Secret, salt, nil)

	pSite := mustPrefix(t, g.Pseudonym(detect.KindCIDR, site, 0))
	pLan := mustPrefix(t, g.Pseudonym(detect.KindCIDR, lan, 0))
	pOther := mustPrefix(t, g.Pseudonym(detect.KindCIDR, other, 0))
	pV6 := mustPrefix(t, g.Pseudonym(detect.KindCIDR, v6net, 0))
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	for _, p := range []netip.Prefix{pSite, pLan, pOther} {
		if !cgnat.Contains(p.Addr()) || p.Masked() != p {
			t.Fatalf("network pseudonym %v is not a masked network inside the marker range", p)
		}
	}
	if pSite.Bits() != 16 || pLan.Bits() != 24 || pOther.Bits() != 24 || pV6.Bits() != 64 {
		t.Fatalf("prefix lengths changed: %v %v %v %v", pSite, pLan, pOther, pV6)
	}
	if !pSite.Contains(pLan.Addr()) {
		t.Fatalf("nested network %v does not lie inside its parent's pseudonym %v", pLan, pSite)
	}
	if pSite.Contains(pOther.Addr()) {
		t.Fatalf("unrelated network %v lies inside %v", pOther, pSite)
	}

	// Hosts.
	inLan := q(10, 13, 7, 42)
	inSite := q(10, 13, 200, 9)
	inOther := q(192, 168, 2, 1)
	outside := q(172, 16, 5, 5)
	inV6 := q6(0xfd12, 0x3456, 0x789a, 1, 0, 0, 0, 0x10)
	hLan := netip.MustParseAddr(g.Pseudonym(detect.KindIPv4, inLan, 0))
	hSite := netip.MustParseAddr(g.Pseudonym(detect.KindIPv4, inSite, 0))
	hOther := netip.MustParseAddr(g.Pseudonym(detect.KindIPv4, inOther, 0))
	hV6 := netip.MustParseAddr(g.Pseudonym(detect.KindIPv6, inV6, 0))
	if !pLan.Contains(hLan) {
		t.Fatalf("host %v not inside its network pseudonym %v", hLan, pLan)
	}
	if !pSite.Contains(hSite) || pLan.Contains(hSite) {
		t.Fatalf("host %v must lie in %v and not in %v", hSite, pSite, pLan)
	}
	if !pOther.Contains(hOther) {
		t.Fatalf("host %v not inside %v", hOther, pOther)
	}
	if !pV6.Contains(hV6) {
		t.Fatalf("v6 host %v not inside %v", hV6, pV6)
	}
	if got := g.Pseudonym(detect.KindIPv4, outside, 0); got != plain.Pseudonym(detect.KindIPv4, outside, 0) {
		t.Fatalf("address outside every network changed: %q vs %q", got, plain.Pseudonym(detect.KindIPv4, outside, 0))
	}

	// Host bits are the address's own: two hosts of one network differ, the
	// same host is stable, a collision attempt changes only the host part.
	other42 := netip.MustParseAddr(g.Pseudonym(detect.KindIPv4, q(10, 13, 7, 43), 0))
	if other42 == hLan || !pLan.Contains(other42) {
		t.Fatalf("neighbour rendered %v, want a different address inside %v", other42, pLan)
	}
	if again := g.Pseudonym(detect.KindIPv4, inLan, 0); again != hLan.String() {
		t.Fatalf("not deterministic: %q vs %q", again, hLan)
	}
	retry := netip.MustParseAddr(g.Pseudonym(detect.KindIPv4, inLan, 1))
	if retry == hLan || !pLan.Contains(retry) {
		t.Fatalf("attempt 1 rendered %v, want another host inside %v", retry, pLan)
	}

	// The network's own address is a host of the network.
	base := netip.MustParseAddr(g.Pseudonym(detect.KindIPv4, q(10, 13, 7, 0), 0))
	if !pLan.Contains(base) {
		t.Fatalf("network address %v not inside %v", base, pLan)
	}
	// A dotted mask is kept.
	if got := g.Pseudonym(detect.KindCIDR, q(10, 13, 7, 0)+"/255.255.255.0", 0); !strings.HasSuffix(got, "/255.255.255.0") || !strings.HasPrefix(got, pLan.Addr().String()) {
		t.Fatalf("dotted mask: got %q, want %v with the mask", got, pLan.Addr())
	}
	// Every result is still a pseudonym shape.
	for _, s := range []string{pSite.String(), pLan.String(), hLan.String(), hV6.String(), pV6.String()} {
		if !g.IsPseudonym(s) {
			t.Fatalf("IsPseudonym(%q) = false", s)
		}
	}
}
