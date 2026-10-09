package detect_test

import (
	"net/netip"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// q and q6 build address strings from their numeric parts, so this file
// holds no dotted quad and no colon-hex literal.
func q(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }

func q6(groups ...uint16) string {
	var b [16]byte
	for i, g := range groups {
		b[2*i], b[2*i+1] = byte(g>>8), byte(g)
	}
	return netip.AddrFrom16(b).String()
}

// Addresses that identify no machine are left alone by the structural
// layer, in bare and in CIDR form, so the model still sees them for what
// they are. Ordinary addresses next to them are found as before.
func TestPatterns_SpecialAddressesUntouched(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true})
	if err != nil {
		t.Fatal(err)
	}
	untouched := []string{
		q(127, 0, 0, 1), q(0, 0, 0, 0), q(255, 255, 255, 255), q(224, 0, 0, 1), q(239, 255, 255, 250),
		q(169, 254, 1, 1), q(192, 0, 2, 10), q(198, 51, 100, 7), q(203, 0, 113, 9),
		q(127, 0, 0, 0) + "/8", q(0, 0, 0, 0) + "/0", q(224, 0, 0, 0) + "/4", q(169, 254, 0, 0) + "/16", q(192, 0, 2, 0) + "/24",
		q6(0, 0, 0, 0, 0, 0, 0, 1), q6(), q6(0xfe80, 0, 0, 0, 0, 0, 0, 1), q6(0xfe80, 0, 0, 0, 0, 0, 0, 1) + "%eth0",
		q6(0xff02, 0, 0, 0, 0, 0, 0, 1), q6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
		q6(0xfe80) + "/64", q6(0xff02) + "/16", q6(0x2001, 0xdb8) + "/32",
	}
	for _, s := range untouched {
		if got := d.Scan("bind " + s + " now"); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want nothing", s, got)
		}
	}
	found := []string{
		q(10, 0, 0, 5), q(192, 168, 1, 1), q(172, 16, 0, 1), q(8, 8, 8, 8),
		q(192, 168, 7, 0) + "/24", q(10, 0, 0, 0) + "/8",
		q6(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1), q6(0x2a01, 0x4f8, 1, 2, 0, 0, 0, 1) + "/64",
	}
	for _, s := range found {
		if got := d.Scan("bind " + s + " now"); len(got) != 1 || got[0].Value != s {
			t.Errorf("Scan(%q) = %+v, want the address itself", s, got)
		}
	}
	// One line with both: only the ordinary addresses are reported.
	line := "listen " + q(127, 0, 0, 1) + ":53 and " + q(192, 168, 7, 1) + ":53 and " + q(10, 0, 0, 5)
	got := d.Scan(line)
	if len(got) != 2 || got[0].Value != q(192, 168, 7, 1) || got[1].Value != q(10, 0, 0, 5) {
		t.Fatalf("Scan = %+v, want only the two ordinary addresses", got)
	}
}
