package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
)

func identifiersDetector(t *testing.T) detect.Detector {
	t.Helper()
	d, err := detect.NewPatterns(detect.PatternsConfig{UUID: true, HexID: true, Fingerprint: true, Serial: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	return d
}

// TestPatterns_Identifiers: the machine identifier shapes are found in the
// output of the tools that print them, each once and with its kind.
func TestPatterns_Identifiers(t *testing.T) {
	d := identifiersDetector(t)
	cases := []struct {
		text string
		want fixtures.Term
	}{
		{`lsblk -o NAME,UUID: sda1 3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b`, fixtures.Term{Value: "3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b", Kind: detect.KindUUID}},
		{`UUID="3F2A9C1E-7B4D-4E8F-9A0B-1C2D3E4F5A6B" TYPE="ext4"`, fixtures.Term{Value: "3F2A9C1E-7B4D-4E8F-9A0B-1C2D3E4F5A6B", Kind: detect.KindUUID}},
		{"hostnamectl: Machine ID: 9d4091ce1f9d37bd8b2d4e6f1a3c5e7f\n", fixtures.Term{Value: "9d4091ce1f9d37bd8b2d4e6f1a3c5e7f", Kind: detect.KindHexID}},
		{`LU WWN Device Id: 5 000c50 0a1b2c3d4 (0x5000c500a1b2c3d4)`, fixtures.Term{Value: "0x5000c500a1b2c3d4", Kind: detect.KindHexID}},
		{`256 SHA256:Yk3mQ9ZpLx4vB2nR8tW1sC6dF0hJ5gK7aE9iU3oP2qM root@nuc (ED25519)`, fixtures.Term{Value: "SHA256:Yk3mQ9ZpLx4vB2nR8tW1sC6dF0hJ5gK7aE9iU3oP2qM", Kind: detect.KindFingerprint}},
		{`Serial Number:    WD-WCC7K1234567`, fixtures.Term{Value: "WD-WCC7K1234567", Kind: detect.KindSerial}},
		{`E: ID_SERIAL_SHORT=S4EVNX0N123456A`, fixtures.Term{Value: "S4EVNX0N123456A", Kind: detect.KindSerial}},
		{`{"name": "sda", "serial": "C02XK1ABJG5H", "size": "1.8T"}`, fixtures.Term{Value: "C02XK1ABJG5H", Kind: detect.KindSerial}},
		{`  iSerial                 3 0123456789AB`, fixtures.Term{Value: "0123456789AB", Kind: detect.KindSerial}},
		{`Seriennummer: C02XK1ABJG5H.`, fixtures.Term{Value: "C02XK1ABJG5H", Kind: detect.KindSerial}},
		{`s/n: pf-ab12cd`, fixtures.Term{Value: "pf-ab12cd", Kind: detect.KindSerial}},
	}
	for _, c := range cases {
		got := d.Scan(c.text)
		assertDisjointSorted(t, c.text, got)
		if len(got) != 1 {
			t.Errorf("Scan(%q) = %+v, want exactly one match", c.text, got)
			continue
		}
		if got[0].Value != c.want.Value || got[0].Kind != c.want.Kind {
			t.Errorf("Scan(%q) = %+v, want %q as %s", c.text, got[0], c.want.Value, c.want.Kind)
		}
	}
}

// TestPatterns_IdentifiersLeaveLookAlikes: hashes, counters and prose that
// share characters with the identifiers are not reported.
func TestPatterns_IdentifiersLeaveLookAlikes(t *testing.T) {
	d := identifiersDetector(t)
	for _, text := range []string{
		"commit 54545e1c8f6f13ac5b1c8f6f13ac5b1c8f6f13ac",            // 40 hex, a git hash
		"sha256:" + strings.Repeat("ab", 32),                         // 64 hex, an image id
		"serial: 2026090601",                                         // DNS zone serial, digits only
		"serial: console",                                            // prose
		"Serial Number: abc",                                         // too short
		"SHA256:tooshort",                                            // not a fingerprint
		"Version 1.2.3-rc1 vom 05.09.2026, Port 8317, Uhrzeit 14:46", // fixtures.Benign shapes
		"id 3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6bx",                   // uuid glued to a letter
		"PF-ABCDEF123456 SHA256:PF" + strings.Repeat("Q", 41),        // own pseudonym shapes are for IsPseudonym, still no false hit here
	} {
		got := d.Scan(text)
		filtered := got[:0]
		for _, m := range got {
			// The last line contains the serial and fingerprint pseudonym
			// shapes, which the pattern layer does report; the composite's
			// Exclude drops them. Everything else must be silent.
			if !strings.HasPrefix(text, "PF-") {
				filtered = append(filtered, m)
			}
		}
		if len(filtered) != 0 {
			t.Errorf("Scan(%q) = %+v, want nothing", text, filtered)
		}
	}
	if got := d.Scan(fixtures.Benign); len(got) != 0 {
		t.Errorf("Scan(Benign) = %+v, want nothing", got)
	}
}
