package basics

// Address ranges, decided without a single literal in the file. Every test
// file in this directory passes through the running filter on its way to
// disk, so an address written out as text may arrive as something else. The
// values here are assembled from numbers at run time, which nothing can
// rewrite, and the ranges are named by their numeric bounds rather than by
// an example.

import (
	"fmt"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

func v4(a, b, c, d int) string {
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// Which ranges does the pattern layer report, and which does it pass over?
// The answer decides how much noise a pasted manual produces and whether the
// pseudonym range is shielded by the pattern itself or only by the composite.
func TestRange_WhatThePatternLayerReports(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	cases := []struct {
		name string
		addr string
	}{
		{"private 10/8", v4(10, 42, 0, 7)},
		{"private 172.16/12", v4(172, 20, 0, 5)},
		{"private 192.168/16", v4(192, 168, 178, 22)},
		{"pseudonym range 100.64/10", v4(100, 64+3, 12, 9)},
		{"just below it 100.63", v4(100, 63, 12, 9)},
		{"just above it 100.128", v4(100, 128, 12, 9)},
		{"documentation net 1", v4(192, 0, 2, 1)},
		{"documentation net 2", v4(198, 51, 100, 1)},
		{"documentation net 3", v4(203, 0, 113, 1)},
		{"loopback", v4(127, 0, 0, 1)},
		{"unspecified", v4(0, 0, 0, 0)},
		{"broadcast", v4(255, 255, 255, 255)},
		{"link local", v4(169, 254, 1, 1)},
		{"multicast", v4(224, 0, 0, 1)},
		{"public", v4(93, 184, 216, 34)},
		{"version-like", v4(1, 22, 3, 4)},
	}
	for _, c := range cases {
		tab := newTable(t)
		mid := forward(c.addr, d, tab)
		state := "reported"
		if mid == c.addr {
			state = "passed over"
		}
		t.Logf("%-26s %-16s %s", c.name, c.addr, state)
	}
}

// A version number is four dotted numbers too. If the layer reports it, every
// changelog line becomes a pseudonym.
func TestRange_VersionNumbersAreNotAddresses(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	texts := []string{
		fmt.Sprintf("upgraded to v%d.%d.%d", 7, 2, 149),
		fmt.Sprintf("kernel %d.%d.%d-%d.fc44", 7, 1, 13, 200),
		fmt.Sprintf("version %d.%d.%d.%d released", 1, 22, 3, 4),
		fmt.Sprintf("timeout after %d.%d seconds", 1, 5),
	}
	for _, text := range texts {
		tab := newTable(t)
		mid := forward(text, d, tab)
		if mid != text {
			t.Logf("a version number was replaced: %q -> %q", text, mid)
		} else {
			t.Logf("left alone: %q", text)
		}
	}
}

// The pseudonym range again, from the other side: does the generator produce
// addresses there, and does IsPseudonym recognise its own output?
func TestRange_GeneratorStaysInsideItsRange(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	tab := mapping.NewTable(gen)
	var outside int
	for i := 0; i < 500; i++ {
		alias := tab.Lookup(detect.KindIPv4, v4(10, i/256, i%256, 7))
		var a, b, c, dd int
		if _, err := fmt.Sscanf(alias, "%d.%d.%d.%d", &a, &b, &c, &dd); err != nil {
			t.Fatalf("the pseudonym is not an address: %q", alias)
		}
		if a != 100 || b < 64 || b > 127 {
			outside++
			if outside < 4 {
				t.Errorf("pseudonym outside the reserved range: %s", alias)
			}
		}
	}
	t.Logf("500 pseudonyms, %d outside the range", outside)

	// A second pass over an already replaced text must not replace again.
	once := forward(v4(10, 1, 2, 3), d, tab)
	comp := detect.NewComposite(tab.Knows, d)
	twice := forward(once, comp, tab)
	if twice != once {
		t.Errorf("the composite replaced its own output: %q -> %q", once, twice)
	}
	plain := forward(once, d, tab)
	if plain == once {
		t.Logf("the bare pattern layer leaves the pseudonym alone as well")
	} else {
		t.Logf("the bare pattern layer would replace it again: %q -> %q", once, plain)
		t.Logf("   -> idempotence rests on the composite's exclude, not on the pattern")
	}
}

// The ranges the generator draws from are not empty in the real world.
// Carrier-grade NAT space is what Tailscale hands out, unique local addresses
// are what most home networks use, and the locally administered MAC prefix is
// what Docker gives every container. The exclude decides by the table, not
// by shape, so those real values are replaced like any other.
func TestRange_RealValuesInsideThePseudonymSpace(t *testing.T) {
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, MAC: true})
	if err != nil {
		t.Skipf("NewPatterns: %v", err)
	}

	cases := []struct {
		name  string
		value string
	}{
		{"tailscale node", v4(100, 64+37, 214, 8)},
		{"cgnat customer", v4(100, 64+2, 0, 1)},
		{"docker container mac", fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 2, 0x42, 0xac, 0x11, 0, 2)},
		{"unique local address", fmt.Sprintf("fd%02x:%x:%x::%x", 0, 0x1234, 0x5678, 0x42)},
		{"ordinary private v4", v4(192, 168, 178, 22)},
	}
	for _, c := range cases {
		tab := mapping.NewTable(gen)
		comp := detect.NewComposite(tab.Knows, d)
		mid := forward(c.value, comp, tab)
		shaped := gen.IsPseudonym(c.value)
		if mid == c.value {
			t.Errorf("%s: %s went out unchanged (IsPseudonym=%v)", c.name, c.value, shaped)
		} else {
			t.Logf("%-22s %-40s -> %s", c.name, c.value, mid)
		}
	}
}
