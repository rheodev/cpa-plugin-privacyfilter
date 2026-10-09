package detect_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// allPatterns is the structural layer with every category of milestone 1 on.
func allPatterns(t *testing.T) detect.Detector {
	t.Helper()
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true, MAC: true, Email: true, IBAN: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	return d
}

// TestPatterns_UnderscoreIsADelimiter pins the rule that separates the
// structural layer from the term list: an underscore next to an address is a
// delimiter, not part of a word. A log file name must not hide the address
// inside it.
func TestPatterns_UnderscoreIsADelimiter(t *testing.T) {
	d := allPatterns(t)
	cases := []struct {
		text  string
		value string
		kind  detect.Kind
	}{
		{"scan_10.13.7.42.log", "10.13.7.42", detect.KindIPv4},
		{"host_192.168.2.15", "192.168.2.15", detect.KindIPv4},
		{"nmap_10.13.0.0/16.xml", "10.13.0.0/16", detect.KindCIDR},
		{"iface_a4:5e:60:c1:2b:3d_up", "a4:5e:60:c1:2b:3d", detect.KindMAC},
		{"ref_DE89370400440532013000_alt", "DE89370400440532013000", detect.KindIBAN},
		{"log_fd12:3456:789a::1.txt", "fd12:3456:789a::1", detect.KindIPv6},
	}
	for _, c := range cases {
		got := d.Scan(c.text)
		assertDisjointSorted(t, c.text, got)
		if len(got) != 1 {
			t.Errorf("Scan(%q) = %+v, want exactly one match", c.text, got)
			continue
		}
		if got[0].Value != c.value || got[0].Kind != c.kind {
			t.Errorf("Scan(%q) = %+v, want %q as %q", c.text, got[0], c.value, c.kind)
		}
	}
}

// TestPatterns_NoQuadInsideDigitRun is the other half of the same rule: a
// letter or a digit next to a candidate still rejects it, and the rejection
// does not smuggle in a shortened address either.
func TestPatterns_NoQuadInsideDigitRun(t *testing.T) {
	d := allPatterns(t)
	for _, text := range []string{"12345.6.7.8", "10.13.7.42a", "x10.13.7.42"} {
		if got := d.Scan(text); len(got) != 0 {
			t.Errorf("Scan(%q) = %+v, want nothing", text, got)
		}
	}
}

// TestMerge_ManyMixedLengths exercises the coverage path of the merge, which
// takes over from the sorted insertion once the candidates get numerous. The
// long span of every group must win over the short one inside it, the second
// short one must survive, and the result must stay sorted and disjoint.
func TestMerge_ManyMixedLengths(t *testing.T) {
	const groups = 200
	text := strings.Repeat("x", groups*20)
	var long, short []detect.Match
	for i := 0; i < groups; i++ {
		base := i * 20
		long = append(long, m(base, base+10, text, detect.KindHost, "long"))
		short = append(short, m(base+5, base+8, text, detect.KindSecret, "short"))
		short = append(short, m(base+12, base+15, text, detect.KindSecret, "short"))
	}
	got := detect.Merge(long, short)
	assertDisjointSorted(t, text, got)
	if len(got) != 2*groups {
		t.Fatalf("Merge returned %d matches, want %d", len(got), 2*groups)
	}
	for i, x := range got {
		wantStart := (i/2)*20 + (i%2)*12
		if x.Start != wantStart {
			t.Fatalf("match %d starts at %d, want %d", i, x.Start, wantStart)
		}
		if i%2 == 0 && x.Source != "long" {
			t.Fatalf("match %d source = %q, want the longer span to win", i, x.Source)
		}
	}
	if again := detect.Merge(long, short); len(again) != len(got) {
		t.Fatal("Merge is not deterministic on the coverage path")
	}
}

// TestPatterns_ManyAddresses runs the same scale through the structural layer,
// where the candidates of one text carry mixed lengths.
func TestPatterns_ManyAddresses(t *testing.T) {
	const rounds = 200
	text := strings.Repeat("ping 10.13.7.42 und 192.168.2.15; ", rounds)
	got := allPatterns(t).Scan(text)
	assertDisjointSorted(t, text, got)
	if len(got) != 2*rounds {
		t.Fatalf("Scan found %d addresses, want %d", len(got), 2*rounds)
	}
	for i, x := range got {
		want := "10.13.7.42"
		if i%2 == 1 {
			want = "192.168.2.15"
		}
		if x.Value != want || x.Kind != detect.KindIPv4 {
			t.Fatalf("match %d = %+v, want %q", i, x, want)
		}
	}
}
