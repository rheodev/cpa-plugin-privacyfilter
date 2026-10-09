package config

// Every class of the structural layer is a switch, and every switch is off
// unless the configuration turns it on. An empty PatternsConfig therefore
// finds nothing at all, which is the shape a test writes by accident and a
// configuration writes when the section is missing.

import (
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

func TestConfig_PatternsEveryClassIsOffByDefault(t *testing.T) {
	classes := []struct {
		name string
		cfg  detect.PatternsConfig
		text string
	}{
		{"ipv4", detect.PatternsConfig{IPv4: true}, "addr " + lab.V4(10, 17, 42, 9)},
		{"mac", detect.PatternsConfig{MAC: true}, "mac " + lab.MAC(0xa4, 0xbb, 0x6d, 0x11, 0x22, 0x33)},
		{"email", detect.PatternsConfig{Email: true}, "mail " + "erika" + "@" + "beispiel" + ".de"},
	}
	off := lab.Patterns(t, detect.PatternsConfig{})
	for _, c := range classes {
		if ms := off.Scan(c.text); len(ms) != 0 {
			t.Errorf("%s: the empty configuration reported %d hits in %q", c.name, len(ms), c.text)
		}
		if ms := lab.Patterns(t, c.cfg).Scan(c.text); len(ms) == 0 {
			t.Errorf("%s: the switch is on and nothing was reported for %q", c.name, c.text)
		}
	}
	t.Logf("%d classes, each silent until its own switch is set", len(classes))
}

// What the pattern constructor refuses. Nothing either; the struct has no
// value it could reject.
func TestConfig_PatternsConstructorRefusesNothing(t *testing.T) {
	all := detect.PatternsConfig{
		IPv4: true, IPv6: true, CIDR: true, MAC: true, Email: true, IBAN: true,
		URL: true, UUID: true, HexID: true, Fingerprint: true, Serial: true,
	}
	for _, cfg := range []detect.PatternsConfig{{}, all} {
		if _, err := detect.NewPatterns(cfg); err != nil {
			t.Errorf("NewPatterns refused a configuration: %v", err)
		}
	}
	t.Log("neither the empty nor the complete configuration is refused")
}
