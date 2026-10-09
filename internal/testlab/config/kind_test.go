package config

// The kind is the one word a user must get right in every entry of the term
// list. These tests check the vocabulary itself, the spellings that are near
// misses of it, and what the build reports when one of them arrives.

import (
	"sort"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// configKinds lists every kind the detect package declares as a constant.
var configKinds = []detect.Kind{
	detect.KindIPv4,
	detect.KindIPv6,
	detect.KindCIDR,
	detect.KindMAC,
	detect.KindEmail,
	detect.KindHost,
	detect.KindDomain,
	detect.KindPathSegment,
	detect.KindFileName,
	detect.KindPerson,
	detect.KindIBAN,
	detect.KindURL,
	detect.KindUUID,
	detect.KindHexID,
	detect.KindFingerprint,
	detect.KindSerial,
	detect.KindSecret,
}

// Every declared kind passes Valid, is declared once, and builds a term.
func TestConfig_KindValidOverAllDeclaredKinds(t *testing.T) {
	seen := make(map[detect.Kind]bool, len(configKinds))
	for _, k := range configKinds {
		if !k.Valid() {
			t.Errorf("declared kind %q is not Valid", string(k))
		}
		if seen[k] {
			t.Errorf("kind %q is declared twice", string(k))
		}
		seen[k] = true
		if _, err := detect.NewTerms(detect.TermsConfig{
			WordBoundary: true,
			Terms:        []detect.Term{{Value: hostName(1), Kind: k}},
		}); err != nil {
			t.Errorf("a term of kind %q does not build: %v", string(k), err)
		}
	}
	t.Logf("%d declared kinds", len(configKinds))
}

// Valid and the renderer table are edited in two packages. A kind with a
// renderer that Valid rejects could never be configured; the other direction
// falls back to the opaque token and is only logged, since KindURL is a
// finding of its own.
func TestConfig_KindValidCoversEveryRenderer(t *testing.T) {
	renderers := pseudo.DefaultRenderers()
	for k := range renderers {
		if !k.Valid() {
			t.Errorf("kind %q has a renderer but Valid rejects it", string(k))
		}
	}
	var without []string
	for _, k := range configKinds {
		if _, ok := renderers[k]; !ok {
			without = append(without, string(k))
		}
	}
	sort.Strings(without)
	t.Logf("valid kinds without a renderer of their own: %v", without)
}

// The spellings a hand-written configuration produces. None of them may pass.
func TestConfig_KindNearMissesAreRefused(t *testing.T) {
	near := []string{
		"", " ", "host ", " host", "HOST", "Host", "hosts", "hostname",
		"ip", "ipv_4", "IPv4", "ipv4/24", "path-segment", "pathsegment",
		"path_segments", "file_name", "fileName", "hex_id", "hexID",
		"mac_address", "e-mail", "mail", "person_name", "name", "uuid4",
		"secrets", "iban ", "url ",
	}
	for _, s := range near {
		if detect.Kind(s).Valid() {
			t.Errorf("kind %q is accepted", s)
		}
	}
}

// The report for a wrong kind names the position, quotes the word and lists
// the accepted vocabulary. The position is an index into the list handed to
// the constructor; the wiring in main.go reports the line of the term file
// instead, which it knows and the constructor does not.
func TestConfig_InvalidKindReport(t *testing.T) {
	_, err := detect.NewTerms(detect.TermsConfig{
		WordBoundary: true,
		Terms: []detect.Term{
			{Value: hostName(1), Kind: detect.KindHost},
			{Value: hostName(2), Kind: detect.Kind("file_name")},
		},
	})
	if err == nil {
		t.Fatal("a term with an unknown kind was accepted")
	}
	msg := err.Error()
	if !strings.Contains(msg, "file_name") {
		t.Errorf("the report does not quote the rejected word: %q", msg)
	}
	if !strings.Contains(msg, "1") {
		t.Errorf("the report does not name the position: %q", msg)
	}
	named := 0
	for _, k := range configKinds {
		if strings.Contains(msg, string(k)) {
			named++
		}
	}
	t.Logf("report: %s", msg)
	if named != len(configKinds) {
		t.Errorf("the report names %d of %d accepted kinds", named, len(configKinds))
	}
}
