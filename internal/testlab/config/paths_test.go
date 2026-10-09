package config

// The path layer is the safety net for the directory nobody entered in the
// term list, and its preserve list is the one knob a user turns on it.
// NewPaths has an error in its signature and never returns one; these tests
// ask what it therefore accepts.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// configPath assembles an absolute path from its segments, so no path
// literal stands in this file.
func configPath(seg ...string) string { return "/" + strings.Join(seg, "/") }

// Empty and blank entries are trimmed away and change nothing.
func TestConfig_PathsPreserveEmptyEntries(t *testing.T) {
	customer := dirName(4711)
	path := configPath("mnt", customer, "notes.txt")
	plain := lab.Forward(path, lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true}), lab.Table())
	blank := lab.Forward(path, lab.Paths(t, detect.PathsConfig{
		ReplaceUnknown: true,
		Preserve:       []string{"", "   ", "\t", "\n"},
	}), lab.Table())
	if plain != blank {
		t.Errorf("blank preserve entries changed the result: %q against %q", plain, blank)
	}
	if strings.Contains(plain, customer) {
		t.Fatalf("the customer directory was not replaced at all: %q", plain)
	}
	t.Logf("%q\n   -> %q", path, plain)
}

// A preserve entry is compared against a single segment, so an entry that
// carries a slash, a trailing slash or a wildcard can never equal one. Such
// an entry is accepted and does nothing, and the user reads his own
// configuration and believes the directory is preserved.
func TestConfig_PathsPreserveEntriesThatCannotMatch(t *testing.T) {
	customer := dirName(4711)
	path := configPath("mnt", customer, "notes.txt")
	entries := []string{
		"/" + customer,
		customer + "/",
		"mnt/" + customer,
		"*",
	}
	for _, e := range entries {
		d, err := detect.NewPaths(detect.PathsConfig{ReplaceUnknown: true, Preserve: []string{e}})
		if err != nil {
			t.Logf("preserve entry %q refused: %v", e, err)
			continue
		}
		got := lab.Forward(path, d, lab.Table())
		if strings.Contains(got, customer) {
			t.Logf("preserve entry %q took effect", e)
			continue
		}
		t.Errorf("preserve entry %q was accepted, has no effect and is not reported: %q -> %q", e, path, got)
	}
}

// The comparison is exact, so an entry must be written the way the segment
// appears. The built-in list carries efi and EFI side by side for that
// reason; a user has no such hint.
func TestConfig_PathsPreserveIsCaseSensitive(t *testing.T) {
	segment := "Kunden"
	path := configPath("mnt", segment, "notes.txt")
	lower := lab.Forward(path, lab.Paths(t, detect.PathsConfig{
		ReplaceUnknown: true,
		Preserve:       []string{strings.ToLower(segment)},
	}), lab.Table())
	exact := lab.Forward(path, lab.Paths(t, detect.PathsConfig{
		ReplaceUnknown: true,
		Preserve:       []string{segment},
	}), lab.Table())
	t.Logf("entry %q against segment %q: %q", strings.ToLower(segment), segment, lower)
	t.Logf("entry %q against segment %q: %q", segment, segment, exact)
	if !strings.Contains(exact, segment) {
		t.Errorf("the exact entry did not preserve the segment: %q", exact)
	}
}

// What the path constructor refuses. Nothing.
func TestConfig_PathsConstructorRefusesNothing(t *testing.T) {
	cases := []struct {
		name string
		cfg  detect.PathsConfig
	}{
		{"an empty configuration", detect.PathsConfig{}},
		{"replace_unknown off and no known values", detect.PathsConfig{ReplaceUnknown: false}},
		{"preserve entries that are only white space", detect.PathsConfig{Preserve: []string{" ", "\t"}}},
		{"a preserve entry with a slash", detect.PathsConfig{Preserve: []string{"a/b"}}},
		{"a preserve entry that is a glob", detect.PathsConfig{Preserve: []string{"*"}}},
		{"a preserve entry of ten thousand characters", detect.PathsConfig{Preserve: []string{strings.Repeat("x", 10000)}}},
		{"a preserve entry that is a dot", detect.PathsConfig{Preserve: []string{"."}}},
	}
	for _, c := range cases {
		if _, err := detect.NewPaths(c.cfg); err != nil {
			t.Logf("%s: refused: %v", c.name, err)
			continue
		}
		t.Logf("%s: accepted", c.name)
	}
}
