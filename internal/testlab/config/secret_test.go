package config

// The salt secret decides every pseudonym of every conversation. Its rules
// live in package pseudo: a minimum length, a default file name, and a
// resolution against the plugin directory. These tests ask which of the
// rules hold where the value is built and which only where it is read.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// secretOfLen returns n bytes that are a key of nothing.
func secretOfLen(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// The length is measured after trimming, and the boundary is exact.
func TestConfig_LoadSecretLengthBoundary(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []int{0, 1, 31, pseudo.MinSecretLen, pseudo.MinSecretLen + 1, 64} {
		path := filepath.Join(dir, "k"+strconv.Itoa(n))
		if err := os.WriteFile(path, secretOfLen(n), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := pseudo.LoadSecret(path)
		if n < pseudo.MinSecretLen {
			if !errors.Is(err, pseudo.ErrSecretTooShort) {
				t.Errorf("%d bytes: want ErrSecretTooShort, got %v", n, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%d bytes: %v", n, err)
			continue
		}
		if len(got) != n {
			t.Errorf("%d bytes in, %d bytes back", n, len(got))
		}
	}
}

// A file that looks long enough in an editor can still be refused, because
// the trailing newline does not count.
func TestConfig_LoadSecretTrimsBeforeMeasuring(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name     string
		content  []byte
		accepted bool
	}{
		{"the exact length and a newline", append(secretOfLen(pseudo.MinSecretLen), '\n'), true},
		{"one byte short and a newline", append(secretOfLen(pseudo.MinSecretLen-1), '\n'), false},
		{"space around a long enough key", []byte("  " + string(secretOfLen(pseudo.MinSecretLen)) + " \t\n"), true},
		{"white space only", []byte("   \n\t\n"), false},
		{"empty", nil, false},
	}
	for i, c := range cases {
		path := filepath.Join(dir, "c"+strconv.Itoa(i))
		if err := os.WriteFile(path, c.content, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := pseudo.LoadSecret(path)
		if c.accepted && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.accepted && !errors.Is(err, pseudo.ErrSecretTooShort) {
			t.Errorf("%s: want ErrSecretTooShort, got %v", c.name, err)
		}
	}
}

// Everything between the first and the last non-space byte is the key. A
// comment line a user adds to remember what the file is changes every
// pseudonym of every conversation, and nothing reports it.
func TestConfig_LoadSecretKeepsEverythingBetween(t *testing.T) {
	dir := t.TempDir()
	key := secretOfLen(64)
	plain := filepath.Join(dir, "plain")
	commented := filepath.Join(dir, "commented")
	if err := os.WriteFile(plain, append(bytes.Clone(key), '\n'), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	head := append([]byte("# the salt of this host\n"), key...)
	if err := os.WriteFile(commented, append(head, '\n'), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	a, err := pseudo.LoadSecret(plain)
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	b, err := pseudo.LoadSecret(commented)
	if err != nil {
		t.Fatalf("commented: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("the comment line was dropped")
	}
	host := hostName(31)
	pa := pseudo.NewGenerator(a, []byte(lab.Salt), nil).Pseudonym(detect.KindHost, host, 0)
	pb := pseudo.NewGenerator(b, []byte(lab.Salt), nil).Pseudonym(detect.KindHost, host, 0)
	t.Logf("key of %d bytes against key of %d bytes", len(a), len(b))
	t.Logf("the same host is %q with the plain file and %q with the commented one", pa, pb)
	if pa == pb {
		t.Error("two different keys produced the same pseudonym")
	}
}

// The file that is not there, the path that is a directory, the empty path.
func TestConfig_LoadSecretUnreadable(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, pseudo.DefaultSecretFile)
	_, err := pseudo.LoadSecret(missing)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing file gave %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), pseudo.DefaultSecretFile) {
		t.Errorf("the report does not name the file: %v", err)
	}
	t.Logf("missing file: %v", err)

	if _, err := pseudo.LoadSecret(dir); err == nil {
		t.Error("a directory was accepted as the secret")
	} else {
		t.Logf("directory: %v", err)
	}

	if _, err := pseudo.LoadSecret(""); err == nil {
		t.Error("an empty path was accepted as the secret")
	} else {
		t.Logf("empty path: %v", err)
	}
}

// The mode of the file is looked at, and held like ssh holds a private key:
// a secret every account on the machine can read is refused, because it is
// the one value that makes the pseudonyms of a whole conversation reversible.
func TestConfig_SecretFileMode(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		mode     os.FileMode
		accepted bool
	}{
		{0o600, true},
		{0o400, true},
		{0o640, false},
		{0o644, false},
		{0o604, false},
	}
	for i, c := range cases {
		path := filepath.Join(dir, "m"+strconv.Itoa(i))
		if err := os.WriteFile(path, secretOfLen(64), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		_, err := pseudo.LoadSecret(path)
		switch {
		case c.accepted && err != nil:
			t.Errorf("mode %04o: refused: %v", c.mode, err)
		case !c.accepted && !errors.Is(err, pseudo.ErrSecretReadable):
			t.Errorf("mode %04o: want ErrSecretReadable, got %v", c.mode, err)
		case !c.accepted && !strings.Contains(err.Error(), "0600"):
			t.Errorf("mode %04o: the report does not say what mode is wanted: %v", c.mode, err)
		}
	}
}

// MinSecretLen is a rule of the package that its constructor does not
// apply: a generator over an empty secret renders like any other, which the
// tests of this module rely on. In service the generator is only reached
// through LoadSecret, so the rule holds there, and a caller that takes a
// secret from elsewhere has CheckSecret, which applies the same rule.
func TestConfig_NewGeneratorSecretLength(t *testing.T) {
	host := hostName(41)
	for _, n := range []int{0, 1, 8, pseudo.MinSecretLen - 1} {
		g := pseudo.NewGenerator(secretOfLen(n), []byte(lab.Salt), nil)
		p := g.Pseudonym(detect.KindHost, host, 0)
		if p == "" || p == host {
			t.Errorf("a secret of %d bytes produced %q", n, p)
		}
		if err := pseudo.CheckSecret(secretOfLen(n)); !errors.Is(err, pseudo.ErrSecretTooShort) {
			t.Errorf("CheckSecret over %d bytes = %v, want ErrSecretTooShort", n, err)
		}
	}
	if err := pseudo.CheckSecret(append(secretOfLen(pseudo.MinSecretLen), '\n')); err != nil {
		t.Errorf("CheckSecret refused a secret of the minimum length: %v", err)
	}
	first := pseudo.NewGenerator(nil, nil, nil).Pseudonym(detect.KindHost, host, 0)
	second := pseudo.NewGenerator(nil, nil, nil).Pseudonym(detect.KindHost, host, 0)
	if first != second {
		t.Fatal("two generators without a secret disagree")
	}
	t.Logf("without secret and salt the pseudonym is a fixed function of the value: %q", first)
}

// nil renderers mean the defaults, an empty map means none, and every kind
// then falls back to the opaque token. Both are documented; the difference
// between nil and empty is the trap.
func TestConfig_NewGeneratorRendererMap(t *testing.T) {
	host := hostName(42)
	secret := secretOfLen(64)
	withDefaults := pseudo.NewGenerator(secret, nil, nil).Pseudonym(detect.KindHost, host, 0)
	withNone := pseudo.NewGenerator(secret, nil, map[detect.Kind]pseudo.Renderer{}).Pseudonym(detect.KindHost, host, 0)
	if withDefaults == withNone {
		t.Fatalf("the empty map produced the default shape: %q", withNone)
	}
	t.Logf("nil renderers: %q, empty map: %q", withDefaults, withNone)
}

// The default name and an absolute value.
func TestConfig_ResolveSecretPathDefaults(t *testing.T) {
	dir := t.TempDir()
	got := pseudo.ResolveSecretPath(dir, "")
	if filepath.Dir(got) != dir {
		t.Errorf("the default landed outside the plugin directory: %q", got)
	}
	if filepath.Base(got) != pseudo.DefaultSecretFile {
		t.Errorf("want the default file name, got %q", filepath.Base(got))
	}

	rel := filepath.Join("etc", "own.dat")
	if want := filepath.Join(dir, rel); pseudo.ResolveSecretPath(dir, rel) != want {
		t.Errorf("a relative value was not resolved against the plugin directory")
	}

	abs := filepath.Join(t.TempDir(), "elsewhere.dat")
	if got := pseudo.ResolveSecretPath(dir, abs); got != abs {
		t.Errorf("an absolute value was changed: %q", got)
	}
}

// The result is only absolute when the plugin directory is. Without one the
// resolver yields a bare file name, and LoadSecret refuses it, so the plugin
// never reads the secret from whatever directory the proxy happens to run in.
func TestConfig_SecretPathWithoutPluginDir(t *testing.T) {
	got := pseudo.ResolveSecretPath("", "")
	if filepath.IsAbs(got) {
		t.Logf("resolved to an absolute path: %q", got)
		return
	}
	if got != pseudo.DefaultSecretFile {
		t.Errorf("want the bare default name, got %q", got)
	}
	if _, err := pseudo.LoadSecret(got); !errors.Is(err, pseudo.ErrSecretPathRelative) {
		t.Errorf("a relative secret path was not refused: %v", err)
	}
	rel := pseudo.ResolveSecretPath("", filepath.Join("etc", "own.dat"))
	if _, err := pseudo.LoadSecret(rel); !errors.Is(err, pseudo.ErrSecretPathRelative) {
		t.Errorf("a relative configured value without a plugin directory was not refused: %v", err)
	}
}

// Two values that need care: one that climbs out of the plugin directory,
// which is allowed and does what it says, and one that is only white space,
// which is trimmed and then means the default.
func TestConfig_SecretPathClimbingAndBlank(t *testing.T) {
	dir := t.TempDir()
	up := pseudo.ResolveSecretPath(dir, filepath.Join("..", "..", "elsewhere.dat"))
	if strings.HasPrefix(up, dir) {
		t.Errorf("the climbing value stayed inside the plugin directory: %q", up)
	}
	t.Logf("a climbing value resolves outside the plugin directory, as written")

	blank := pseudo.ResolveSecretPath(dir, "   ")
	if blank != filepath.Join(dir, pseudo.DefaultSecretFile) {
		t.Errorf("a blank value was not treated as empty: %q", blank)
	}
	padded := pseudo.ResolveSecretPath(dir, " own.dat\t")
	if padded != filepath.Join(dir, "own.dat") {
		t.Errorf("white space around the value was kept: %q", padded)
	}
}
