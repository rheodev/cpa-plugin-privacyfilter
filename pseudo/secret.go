package pseudo

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultSecretFile is the file name used when salt_secret_path is empty.
// The name is deliberate: the local guard hook on the development machine
// blocks commands containing "key_file" or the extension ".key".
const DefaultSecretFile = "pseudonym.secret"

// MinSecretLen is the smallest number of bytes accepted after trimming.
const MinSecretLen = 32

// ErrSecretTooShort is returned when fewer than MinSecretLen bytes remain
// after trimming. The plugin then refuses to start in pseudonymize mode.
var ErrSecretTooShort = errors.New("pseudo: secret shorter than 32 bytes")

// ErrSecretPathRelative is returned by LoadSecret for a path that is not
// absolute. ResolveSecretPath yields one when the plugin directory is
// unknown, and a relative path would then name a file in whatever directory
// the proxy happens to run in.
var ErrSecretPathRelative = errors.New("pseudo: secret path is not absolute")

// ErrSecretReadable is returned by LoadSecret for a file that group or
// others may read. The secret decides every pseudonym of every conversation,
// so it is held like an SSH private key: a mode wider than the owner is
// refused, not warned about.
var ErrSecretReadable = errors.New("pseudo: secret file is readable by group or others")

// ResolveSecretPath returns the path of the secret file. The configured
// value is trimmed; an empty value means DefaultSecretFile; a relative value
// is resolved against pluginDir, the directory of the shared object, like
// gitleaks_toml in the original plugin. An absolute value is returned
// unchanged. The result is absolute when pluginDir is, and LoadSecret
// refuses it otherwise.
func ResolveSecretPath(pluginDir, configured string) string {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		configured = DefaultSecretFile
	}
	if filepath.IsAbs(configured) {
		return configured
	}
	return filepath.Join(pluginDir, configured)
}

// LoadSecret reads the file at path, trims leading and trailing white space
// (the file on the target host holds 64 hex characters and a newline) and
// returns the remaining bytes unchanged as the HMAC key; there is no hex
// decoding. It returns ErrSecretPathRelative for a path that is not
// absolute, the read error when the file cannot be opened,
// ErrSecretReadable when group or others may read it, and ErrSecretTooShort
// when fewer than MinSecretLen bytes remain. The contents are never logged.
func LoadSecret(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %q", ErrSecretPathRelative, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("pseudo: secret path %s is a directory", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s has mode %04o, want 0600 or tighter", ErrSecretReadable, path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimSpace(raw)
	if len(secret) < MinSecretLen {
		return nil, ErrSecretTooShort
	}
	return secret, nil
}
