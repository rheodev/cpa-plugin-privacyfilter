package main

import _ "embed"

// embeddedGitleaks holds the built-in gitleaks rules compiled into the shared
// library. The store installer only ships the dynamic library, so we embed the
// rules to guarantee they are available without a sidecar file.
//
//go:embed rules/gitleaks.toml
var embeddedGitleaks []byte
