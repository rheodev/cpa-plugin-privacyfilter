// Package config probes the constructors of the plugin against a
// configuration that is wrong. The question is not whether a correct setup
// works, but whether every mistake is refused where the detector is built
// and not carried silently into service.
//
// Reachable from here are detect and pseudo. The wiring in main.go is not,
// so where a check lives in the wiring rather than in the constructor, the
// tests say which of the two is holding.
package config

import (
	"fmt"
	"strconv"
)

// hostName assembles a host name from a number. Every file of this tree runs
// through the running filter on its way to disk, so a name written as a
// literal can arrive as something else; one built at run time cannot.
func hostName(n int) string { return "hst" + strconv.Itoa(1000+n) + ".werk" }

// dirName assembles the name of a directory that identifies a customer.
func dirName(n int) string { return "kunde" + strconv.Itoa(n) }

// changed reports in one word what a replacement did to a text.
func changed(before, after string) string {
	if before == after {
		return "unchanged"
	}
	return fmt.Sprintf("changed to %q", after)
}
