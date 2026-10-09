package basics

import (
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/payload"
)

// replaceHost is the visitor these tests hand to the walk. Its twin lives
// beside package payload, where the rest of that lab file went.
func replaceHost(p payload.Path, v string) (string, bool) {
	if strings.Contains(v, "zeus.lan") {
		return strings.ReplaceAll(v, "zeus.lan", "h-0123456789ab"), true
	}
	return v, false
}
