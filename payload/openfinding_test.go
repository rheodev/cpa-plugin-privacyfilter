package payload_test

import (
	"os"
	"testing"
)

// skipOpenFinding skips a test that holds a finding which is still open. The
// test stays in the tree because it is the reproduction: whoever cures the
// finding deletes this one call and watches the test turn green. To see every
// open finding fail at once, set the variable:
//
//	PRIVACYFILTER_OPEN_FINDINGS=1 go test ./...
//
// What each of them shows, how heavily it weighs and which cure is proposed
// stands in BEFUNDE.md beside these packages.
func skipOpenFinding(tb testing.TB) {
	tb.Helper()
	if os.Getenv("PRIVACYFILTER_OPEN_FINDINGS") == "" {
		tb.Skip("open finding, see internal/testlab/BEFUNDE.md, chapter by chapter")
	}
}
