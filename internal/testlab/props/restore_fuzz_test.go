package props

// Properties of the return direction on its own. Restore is called once per
// response and once per emitted fragment of a stream, so what matters is that
// it reports what it did, that a second pass over its own output changes
// nothing, and that the escaped form agrees with the plain one wherever the
// originals hold no character JSON escapes.

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// restoreSeeds is the corpus: pseudonym shapes alone, glued to a word, twice
// over, and text that holds none.
func restoreSeeds() []string {
	hex12 := strings.Repeat("ab", 6)
	host := "h-" + hex12
	return []string{
		"",
		"nichts zu tun",
		host,
		host + host,
		"x" + host,
		host + "x",
		"(" + host + ")",
		host + "_log",
		"weiß " + host + " 漢字",
		"d-" + hex12 + ".invalid",
		"u-" + strings.Repeat("cd", 4) + "@d-" + hex12 + ".invalid",
		lab.V4(100, 64, 0, 1),
		lab.MAC(0x02, 0xab, 0xab, 0xab, 0xab, 0xab),
		strings.ToUpper(host),
	}
}

// Restore reports what it did, is idempotent over its own output, and reads
// the same in both encodings for originals without escapes.
func FuzzPropsRestore(f *testing.F) {
	for _, seed := range restoreSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInput {
			return
		}
		tab, _ := fillTable(t)
		r := tab.Restorer()

		out, changed := r.Restore(text, false)
		if !changed && out != text {
			t.Errorf("Restore reported no change but rewrote %q to %q", text, out)
		}
		if changed && out == text {
			t.Errorf("Restore reported a change but returned %q unchanged", text)
		}
		if again, _ := r.Restore(out, false); again != out {
			t.Errorf("Restore is not idempotent\n in:    %q\n once:  %q\n twice: %q", text, out, again)
		}
		// None of the fixture originals holds a quote, a backslash or a
		// control character, so both encodings have to agree.
		if esc, _ := r.Restore(text, true); esc != out {
			t.Errorf("the escaped form differs without an escapable original\n plain:   %q\n escaped: %q", out, esc)
		}
	})
}

// A pseudonym the return pass does not know stays as it is. The rule matters
// because a token in pseudonym shape may come from the user's own network,
// and the return pass restores, it never detects.
func FuzzPropsRestoreLeavesUnknownShapes(f *testing.F) {
	for _, seed := range restoreSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInput {
			return
		}
		empty := lab.Table()
		out, changed := empty.Restorer().Restore(text, false)
		if changed || out != text {
			t.Errorf("an empty table changed %q to %q", text, out)
		}
		if h := empty.Restorer().Holdback(text); h != 0 {
			t.Errorf("an empty table held %d bytes of %q back", h, text)
		}
	})
}
