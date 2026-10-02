package pseudo

import (
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// ShapedTokens returns every token of text that has the shape of a short
// hex pseudonym: one of the prefixes h-, d-, f-, u- and PF_ followed by
// twelve lower-case hex digits, standing on token boundaries, so that a
// letter or digit on either side makes it part of a longer word, unless
// the digit in front ends a percent-escape, "%20d-…", which delimits as it
// does for the restorer. The return path runs it over restored text:
// whatever still has this shape after the restore is a token the model
// wrote in the plugin's shape without a table row behind it, an invented
// name, a pseudonym recalled with slipped digits, or one of another
// conversation quoted from a file. The address shapes are left out,
// because real Tailscale and Docker values share them and would only add
// noise. The result keeps duplicates; the caller counts.
func ShapedTokens(text string) []string {
	var out []string
	for i := 0; i < len(text); i++ {
		if i > 0 && continuesWord(text[i-1]) && !detect.PercentEscapeEnds(text[:i]) {
			continue
		}
		var n, width int
		switch {
		case i+1 < len(text) && text[i+1] == '-' && strings.IndexByte("hdfu", text[i]) >= 0:
			n, width = 2, HexShort
		case strings.HasPrefix(text[i:], PrefixSecret):
			n, width = len(PrefixSecret), HexSecret
		default:
			continue
		}
		end := i + n + width
		if end > len(text) || !isLowerHex(text[i+n:end]) {
			continue
		}
		if end < len(text) && continuesWord(text[end]) {
			continue
		}
		out = append(out, text[i:end])
		i = end - 1
	}
	return out
}

// continuesWord reports whether the byte c binds to a neighbouring token:
// an ASCII letter or digit, or a byte of a multi-byte rune, which is a
// letter in every script the model writes. It is the boundary rule of the
// restorer, so a token the restorer would not have touched is not counted
// either.
func continuesWord(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}
