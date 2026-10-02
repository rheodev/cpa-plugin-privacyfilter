package detect

import "strings"

// encodedSpace is the space of a URL-encoded path, the way a Markdown link
// writes a directory with a space in its name, "Docker%20Sandboxes". The
// path layer divides a segment at it and reports the words on either side
// on their own, so the model sees the encoded space and can decode it, and
// SegmentTokens splits the model's own words the same way.
const encodedSpace = "%20"

// PercentEscapeEnds reports whether s ends in a percent-escape, "%" and two
// hex digits, the way URL encoding writes a space, a slash or a letter
// outside ASCII. Such an escape is punctuation of the encoded text, so a
// pseudonym or a term right behind it stands on its own although the byte
// in front of it is a digit or a letter: the "0" of "%20d-…" binds to the
// escape, not to the pseudonym. The boundary rules of the detectors, of the
// restorer and of the counter of pseudonym shapes all consult it, so that
// the forward path, the return path and the count agree.
func PercentEscapeEnds(s string) bool {
	n := len(s)
	return n >= 3 && s[n-3] == '%' && isHexByte(s[n-2]) && isHexByte(s[n-1])
}

// SegmentTokens returns the runs of segment characters in text, the
// characters a path segment may consist of, split at every other character,
// at the slash and at an encoded space, with trailing dots removed and
// empty runs left out. A command the model writes, "mkdir -p hallo/unter",
// names its directories without any path shape; these are the words such a
// name could be, so the forward pass can tell later that the model wrote it.
func SegmentTokens(text string) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		for tok := range strings.SplitSeq(text[start:end], encodedSpace) {
			if tok = strings.TrimRight(tok, "."); tok != "" {
				out = append(out, tok)
			}
		}
		start = -1
	}
	for i, r := range text {
		if isSegmentRune(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(text))
	return out
}
