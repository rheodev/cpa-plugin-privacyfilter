package detect

import "strings"

// SegmentTokens returns the runs of segment characters in text, the
// characters a path segment may consist of, split at every other character
// and at the slash, with trailing dots removed and empty runs left out. A
// command the model writes, "mkdir -p hallo/unter", names its directories
// without any path shape; these are the words such a name could be, so the
// forward pass can tell later that the model wrote it.
func SegmentTokens(text string) []string {
	var out []string
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		if tok := strings.TrimRight(text[start:end], "."); tok != "" {
			out = append(out, tok)
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
