package pseudo_test

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// ShapedTokens finds the short hex shapes on token boundaries and nothing
// else: not a shape glued to a word, not one with a wrong case or width,
// not the address shapes.
func TestShapedTokens(t *testing.T) {
	seg := "d-0123456789ab"
	host := "h-fedcba987654"
	file := "f-00112233aabb"
	user := "u-abcdef012345"
	opaque := "PF_0a1b2c3d4e5f"
	cases := map[string]string{
		"see " + seg + " here":                   seg,
		seg + "/" + host + "/" + file + ".md":    seg + " " + host + " " + file,
		user + "@" + seg + ".invalid":            user + " " + seg,
		"(" + opaque + ")":                       opaque,
		"backup-" + seg + ".tar":                 seg,
		"x%20" + seg + "%2F" + host:              seg + " " + host, // a percent-escape in front delimits
		"20" + seg + " %2G" + seg:                "",               // a digit without the percent sign does not, nor does "%2G"
		seg:                                      seg,
		"x" + seg + " " + seg + "x " + seg + "1": "",
		"ä" + seg + " " + seg + "ü":              "",
		"D-0123456789AB d-0123456789AB":          "",
		"d-0123456789a d-0123456789abc":          "",
		"d_0123456789ab h0123456789ab":           "",
		"100.64.1.2 02:42:ac:11:00:02":           "",
		"":                                       "",
	}
	for text, want := range cases {
		if got := strings.Join(pseudo.ShapedTokens(text), " "); got != want {
			t.Errorf("ShapedTokens(%q) = %q, want %q", text, got, want)
		}
	}
}
