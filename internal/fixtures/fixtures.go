// Package fixtures holds the invented test corpus shared by the package
// tests. Every value here is made up and matches the shape of the real
// values it stands in for; none is or ever was a real credential, address
// or person. Values that must look like credentials are assembled from
// parts so the file never contains a complete well-known token prefix.
//
// The corpus is written with the Write tool, never through a shell, because
// the guard hook on the development machine inspects command strings for
// secret-shaped text.
package fixtures

import (
	"strings"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Secret is a 64-hex-character test secret, the shape of pseudonym.secret.
// It is deliberately a repeating pattern so nobody mistakes it for a value
// worth protecting.
var Secret = []byte(strings.Repeat("0123456789abcdef", 4))

// SessionA and SessionB are two Claude Code session identifiers.
const (
	SessionA = "7f3c2a1e-4b5d-4e6f-8a9b-0c1d2e3f4a5b"
	SessionB = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
)

// UserIDFor builds a metadata.user_id in the form Claude Code sends:
// user_<hash>_account_<uuid>_session_<uuid>.
func UserIDFor(session string) string {
	return "user_1111111111111111111111111111111111111111111111111111111111111111" +
		"_account_00000000-0000-4000-8000-000000000000_session_" + session
}

// Term is a corpus entry: a confidential value with the kind a detector must
// assign to it. Either Value or Regex is set, as in detect.Term.
type Term struct {
	Value      string
	Regex      string
	Kind       detect.Kind
	IgnoreCase bool
}

// Terms is the maintained list of the test user. Its shape mirrors the real
// list: given name, nickname and surname as separate case-insensitive
// entries, a domain built from the surname, one host suffix as a regular
// expression, and short hostnames with and without a .local suffix. The
// values themselves are invented.
var Terms = []Term{
	{Value: "markus", Kind: detect.KindPerson, IgnoreCase: true},
	{Value: "maki", Kind: detect.KindPerson, IgnoreCase: true},
	{Value: "wendler", Kind: detect.KindPerson, IgnoreCase: true},
	{Value: "wendler.de", Kind: detect.KindDomain},
	{Regex: `[a-z0-9-]+\.home\.lan`, Kind: detect.KindHost},
	{Value: "p14", Kind: detect.KindHost},
	{Value: "p14.local", Kind: detect.KindHost},
	{Value: "nuc", Kind: detect.KindHost},
	{Value: "nuc.local", Kind: detect.KindHost},
	{Value: "athene.lan", Kind: detect.KindHost},
	{Value: "helios-nas-01", Kind: detect.KindHost},
	{Value: "10.13.0.0/16", Kind: detect.KindCIDR},
}

// Literals returns the terms with a Value, the ones a leak test can search
// for byte by byte; regex terms are covered by SuffixHosts.
func Literals() []Term {
	var out []Term
	for _, t := range Terms {
		if t.Value != "" {
			out = append(out, t)
		}
	}
	return out
}

// SuffixHosts are hostnames only the regex term finds.
var SuffixHosts = []Term{
	{Value: "nas.home.lan", Kind: detect.KindHost},
	{Value: "drucker-1.home.lan", Kind: detect.KindHost},
}

// Structured are values the pattern layer must find on its own.
var Structured = []Term{
	{Value: "10.13.7.42", Kind: detect.KindIPv4},
	{Value: "192.168.2.15", Kind: detect.KindIPv4},
	{Value: "fd12:3456:789a::1", Kind: detect.KindIPv6},
	{Value: "2a01:4f8:c010:5e60::1", Kind: detect.KindIPv6},
	{Value: "192.168.2.0/24", Kind: detect.KindCIDR},
	{Value: "10.13.*.*", Kind: detect.KindCIDR},
	{Value: "a4:5e:60:c1:2b:3d", Kind: detect.KindMAC},
	{Value: "markus@wendler.de", Kind: detect.KindEmail},
	{Value: "DE89370400440532013000", Kind: detect.KindIBAN},
	{Value: "3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b", Kind: detect.KindUUID},
	{Value: "9d4091ce1f9d37bd8b2d4e6f1a3c5e7f", Kind: detect.KindHexID},
	{Value: "0x5000c500a1b2c3d4", Kind: detect.KindHexID},
	{Value: "SHA256:Yk3mQ9ZpLx4vB2nR8tW1sC6dF0hJ5gK7aE9iU3oP2qM", Kind: detect.KindFingerprint},
}

// FakeToken assembles a credential-shaped string at runtime so the source
// file never contains one. The result has the shape of a GitHub personal
// access token: a four-letter prefix, an underscore and 36 base62 characters.
func FakeToken() string {
	// 36 characters with many distinct symbols: the shipped gitleaks rule for
	// this shape requires a Shannon entropy of 3, which a repeating pattern
	// does not reach.
	return "gh" + "p_" + "Q7v2Kd9Lm4Xs8Wb1Zc6Nf3Hj5Rt0Yp2Gu7Ea"
}

// Secrets are values the secret layers (packyme, betterleaks) must find.
var Secrets = []Term{
	{Value: FakeToken(), Kind: detect.KindSecret},
}

// Labelled are values the pattern layer finds only behind their label, as
// Prose writes them: a serial number after "Seriennummer:".
var Labelled = []Term{
	{Value: "C02XK1ABJG5H", Kind: detect.KindSerial},
}

// PathParts are the identifying segments of the paths in Prose, which the
// path layer must find on its own: the login name, the customer directory
// and the file names. The ordinary segments around them stay.
var PathParts = []Term{
	{Value: "mwendler", Kind: detect.KindPathSegment},
	{Value: "kunde-x", Kind: detect.KindPathSegment},
	{Value: "main.go", Kind: detect.KindFileName},
	{Value: "cliproxyapi", Kind: detect.KindPathSegment},
}

// All returns every confidential literal of the corpus. The leak test
// asserts that none of them survives the forward pass.
func All() []Term {
	lits := Literals()
	out := make([]Term, 0, len(lits)+len(SuffixHosts)+len(Structured)+len(Secrets)+len(Labelled)+len(PathParts))
	out = append(out, lits...)
	out = append(out, SuffixHosts...)
	out = append(out, Structured...)
	out = append(out, Secrets...)
	out = append(out, Labelled...)
	out = append(out, PathParts...)
	return out
}

// DetectTerms converts Terms into the configuration of the detect package.
func DetectTerms() []detect.Term {
	out := make([]detect.Term, 0, len(Terms))
	for _, t := range Terms {
		out = append(out, detect.Term{Value: t.Value, Regex: t.Regex, Kind: t.Kind, IgnoreCase: t.IgnoreCase})
	}
	return out
}

// Values returns only the strings of ts.
func Values(ts []Term) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Value
	}
	return out
}

// Prose is a user message that mentions most corpus values in running
// text, including one at the very end without trailing punctuation and one
// inside a longer word-like token.
var Prose = "Bitte prüfe, warum athene.lan (10.13.7.42) den Backup-Job auf helios-nas-01 nicht erreicht. " +
	"Der Router hat 192.168.2.15, das Netz ist 10.13.0.0/16, IPv6 fd12:3456:789a::1. " +
	"Mail an markus@wendler.de, Ansprechpartner Markus Wendler, kurz Maki, Webseite wendler.de. " +
	"Die Laptops heißen p14 und p14.local, der Server nuc (nuc.local), das NAS nas.home.lan, der Drucker drucker-1.home.lan. " +
	"MAC a4:5e:60:c1:2b:3d, IBAN DE89370400440532013000, Token " + FakeToken() + ". " +
	"Die Platte hat UUID 3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b, WWN 0x5000c500a1b2c3d4, Seriennummer: C02XK1ABJG5H, " +
	"die machine-id ist 9d4091ce1f9d37bd8b2d4e6f1a3c5e7f, der Host-Key SHA256:Yk3mQ9ZpLx4vB2nR8tW1sC6dF0hJ5gK7aE9iU3oP2qM. " +
	"Der Code liegt in " + PathExamples[0] + ", die Konfiguration in " + PathExamples[2] + ". " +
	"Der Plan ist gut. Zuletzt noch MARKUS"

// Benign is a message that must come out of the forward pass byte for byte
// unchanged. It contains look-alikes: a version number, words containing a
// term as a substring ("Nucleus" contains "nuc", "Markusplatz" contains
// "markus", "Wendlers" is not "wendler" as a whole word), a host with a
// different suffix, an ordinary date, a time, a domain the term list does not
// name. It contains no dotted quad, because any dotted quad is a legitimate
// IPv4 hit.
var Benign = "Version 1.2.3-rc1 vom 05.09.2026, der Plan steht, Nucleus läuft am Markusplatz. " +
	"Die Datei heißt README.md, der Port ist 8317, die Uhrzeit 14:46:00, der Host heißt drucker.work.lan. " +
	"Ein Beispiel für die Doku: example.com."

// PathExamples are the paths Prose mentions; PathParts lists what the path
// layer must replace in them.
var PathExamples = []string{
	"/home/mwendler/Projekte/kunde-x/src/main.go",
	"/home/mwendler/Projekte/kunde-x/README.md",
	"/mnt/part4/Container/cliproxyapi/config.yaml",
}

// ThinkingSignature is a made-up signature of a thinking block. It has the
// base64 shape a secret detector might flag, which is why it must be on the
// deny list.
const ThinkingSignature = "EqQBCkYIBRgCIkAxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVm"

// ToolUseID is a made-up tool_use id in the Anthropic shape.
const ToolUseID = "toolu_01A2B3C4D5E6F7G8H9J0K1L2"

// Request builds an Anthropic Messages request body in the shape Claude Code
// sends: system prompt, tools with name and description, a history with a
// user message, an assistant turn containing a thinking block and a tool_use
// with arguments, the tool_result, and a final user message. Every string
// field that the deny list must protect is present. session goes into
// metadata.user_id; pass "" to leave metadata out.
//
// The thinking block carries an address but deliberately no term of the list:
// the golden test of package payload replaces the host term in every visited
// string and then demands that none survives anywhere in the body, which a
// denied block containing it could not satisfy. The address that stays is what
// proves the block is passed through untouched.
func Request(session string) map[string]any {
	req := map[string]any{
		"model":      "claude-fable-5-1",
		"max_tokens": 4096,
		"stream":     true,
		"system": []any{
			map[string]any{
				"type":          "text",
				"text":          "Du arbeitest für Markus Wendler auf athene.lan im Netz 10.13.0.0/16.",
				"cache_control": map[string]any{"type": "ephemeral"},
			},
		},
		"tools": []any{
			map[string]any{
				"name":        "Bash",
				"description": "Führt Befehle aus, zum Beispiel ssh helios-nas-01.",
				"input_schema": map[string]any{
					"type":       "object",
					"properties": map[string]any{"command": map[string]any{"type": "string"}},
				},
			},
		},
		"messages": []any{
			map[string]any{"role": "user", "content": Prose},
			map[string]any{
				"role": "assistant",
				"content": []any{
					map[string]any{
						"type":      "thinking",
						"thinking":  "Der Nutzer meint den Zielrechner, ich pinge 10.13.7.42.",
						"signature": ThinkingSignature,
					},
					map[string]any{
						"type":  "tool_use",
						"id":    ToolUseID,
						"name":  "Bash",
						"input": map[string]any{"command": "ping -c1 10.13.7.42 && ssh nuc uptime"},
					},
				},
			},
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": ToolUseID,
						"content":     "PING 10.13.7.42: 64 bytes from athene.lan (10.13.7.42)",
					},
					map[string]any{"type": "text", "text": Benign},
				},
			},
		},
	}
	if session != "" {
		req["metadata"] = map[string]any{"user_id": UserIDFor(session)}
	}
	return req
}
