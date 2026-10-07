package pseudo_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

func newGen(t *testing.T, session string) *pseudo.Generator {
	t.Helper()
	salt := pseudo.DeriveSalt(fixtures.Secret, session)
	if len(salt) != pseudo.DigestLen {
		t.Fatalf("DeriveSalt returned %d bytes, want %d", len(salt), pseudo.DigestLen)
	}
	g := pseudo.NewGenerator(fixtures.Secret, salt, nil)
	if g == nil {
		t.Fatal("NewGenerator returned nil")
	}
	return g
}

// allKinds lists every kind with a sample value in the format the renderer
// carries over.
var allKinds = []fixtures.Term{
	{Value: "10.13.7.42", Kind: detect.KindIPv4},
	{Value: "fd12:3456:789a::1", Kind: detect.KindIPv6},
	{Value: "10.13.0.0/16", Kind: detect.KindCIDR},
	{Value: "10.13.*.*", Kind: detect.KindCIDR},
	{Value: "a4:5e:60:c1:2b:3d", Kind: detect.KindMAC},
	{Value: "ingrid.muster@beispiel-gmbh.de", Kind: detect.KindEmail},
	{Value: "athene.lan", Kind: detect.KindHost},
	{Value: "beispiel-gmbh.de", Kind: detect.KindDomain},
	{Value: "kunde-x", Kind: detect.KindPathSegment},
	{Value: "main.go", Kind: detect.KindFileName},
	{Value: "Ingrid Muster", Kind: detect.KindPerson},
	{Value: "DE89370400440532013000", Kind: detect.KindIBAN},
	{Value: fixtures.FakeToken(), Kind: detect.KindSecret},
	{Value: "https://athene.lan/x", Kind: detect.KindURL},
	{Value: "3f2a9c1e-7b4d-4e8f-9a0b-1c2d3e4f5a6b", Kind: detect.KindUUID},
	{Value: "9d4091ce1f9d37bd8b2d4e6f1a3c5e7f", Kind: detect.KindHexID},
	{Value: "0x5000c500a1b2c3d4", Kind: detect.KindHexID},
	{Value: "SHA256:Yk3mQ9ZpLx4vB2nR8tW1sC6dF0hJ5gK7aE9iU3oP2qM", Kind: detect.KindFingerprint},
	{Value: "C02XK1ABJG5H", Kind: detect.KindSerial},
}

func TestPseudonym_Deterministic(t *testing.T) {
	a := newGen(t, fixtures.SessionA)
	b := newGen(t, fixtures.SessionA)
	for _, k := range allKinds {
		p1 := a.Pseudonym(k.Kind, k.Value, 0)
		p2 := b.Pseudonym(k.Kind, k.Value, 0)
		if p1 == "" {
			t.Fatalf("%s %q: empty pseudonym", k.Kind, k.Value)
		}
		if p1 != p2 {
			t.Fatalf("%s %q: %q != %q across generators with same secret and salt", k.Kind, k.Value, p1, p2)
		}
		if p1 == k.Value {
			t.Fatalf("%s %q: pseudonym equals original", k.Kind, k.Value)
		}
	}
}

func TestPseudonym_DiffersAcrossSessionsAndKinds(t *testing.T) {
	a := newGen(t, fixtures.SessionA)
	b := newGen(t, fixtures.SessionB)
	if a.Pseudonym(detect.KindHost, "athene.lan", 0) == b.Pseudonym(detect.KindHost, "athene.lan", 0) {
		t.Fatal("same pseudonym in two conversations")
	}
	if a.Pseudonym(detect.KindHost, "kunde-x", 0) == a.Pseudonym(detect.KindPathSegment, "kunde-x", 0) {
		t.Fatal("kind is not part of the HMAC input")
	}
	if a.Pseudonym(detect.KindHost, "athene.lan", 0) == a.Pseudonym(detect.KindHost, "athene.lan", 1) {
		t.Fatal("attempt is not part of the HMAC input")
	}
}

func TestPseudonym_ShapesAreASCIIAndSelfRecognized(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	for _, k := range allKinds {
		p := g.Pseudonym(k.Kind, k.Value, 0)
		for _, r := range p {
			if r > unicode.MaxASCII || r == '"' || r == '\\' || r < 0x20 {
				t.Fatalf("%s: pseudonym %q contains a non-ASCII or JSON-escaped character", k.Kind, p)
			}
		}
		if !g.IsPseudonym(p) {
			t.Fatalf("%s: IsPseudonym(%q) = false for own output", k.Kind, p)
		}
		if len(p) > g.MaxLen() {
			t.Fatalf("%s: len(%q) = %d > MaxLen %d", k.Kind, p, len(p), g.MaxLen())
		}
	}
	for _, v := range fixtures.Values(fixtures.All()) {
		if g.IsPseudonym(v) {
			t.Fatalf("IsPseudonym(%q) = true for a real value", v)
		}
	}
	for _, w := range []string{"", "d-", "h-zzzzzzzz", "PF_", "100.64.0", "plan", "Markus", "p14", "nuc.local"} {
		if g.IsPseudonym(w) {
			t.Fatalf("IsPseudonym(%q) = true for junk", w)
		}
	}
}

func TestPseudonym_IPv4InCGNAT(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	for i := 0; i < 200; i++ {
		v := fmt.Sprintf("10.13.%d.%d", i%256, (i*7)%256)
		p := g.Pseudonym(detect.KindIPv4, v, 0)
		addr, err := netip.ParseAddr(p)
		if err != nil || !addr.Is4() {
			t.Fatalf("Pseudonym(ipv4 %q) = %q, not an IPv4 address", v, p)
		}
		if !cgnat.Contains(addr) {
			t.Fatalf("Pseudonym(ipv4 %q) = %q outside 100.64.0.0/10", v, p)
		}
	}
}

func TestPseudonym_IPv6InULA(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	p := g.Pseudonym(detect.KindIPv6, "fd12:3456:789a::1", 0)
	addr, err := netip.ParseAddr(p)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		t.Fatalf("Pseudonym(ipv6) = %q, not an IPv6 address", p)
	}
	if !netip.MustParsePrefix("fd00::/8").Contains(addr) {
		t.Fatalf("Pseudonym(ipv6) = %q outside fd00::/8", p)
	}
	if p != addr.String() {
		t.Fatalf("Pseudonym(ipv6) = %q, want the canonical compressed form %q", p, addr.String())
	}
}

func TestPseudonym_CIDRKeepsPrefixAndWildcards(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	p := g.Pseudonym(detect.KindCIDR, "10.13.0.0/16", 0)
	pfx, err := netip.ParsePrefix(p)
	if err != nil || pfx.Bits() != 16 {
		t.Fatalf("Pseudonym(cidr) = %q, want an IPv4 prefix with /16", p)
	}
	if !netip.MustParsePrefix("100.64.0.0/10").Contains(pfx.Addr()) {
		t.Fatalf("Pseudonym(cidr) = %q outside CGNAT", p)
	}
	if got := g.Pseudonym(detect.KindCIDR, "10.13.0.0/255.255.0.0", 0); !strings.HasSuffix(got, "/255.255.0.0") {
		t.Fatalf("Pseudonym(cidr with mask) = %q, want the mask kept", got)
	}
	w := g.Pseudonym(detect.KindCIDR, "10.13.*.*", 0)
	parts := strings.Split(w, ".")
	if len(parts) != 4 || parts[2] != "*" || parts[3] != "*" || parts[0] != "100" {
		t.Fatalf("Pseudonym(wildcard cidr) = %q, want 100.x.*.*", w)
	}
}

func TestPseudonym_MACLocallyAdministered(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	p := g.Pseudonym(detect.KindMAC, "a4:5e:60:c1:2b:3d", 0)
	if len(p) != 17 || !strings.HasPrefix(p, "02:") || strings.Count(p, ":") != 5 {
		t.Fatalf("Pseudonym(mac) = %q, want 02:xx:xx:xx:xx:xx", p)
	}
}

func TestPseudonym_TokensAndSuffixes(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	cases := []struct {
		kind           detect.Kind
		value          string
		prefix, suffix string
		length         int
	}{
		{detect.KindHost, "athene.lan", pseudo.PrefixHost, "", len(pseudo.PrefixHost) + pseudo.HexShort},
		{detect.KindDomain, "beispiel-gmbh.de", pseudo.PrefixDomain, pseudo.SuffixDomain, len(pseudo.PrefixDomain) + pseudo.HexShort + len(pseudo.SuffixDomain)},
		{detect.KindPathSegment, "kunde-x", pseudo.PrefixPathSegment, "", len(pseudo.PrefixPathSegment) + pseudo.HexShort},
		{detect.KindFileName, "main.go", pseudo.PrefixFileName, ".go", len(pseudo.PrefixFileName) + pseudo.HexShort + len(".go")},
		{detect.KindFileName, "Makefile", pseudo.PrefixFileName, "", len(pseudo.PrefixFileName) + pseudo.HexShort},
		{detect.KindFileName, "archive.tar.gz", pseudo.PrefixFileName, ".gz", len(pseudo.PrefixFileName) + pseudo.HexShort + len(".gz")},
		{detect.KindSecret, fixtures.FakeToken(), pseudo.PrefixSecret, "", len(pseudo.PrefixSecret) + pseudo.HexSecret},
		{detect.KindURL, "https://athene.lan/x", pseudo.PrefixSecret, "", len(pseudo.PrefixSecret) + pseudo.HexSecret},
	}
	for _, c := range cases {
		p := g.Pseudonym(c.kind, c.value, 0)
		if !strings.HasPrefix(p, c.prefix) || !strings.HasSuffix(p, c.suffix) || len(p) != c.length {
			t.Errorf("Pseudonym(%s, %q) = %q, want %s<hex>%s of length %d", c.kind, c.value, p, c.prefix, c.suffix, c.length)
		}
		hex := strings.TrimSuffix(strings.TrimPrefix(p, c.prefix), c.suffix)
		if strings.ToLower(hex) != hex || strings.Trim(hex, "0123456789abcdef") != "" {
			t.Errorf("Pseudonym(%s, %q) = %q, hex part %q is not lower-case hex", c.kind, c.value, p, hex)
		}
	}
}

func TestPseudonym_EmailSharesDomainPseudonym(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	dom := g.Pseudonym(detect.KindDomain, "beispiel-gmbh.de", 0)
	mail := g.Pseudonym(detect.KindEmail, "ingrid.muster@beispiel-gmbh.de", 0)
	at := strings.LastIndex(mail, "@")
	if at < 0 || mail[at+1:] != dom {
		t.Fatalf("Pseudonym(email) = %q, want domain part %q", mail, dom)
	}
	if !strings.HasPrefix(mail, pseudo.PrefixUser) || at != len(pseudo.PrefixUser)+pseudo.HexShort {
		t.Fatalf("Pseudonym(email) = %q, want u-<8hex>@...", mail)
	}
	other := g.Pseudonym(detect.KindEmail, "info@beispiel-gmbh.de", 0)
	if other[:at] == mail[:at] || other[at:] != mail[at:] {
		t.Fatalf("two addresses of one domain: %q and %q, want different local parts and the same domain", mail, other)
	}
}

func TestPseudonym_Person(t *testing.T) {
	if len(pseudo.Names) < 64 {
		t.Fatalf("Names has %d entries, want at least 64", len(pseudo.Names))
	}
	seen := map[string]bool{}
	for _, n := range pseudo.Names {
		if seen[n] || strings.Count(n, " ") != 1 {
			t.Fatalf("Names entry %q duplicated or not 'Given Surname'", n)
		}
		seen[n] = true
	}
	g := newGen(t, fixtures.SessionA)
	p := g.Pseudonym(detect.KindPerson, "Ingrid Muster", 0)
	if !seen[p] {
		t.Fatalf("Pseudonym(person) = %q, not from Names", p)
	}
	given := map[string]bool{}
	for n := range seen {
		given[strings.Fields(n)[0]] = true
	}
	single := g.Pseudonym(detect.KindPerson, "markus", 0)
	if strings.Contains(single, " ") || !given[strings.ToUpper(single[:1])+single[1:]] {
		t.Fatalf("Pseudonym(person %q) = %q, want a lone given name in lower case", "markus", single)
	}
	if strings.ToUpper(single[:1])+single[1:] != g.Pseudonym(detect.KindPerson, "Markus", 0) {
		t.Fatalf("case variants must map to the same given name: %q vs %q", single, g.Pseudonym(detect.KindPerson, "Markus", 0))
	}
	upper := g.Pseudonym(detect.KindPerson, "MARKUS", 0)
	if upper != strings.ToUpper(single) {
		t.Fatalf("Pseudonym(person MARKUS) = %q, want all upper case %q", upper, strings.ToUpper(single))
	}
}

func TestPseudonym_IBANValid(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	p := g.Pseudonym(detect.KindIBAN, "DE89370400440532013000", 0)
	if len(p) != 22 || !strings.HasPrefix(p, "DE") || p == "DE89370400440532013000" {
		t.Fatalf("Pseudonym(iban) = %q, want a different German IBAN of length 22", p)
	}
	if !ibanValid(p) {
		t.Fatalf("Pseudonym(iban) = %q has an invalid mod-97 checksum", p)
	}
}

func ibanValid(iban string) bool {
	s := iban[4:] + iban[:4]
	rem := 0
	for _, r := range s {
		var d string
		switch {
		case r >= '0' && r <= '9':
			d = string(r)
		case r >= 'A' && r <= 'Z':
			d = fmt.Sprint(int(r-'A') + 10)
		default:
			return false
		}
		for _, c := range d {
			rem = (rem*10 + int(c-'0')) % 97
		}
	}
	return rem == 1
}

func TestPseudonym_NoCollisionsOverLargeSet(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	const n = 200_000
	seen := make(map[string]string, n)
	for i := 0; i < n; i++ {
		v := fmt.Sprintf("host-%d.example", i)
		p := g.Pseudonym(detect.KindHost, v, 0)
		if prev, dup := seen[p]; dup {
			t.Fatalf("collision: %q and %q -> %q", prev, v, p)
		}
		seen[p] = v
	}
}

func TestDigest_LengthAndInputs(t *testing.T) {
	g := newGen(t, fixtures.SessionA)
	d0 := g.Digest(detect.KindHost, "athene.lan", 0)
	if len(d0) != pseudo.DigestLen {
		t.Fatalf("Digest len = %d, want %d", len(d0), pseudo.DigestLen)
	}
	if bytes.Equal(d0, g.Digest(detect.KindHost, "athene.lan", 1)) {
		t.Fatal("attempt does not change the digest")
	}
}

func TestIdentifySession_Order(t *testing.T) {
	body := mustJSON(t, fixtures.Request(fixtures.SessionB))
	h := http.Header{}
	h.Set(pseudo.SessionHeader, fixtures.SessionA)
	if s := pseudo.IdentifySession(h, body); s.ID != fixtures.SessionA || s.Source != pseudo.SourceHeader {
		t.Fatalf("header case = %+v", s)
	}
	if s := pseudo.IdentifySession(nil, body); s.ID != fixtures.SessionB || s.Source != pseudo.SourceMetadata {
		t.Fatalf("metadata case = %+v", s)
	}
	plain := mustJSON(t, fixtures.Request(""))
	s := pseudo.IdentifySession(nil, plain)
	if s.Source != pseudo.SourceHead || s.ID == "" || s.ID != pseudo.HeadHash(plain) {
		t.Fatalf("fallback case = %+v, want SourceHead with HeadHash", s)
	}
	if s2 := pseudo.IdentifySession(nil, []byte("not json")); s2.ID == "" {
		t.Fatal("non-JSON body must still yield an identifier")
	}
}

func TestIdentifySession_IgnoresMalformedUserID(t *testing.T) {
	req := fixtures.Request("")
	req["metadata"] = map[string]any{"user_id": "user_abc_account_def"}
	body := mustJSON(t, req)
	if s := pseudo.IdentifySession(nil, body); s.Source != pseudo.SourceHead {
		t.Fatalf("user_id without _session_ suffix must fall back, got %+v", s)
	}
}

func TestHeadHash_StableAcrossTurnsAndFormatting(t *testing.T) {
	first := fixtures.Request("")
	h1 := pseudo.HeadHash(mustJSON(t, first))
	if len(h1) != 64 || strings.Trim(h1, "0123456789abcdef") != "" {
		t.Fatalf("HeadHash = %q, want 64 lower-case hex digits", h1)
	}
	// A later turn appends messages and changes the model; the head stays.
	later := fixtures.Request("")
	later["model"] = "claude-opus-5"
	later["messages"] = append(later["messages"].([]any), map[string]any{"role": "assistant", "content": "ok"})
	if h2 := pseudo.HeadHash(mustJSON(t, later)); h2 != h1 {
		t.Fatalf("HeadHash changed across turns: %q vs %q", h1, h2)
	}
	// Different whitespace, same content.
	if h3 := pseudo.HeadHash(mustJSONIndent(t, first)); h3 != h1 {
		t.Fatalf("HeadHash depends on formatting: %q vs %q", h1, h3)
	}
	// A different first user message is a different conversation.
	other := fixtures.Request("")
	other["messages"].([]any)[0] = map[string]any{"role": "user", "content": "etwas anderes"}
	if h4 := pseudo.HeadHash(mustJSON(t, other)); h4 == h1 {
		t.Fatal("HeadHash equal for different first user messages")
	}
}

func TestDeriveSalt_DependsOnSecretAndSession(t *testing.T) {
	a := pseudo.DeriveSalt(fixtures.Secret, fixtures.SessionA)
	if bytes.Equal(a, pseudo.DeriveSalt(fixtures.Secret, fixtures.SessionB)) {
		t.Fatal("salt equal for two sessions")
	}
	if bytes.Equal(a, pseudo.DeriveSalt(bytes.Repeat([]byte("f"), 64), fixtures.SessionA)) {
		t.Fatal("salt equal for two secrets")
	}
	if !bytes.Equal(a, pseudo.DeriveSalt(fixtures.Secret, fixtures.SessionA)) {
		t.Fatal("salt not deterministic")
	}
}

// TestSessionKey_CallerScopeBoundsTheIdentifier: the key of salt and table
// is the identifier alone without a caller scope, so a host without
// inbound authentication derives what it always did, and the scope joined
// to it otherwise, so one identifier under two callers is two keys.
func TestSessionKey_CallerScopeBoundsTheIdentifier(t *testing.T) {
	plain := pseudo.Session{ID: fixtures.SessionA, Source: pseudo.SourceHeader}
	if plain.Key() != fixtures.SessionA {
		t.Fatalf("Key without a caller = %q, want the identifier alone", plain.Key())
	}
	a := pseudo.Session{ID: fixtures.SessionA, Source: pseudo.SourceHeader, Caller: "caller-a"}
	b := pseudo.Session{ID: fixtures.SessionA, Source: pseudo.SourceHeader, Caller: "caller-b"}
	if a.Key() == plain.Key() || a.Key() == b.Key() || b.Key() == plain.Key() {
		t.Fatalf("keys not distinct: %q, %q, %q", plain.Key(), a.Key(), b.Key())
	}
	if a.Key() != (pseudo.Session{ID: fixtures.SessionA, Caller: "caller-a"}).Key() {
		t.Fatal("key not deterministic")
	}
	if bytes.Equal(pseudo.DeriveSalt(fixtures.Secret, a.Key()), pseudo.DeriveSalt(fixtures.Secret, b.Key())) {
		t.Fatal("salt equal for one conversation under two callers")
	}
	if bytes.Equal(pseudo.DeriveSalt(fixtures.Secret, a.Key()), pseudo.DeriveSalt(fixtures.Secret, plain.Key())) {
		t.Fatal("salt equal with and without a caller")
	}
}

// TestCallerScope_ReadsTheHostsMetadata: the scope is the string under the
// host's key, trimmed; anything else is no scope.
func TestCallerScope_ReadsTheHostsMetadata(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]any
		want string
	}{
		{"nil", nil, ""},
		{"empty", map[string]any{}, ""},
		{"string", map[string]any{pseudo.MetadataCallerScope: " 0a1b2c "}, "0a1b2c"},
		{"blank", map[string]any{pseudo.MetadataCallerScope: "   "}, ""},
		{"not a string", map[string]any{pseudo.MetadataCallerScope: 42}, ""},
		{"other keys", map[string]any{"request_path": "/v1/messages"}, ""},
	}
	for _, tc := range cases {
		if got := pseudo.CallerScope(tc.meta); got != tc.want {
			t.Errorf("%s: CallerScope = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestResolveSecretPath(t *testing.T) {
	dir := "/CLIProxyAPI/plugins/linux/amd64"
	if got := pseudo.ResolveSecretPath(dir, ""); got != filepath.Join(dir, pseudo.DefaultSecretFile) {
		t.Fatalf("empty -> %q", got)
	}
	if got := pseudo.ResolveSecretPath(dir, "other.secret"); got != filepath.Join(dir, "other.secret") {
		t.Fatalf("relative -> %q", got)
	}
	if got := pseudo.ResolveSecretPath(dir, "/etc/x.secret"); got != "/etc/x.secret" {
		t.Fatalf("absolute -> %q", got)
	}
}

func TestLoadSecret(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.secret")
	if err := os.WriteFile(good, append([]byte("  "), append(append([]byte(nil), fixtures.Secret...), '\n')...), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := pseudo.LoadSecret(good)
	if err != nil {
		t.Fatalf("LoadSecret: %v", err)
	}
	if !bytes.Equal(got, fixtures.Secret) {
		t.Fatalf("LoadSecret = %q, want the trimmed bytes without decoding", got)
	}
	short := filepath.Join(dir, "short.secret")
	if err := os.WriteFile(short, []byte(strings.Repeat("a", 31)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pseudo.LoadSecret(short); err != pseudo.ErrSecretTooShort {
		t.Fatalf("short secret error = %v, want ErrSecretTooShort", err)
	}
	if _, err := pseudo.LoadSecret(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must return an error")
	}
}
