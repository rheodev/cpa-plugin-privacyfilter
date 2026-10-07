package detect_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
)

func m(start, end int, text string, kind detect.Kind, src string) detect.Match {
	return detect.Match{Start: start, End: end, Value: text[start:end], Kind: kind, Source: src}
}

// assertDisjointSorted is the invariant every Merge and Scan result must
// satisfy: sorted by Start, no overlaps, offsets inside the text, on rune
// boundaries, Value equal to the slice.
func assertDisjointSorted(t *testing.T, text string, ms []detect.Match) {
	t.Helper()
	for i, x := range ms {
		if x.Start < 0 || x.End > len(text) || x.Start >= x.End {
			t.Fatalf("match %d has bad offsets %d:%d for len %d", i, x.Start, x.End, len(text))
		}
		if text[x.Start:x.End] != x.Value {
			t.Fatalf("match %d Value %q != text slice %q", i, x.Value, text[x.Start:x.End])
		}
		if !strings.HasPrefix(text[x.Start:], x.Value) || (x.End < len(text) && !isRuneStart(text[x.End])) || !isRuneStart(text[x.Start]) {
			t.Fatalf("match %d splits a rune", i)
		}
		if i > 0 && ms[i-1].End > x.Start {
			t.Fatalf("matches %d and %d overlap or are unsorted: %+v %+v", i-1, i, ms[i-1], x)
		}
	}
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

func TestMerge_EarlierLayerWins(t *testing.T) {
	text := "host athene.lan 10.13.7.42"
	terms := []detect.Match{m(5, 15, text, detect.KindHost, "terms")}
	patterns := []detect.Match{
		m(12, 15, text, detect.KindSecret, "patterns"), // "lan" overlaps the host
		m(16, 26, text, detect.KindIPv4, "patterns"),
	}
	got := detect.Merge(terms, patterns)
	want := []detect.Match{terms[0], patterns[1]}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Merge = %+v, want %+v", got, want)
	}
	assertDisjointSorted(t, text, got)
}

func TestMerge_LongerWinsInsideLayer(t *testing.T) {
	text := "ingrid.muster@beispiel-gmbh.de"
	layer := []detect.Match{
		m(14, 30, text, detect.KindDomain, "patterns"),
		m(0, 30, text, detect.KindEmail, "patterns"),
	}
	got := detect.Merge(layer)
	if len(got) != 1 || got[0].Kind != detect.KindEmail {
		t.Fatalf("Merge = %+v, want the single e-mail match", got)
	}
}

func TestMerge_TouchingSpansBothSurvive(t *testing.T) {
	text := "10.13.7.42athene.lan"
	got := detect.Merge([]detect.Match{m(10, 20, text, detect.KindHost, "a")}, []detect.Match{m(0, 10, text, detect.KindIPv4, "b")})
	if len(got) != 2 || got[0].Start != 0 || got[1].Start != 10 {
		t.Fatalf("Merge = %+v, want two sorted touching matches", got)
	}
}

func TestMerge_DeterministicAndPure(t *testing.T) {
	text := "a b c d e"
	in := []detect.Match{m(4, 5, text, detect.KindHost, "x"), m(0, 1, text, detect.KindHost, "x"), m(2, 3, text, detect.KindHost, "x")}
	before := append([]detect.Match(nil), in...)
	first := detect.Merge(in)
	second := detect.Merge(in)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Merge not deterministic: %+v vs %+v", first, second)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatal("Merge modified its argument")
	}
	if len(first) != 3 || first[0].Start != 0 || first[2].Start != 4 {
		t.Fatalf("Merge = %+v, want sorted by Start", first)
	}
}

func TestMerge_EmptyAndNil(t *testing.T) {
	if got := detect.Merge(); len(got) != 0 {
		t.Fatalf("Merge() = %+v, want empty", got)
	}
	if got := detect.Merge(nil, []detect.Match{}); len(got) != 0 {
		t.Fatalf("Merge(nil, empty) = %+v, want empty", got)
	}
}

func TestOverlaps(t *testing.T) {
	a := detect.Match{Start: 0, End: 5}
	b := detect.Match{Start: 5, End: 9}
	c := detect.Match{Start: 4, End: 6}
	if a.Overlaps(b) || b.Overlaps(a) {
		t.Fatal("touching spans must not overlap")
	}
	if !a.Overlaps(c) || !c.Overlaps(b) {
		t.Fatal("intersecting spans must overlap")
	}
}

func TestKind_Valid(t *testing.T) {
	for _, k := range []detect.Kind{detect.KindIPv4, detect.KindHost, detect.KindSecret, detect.KindPathSegment} {
		if !k.Valid() {
			t.Fatalf("%q must be valid", k)
		}
	}
	if detect.Kind("").Valid() || detect.Kind("hostname").Valid() {
		t.Fatal("unknown kinds must be invalid")
	}
}

// fakeDetector reports fixed matches by literal search.
type fakeDetector struct {
	name string
	kind detect.Kind
	lits []string
}

func (f fakeDetector) Name() string { return f.name }
func (f fakeDetector) Scan(text string) []detect.Match {
	var out []detect.Match
	for _, l := range f.lits {
		for off := 0; ; {
			i := strings.Index(text[off:], l)
			if i < 0 {
				break
			}
			s := off + i
			out = append(out, detect.Match{Start: s, End: s + len(l), Value: l, Kind: f.kind, Source: f.name})
			off = s + len(l)
		}
	}
	return out
}

func TestComposite_MergesAndExcludes(t *testing.T) {
	text := "athene.lan h-0badcafe 10.13.7.42"
	c := detect.NewComposite(
		func(v string) bool { return strings.HasPrefix(v, "h-") },
		fakeDetector{"terms", detect.KindHost, []string{"athene.lan", "h-0badcafe"}},
		fakeDetector{"patterns", detect.KindIPv4, []string{"10.13.7.42"}},
	)
	got := c.Scan(text)
	assertDisjointSorted(t, text, got)
	if len(got) != 2 {
		t.Fatalf("Scan = %+v, want host and ipv4 only (pseudonym excluded)", got)
	}
	if got[0].Source != "terms" || got[1].Source != "patterns" {
		t.Fatalf("Scan sources = %q %q", got[0].Source, got[1].Source)
	}
}

func TestComposite_NilExclude(t *testing.T) {
	c := detect.NewComposite(nil, fakeDetector{"terms", detect.KindHost, []string{"nuc"}})
	if got := c.Scan("ssh nuc"); len(got) != 1 {
		t.Fatalf("Scan = %+v, want one match with nil Exclude", got)
	}
}

// An excluded match keeps its precedence: a later layer that matches a
// wider span around a pseudonym must not win just because the pseudonym
// itself is dropped from the result. Otherwise a second forward pass over
// its own output would replace "Host-Key <pseudonym>. " as a credential.
func TestComposite_ExcludedShieldsLaterLayers(t *testing.T) {
	text := "Host-Key h-0badcafe. and nuc"
	c := detect.NewComposite(
		func(v string) bool { return strings.HasPrefix(v, "h-") },
		fakeDetector{"patterns", detect.KindHost, []string{"h-0badcafe"}},
		fakeDetector{"secrets", detect.KindSecret, []string{"Host-Key h-0badcafe. ", "nuc"}},
	)
	got := c.Scan(text)
	assertDisjointSorted(t, text, got)
	if len(got) != 1 || got[0].Value != "nuc" {
		t.Fatalf("Scan = %+v, want only nuc (wider secret match shielded by the excluded pseudonym)", got)
	}
	if got := c.Scan("h-0badcafe"); got != nil {
		t.Fatalf("Scan of a lone pseudonym = %+v, want nil", got)
	}
}

func TestTerms_FindsCorpus(t *testing.T) {
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: fixtures.DetectTerms()})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	got := d.Scan(fixtures.Prose)
	assertDisjointSorted(t, fixtures.Prose, got)
	found := map[string]detect.Kind{}
	for _, x := range got {
		found[strings.ToLower(x.Value)] = x.Kind
		if x.Source != d.Name() {
			t.Fatalf("Source %q != Name %q", x.Source, d.Name())
		}
	}
	want := append(fixtures.Literals(), fixtures.SuffixHosts...)
	for _, term := range want {
		if !strings.Contains(strings.ToLower(fixtures.Prose), term.Value) {
			continue
		}
		if k, ok := found[term.Value]; !ok {
			t.Errorf("term %q not found", term.Value)
		} else if k != term.Kind {
			t.Errorf("term %q kind = %q, want %q", term.Value, k, term.Kind)
		}
	}
	// The upper-case MARKUS at the very end must be found as written.
	if last := got[len(got)-1]; last.Value != "MARKUS" || last.End != len(fixtures.Prose) {
		t.Errorf("last match = %+v, want MARKUS at the end of the text", last)
	}
	if got := d.Scan(fixtures.Benign); len(got) != 0 {
		t.Fatalf("Scan(Benign) = %+v, want no hits", got)
	}
}

func TestTerms_WordBoundary(t *testing.T) {
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: []detect.Term{
		{Value: "nuc", Kind: detect.KindHost},
		{Value: "lan", Kind: detect.KindHost},
	}})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	if got := d.Scan("Nucleus läuft, der Plan steht, planlos, LAN-Party"); len(got) != 0 {
		t.Fatalf("Scan = %+v, want no hits inside words (letters are word characters, case matters)", got)
	}
	// The underscore delimits: a host glued to a suffix is still the host.
	if got := d.Scan("cp nuc_old NUC_HOST=1 nuc_backup.tar.gz"); len(got) != 2 || got[0].Value != "nuc" || got[1].Value != "nuc" {
		t.Fatalf("Scan = %+v, want nuc twice next to underscores (NUC_HOST differs in case)", got)
	}
	if got := d.Scan("ssh nuc; ping nuc."); len(got) != 2 {
		t.Fatalf("Scan = %+v, want two whole-word hits", got)
	}
	if got := d.Scan("athene.lan"); len(got) != 1 || got[0].Value != "lan" {
		t.Fatalf("Scan = %+v, want the dot to count as a boundary", got)
	}
	if got := d.Scan("nuc-lan"); len(got) != 2 {
		t.Fatalf("Scan = %+v, want the hyphen to count as a boundary", got)
	}
	// A percent-escape delimits: a term behind the "%20" of an encoded path
	// is found although the hex digit in front of it would bind.
	if got := d.Scan("[x](Kunden%20nuc/x.md) nuc%2Fetc 100%20nuc"); len(got) != 3 {
		t.Fatalf("Scan = %+v, want nuc three times behind percent-escapes", got)
	}
	if got := d.Scan("20nuc x%2Gnuc"); len(got) != 0 {
		t.Fatalf("Scan = %+v, want nothing: a digit without the percent sign and a G behind it are no escape", got)
	}
}

func TestTerms_LongerLiteralWins(t *testing.T) {
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: fixtures.DetectTerms()})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	got := d.Scan("ssh p14.local und markus@wendler.de")
	if len(got) < 1 || got[0].Value != "p14.local" {
		t.Fatalf("Scan = %+v, want p14.local as one match, not p14", got)
	}
	// wendler.de must win over the bare surname wendler.
	var last detect.Match
	for _, x := range got {
		if x.Start > last.Start {
			last = x
		}
	}
	if last.Value != "wendler.de" || last.Kind != detect.KindDomain {
		t.Fatalf("Scan = %+v, want wendler.de as the domain match", got)
	}
}

func TestTerms_IgnoreCaseAndRegex(t *testing.T) {
	d, err := detect.NewTerms(detect.TermsConfig{WordBoundary: true, Terms: []detect.Term{
		{Value: "Ingrid Muster", Kind: detect.KindPerson, IgnoreCase: true},
		{Regex: `helios-[a-z]+-\d+`, Kind: detect.KindHost},
	}})
	if err != nil {
		t.Fatalf("NewTerms: %v", err)
	}
	got := d.Scan("INGRID MUSTER meldet helios-nas-01 und helios-db-12")
	if len(got) != 3 {
		t.Fatalf("Scan = %+v, want person (case-insensitive) and two regex hosts", got)
	}
	if got[0].Kind != detect.KindPerson || got[0].Value != "INGRID MUSTER" || got[0].Start != 0 {
		t.Fatalf("first match = %+v, want the person as written", got[0])
	}
}

func TestTerms_RejectsBadConfig(t *testing.T) {
	bad := []detect.Term{
		{Kind: detect.KindHost},
		{Value: "a", Regex: "a", Kind: detect.KindHost},
		{Value: "a", Kind: detect.Kind("nope")},
		{Regex: "(", Kind: detect.KindHost},
	}
	for i, term := range bad {
		if _, err := detect.NewTerms(detect.TermsConfig{Terms: []detect.Term{term}}); err == nil {
			t.Errorf("bad term %d accepted: %+v", i, term)
		}
	}
}

func TestPatterns_FindsStructured(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true, MAC: true, Email: true, IBAN: true, UUID: true, HexID: true, Fingerprint: true, Serial: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	for _, s := range fixtures.Structured {
		text := "vorher " + s.Value + " nachher"
		got := d.Scan(text)
		assertDisjointSorted(t, text, got)
		if len(got) != 1 {
			t.Errorf("Scan(%q) = %+v, want exactly one match", s.Value, got)
			continue
		}
		if got[0].Value != s.Value || got[0].Kind != s.Kind {
			t.Errorf("Scan(%q) = %+v, want kind %q", s.Value, got[0], s.Kind)
		}
	}
}

func TestPatterns_BenignUnchanged(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, IPv6: true, CIDR: true, MAC: true, Email: true, IBAN: true, UUID: true, HexID: true, Fingerprint: true, Serial: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	if got := d.Scan(fixtures.Benign); len(got) != 0 {
		t.Fatalf("Scan(Benign) = %+v, want nothing", got)
	}
}

func TestPatterns_CIDRNotAlsoIPv4(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IPv4: true, CIDR: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	got := d.Scan("Netz 10.13.0.0/16 fertig")
	if len(got) != 1 || got[0].Kind != detect.KindCIDR || got[0].Value != "10.13.0.0/16" {
		t.Fatalf("Scan = %+v, want one CIDR match covering the prefix", got)
	}
}

func TestPatterns_DisabledCategorySilent(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{Email: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	if got := d.Scan("10.13.7.42 a4:5e:60:c1:2b:3d"); len(got) != 0 {
		t.Fatalf("Scan = %+v, want nothing with only Email enabled", got)
	}
}

func TestPatterns_IBANChecksum(t *testing.T) {
	d, err := detect.NewPatterns(detect.PatternsConfig{IBAN: true})
	if err != nil {
		t.Fatalf("NewPatterns: %v", err)
	}
	if got := d.Scan("DE89370400440532013001"); len(got) != 0 {
		t.Fatalf("Scan = %+v, want no hit for a bad checksum", got)
	}
}

func TestKindFromPackyme(t *testing.T) {
	cases := map[string]detect.Kind{
		detect.PackymeTypeEmail:    detect.KindEmail,
		detect.PackymeTypeIP:       detect.KindIPv4,
		detect.PackymeTypePhone:    detect.KindSecret,
		detect.PackymeTypeIdentity: detect.KindSecret,
		detect.PackymeTypeBankCard: detect.KindSecret,
		detect.PackymeTypeSecret:   detect.KindSecret,
		// The labels of the library before the fork, and a type a later
		// library might add: opaque, never a shaped pseudonym.
		"[邮箱]":       detect.KindSecret,
		"github-pat": detect.KindSecret,
		"":           detect.KindSecret,
	}
	for entityType, want := range cases {
		if got := detect.KindFromPackyme(entityType); got != want {
			t.Errorf("KindFromPackyme(%q) = %q, want %q", entityType, got, want)
		}
	}
}

func TestSecrets_UnavailableWithoutTag(t *testing.T) {
	// This file has no build constraint, so under -tags betterleaks the
	// expectation flips; the tagged test lives in secrets_betterleaks_test.go.
	if testing.Short() {
		t.Skip()
	}
	_, err := detect.NewSecrets(detect.SecretsConfig{})
	if err == nil {
		t.Skip("secret scanner compiled in")
	}
	if err != detect.ErrSecretsUnavailable {
		t.Fatalf("NewSecrets error = %v, want ErrSecretsUnavailable", err)
	}
}

// TestComposite_AddressWithTermIsReplacedWhole: the term list outranks the
// structural patterns, but an e-mail address that contains a term, the
// company domain or a name, must not be split into a clear local part and a
// domain pseudonym. The e-mail match is promoted and wins as a whole; an
// address without a term inside keeps its usual place in the order.
func TestComposite_AddressWithTermIsReplacedWhole(t *testing.T) {
	domain := "muster-gmbh.de"
	addr := "ingrid.muster" + "@" + domain
	text := "mail " + addr + " site " + domain
	c := detect.NewComposite(
		func(v string) bool { return strings.HasPrefix(v, "d-") },
		fakeDetector{"terms", detect.KindDomain, []string{domain}},
		fakeDetector{"patterns", detect.KindEmail, []string{addr}},
	)
	got := c.Scan(text)
	assertDisjointSorted(t, text, got)
	if len(got) != 2 {
		t.Fatalf("Scan = %+v, want the whole address and the lone domain", got)
	}
	if got[0].Kind != detect.KindEmail || got[0].Value != addr {
		t.Fatalf("first match = %+v, want the whole address as email", got[0])
	}
	if got[1].Kind != detect.KindDomain || got[1].Value != domain {
		t.Fatalf("second match = %+v, want the lone domain as domain", got[1])
	}

	// Second pass over the plugin's own output: the domain inside the
	// address is now a pseudonym and excluded; the address around it must
	// not be promoted and replaced again.
	pseudo := "ingrid.muster" + "@" + "d-0badcafe0bad.invalid"
	c2 := detect.NewComposite(
		func(v string) bool { return strings.HasPrefix(v, "d-") },
		fakeDetector{"terms", detect.KindDomain, []string{"d-0badcafe0bad.invalid"}},
		fakeDetector{"patterns", detect.KindEmail, []string{pseudo}},
	)
	// The e-mail match loses to the span of the excluded pseudonym as
	// usual, so nothing is reported.
	if got := c2.Scan("mail " + pseudo); got != nil {
		t.Fatalf("second pass Scan = %+v, want nil", got)
	}
}
