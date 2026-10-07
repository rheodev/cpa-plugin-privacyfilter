package mapping_test

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
)

// fakeGen renders kind:value:attempt so collisions can be forced: every
// value listed in collide maps to the same pseudonym at attempt 0.
type fakeGen struct {
	collide map[string]bool
}

func (f fakeGen) Pseudonym(kind detect.Kind, value string, attempt int) string {
	if f.collide[value] && attempt == 0 {
		return "h-collide"
	}
	return fmt.Sprintf("%s:%s:%d", kind, value, attempt)
}

func TestTable_LookupStable(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	p1 := tb.Lookup(detect.KindHost, "athene.lan")
	p2 := tb.Lookup(detect.KindHost, "athene.lan")
	if p1 == "" || p1 != p2 {
		t.Fatalf("Lookup not stable: %q %q", p1, p2)
	}
	if tb.Len() != 1 {
		t.Fatalf("Len = %d, want 1", tb.Len())
	}
	e, ok := tb.Original(p1)
	if !ok || e.Original != "athene.lan" || e.Kind != detect.KindHost || e.Attempt != 0 {
		t.Fatalf("Original(%q) = %+v, %v", p1, e, ok)
	}
	if _, ok := tb.Original("nope"); ok {
		t.Fatal("Original of unknown pseudonym reported ok")
	}
}

func TestTable_SameValueDifferentKinds(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	a := tb.Lookup(detect.KindHost, "kunde-x")
	b := tb.Lookup(detect.KindPathSegment, "kunde-x")
	if a == b || tb.Len() != 2 {
		t.Fatalf("kinds must be separate entries: %q %q len %d", a, b, tb.Len())
	}
}

func TestTable_CollisionRaisesAttemptForLaterValue(t *testing.T) {
	tb := mapping.NewTable(fakeGen{collide: map[string]bool{"first": true, "second": true}})
	p1 := tb.Lookup(detect.KindHost, "first")
	p2 := tb.Lookup(detect.KindHost, "second")
	if p1 != "h-collide" {
		t.Fatalf("first value must keep attempt 0, got %q", p1)
	}
	if p2 == p1 {
		t.Fatal("collision not resolved")
	}
	e, _ := tb.Original(p2)
	if e.Attempt != 1 || e.Original != "second" {
		t.Fatalf("second entry = %+v, want attempt 1", e)
	}
	if again := tb.Lookup(detect.KindHost, "second"); again != p2 {
		t.Fatalf("resolved pseudonym not stable: %q vs %q", again, p2)
	}
}

func TestTable_EntriesAndPseudonymsOrdered(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	tb.Lookup(detect.KindHost, "bb")
	tb.Lookup(detect.KindSecret, "a")
	tb.Lookup(detect.KindHost, "cccc")
	es := tb.Entries()
	if len(es) != 3 || !sort.SliceIsSorted(es, func(i, j int) bool { return es[i].Pseudonym < es[j].Pseudonym }) {
		t.Fatalf("Entries = %+v, want 3 sorted by Pseudonym", es)
	}
	ps := tb.Pseudonyms()
	for i := 1; i < len(ps); i++ {
		if len(ps[i-1]) < len(ps[i]) || (len(ps[i-1]) == len(ps[i]) && ps[i-1] > ps[i]) {
			t.Fatalf("Pseudonyms = %q, want descending length then lexical", ps)
		}
	}
	if tb.MaxPseudonymLen() != len(ps[0]) {
		t.Fatalf("MaxPseudonymLen = %d, want %d", tb.MaxPseudonymLen(), len(ps[0]))
	}
	if mapping.NewTable(fakeGen{}).MaxPseudonymLen() != 0 {
		t.Fatal("MaxPseudonymLen of empty table must be 0")
	}
}

func TestTable_ConcurrentLookup(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tb.Lookup(detect.KindHost, fmt.Sprintf("h%d", (i*j)%50))
			}
		}(i)
	}
	wg.Wait()
	if tb.Len() != 50 {
		t.Fatalf("Len = %d, want 50 after concurrent lookups", tb.Len())
	}
}

func TestRestorer_RestoreAndEscaped(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	host := tb.Lookup(detect.KindHost, "athene.lan")
	person := tb.Lookup(detect.KindPerson, `Ingrid "Bobby" Müster\`)
	r := mapping.NewRestorer(tb)
	if r == nil {
		t.Fatal("NewRestorer returned nil")
	}
	out, changed := r.Restore("ping "+host+" von "+person, false)
	if !changed || out != `ping athene.lan von Ingrid "Bobby" Müster\` {
		t.Fatalf("Restore = %q, %v", out, changed)
	}
	esc, _ := json.Marshal(`Ingrid "Bobby" Müster\`)
	want := "ping athene.lan von " + strings.Trim(string(esc), `"`)
	out, changed = r.Restore("ping "+host+" von "+person, true)
	if !changed || out != want {
		t.Fatalf("Restore(escaped) = %q, want %q", out, want)
	}
	out, changed = r.Restore("nichts zu tun", false)
	if changed || out != "nichts zu tun" {
		t.Fatalf("Restore on clean text = %q, %v", out, changed)
	}
}

// TestRestorer_TokenBoundary: a pseudonym is restored only where it stands
// on its own, by the structural detectors' rule: letters and digits continue
// a token, the underscore and all punctuation delimit.
func TestRestorer_TokenBoundary(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	tb.Lookup(detect.KindPerson, "Ruth")   // "person:Ruth:0"
	tb.Lookup(detect.KindIPv4, "10.0.0.1") // "ipv4:10.0.0.1:0"
	r := tb.Restorer()
	if r != tb.Restorer() {
		t.Fatal("Table.Restorer must return the cached instance")
	}
	cases := map[string]string{
		"person:Ruth:0 kam":             "Ruth kam",
		"Xperson:Ruth:0":                "Xperson:Ruth:0",
		"person:Ruth:0x":                "person:Ruth:0x",
		"person:Ruth:01":                "person:Ruth:01",
		"scan_ipv4:10.0.0.1:0.log":      "scan_10.0.0.1.log",
		"_ipv4:10.0.0.1:0_":             "_10.0.0.1_",
		"(ipv4:10.0.0.1:0)":             "(10.0.0.1)",
		"\"person:Ruth:0\"":             "\"Ruth\"",
		"ipv4:10.0.0.1:0/person:Ruth:0": "10.0.0.1/Ruth",
		// A percent-escape in front delimits although it ends in a hex
		// digit; a digit without the percent sign binds, and so does an
		// escape that is none, "%2G".
		"%20person:Ruth:0":      "%20Ruth",
		"a%2Fperson:Ruth:0%2Fb": "a%2FRuth%2Fb",
		"20person:Ruth:0":       "20person:Ruth:0",
		"%2Gperson:Ruth:0":      "%2Gperson:Ruth:0",
	}
	for in, want := range cases {
		if got, _ := r.Restore(in, false); got != want {
			t.Errorf("Restore(%q) = %q, want %q", in, got, want)
		}
	}
}

// A hex-token pseudonym written in upper case restores to the same
// original and counts under the same pseudonym; a person pseudonym does
// not, because its case variants are distinct rows.
func TestRestorer_UpperCaseTokens(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	host := tb.Lookup(detect.KindHost, "nuc")
	mac := tb.Lookup(detect.KindMAC, "a4:5e:60:c1:2b:3d")
	person := tb.Lookup(detect.KindPerson, "Ruth")
	r := tb.Restorer()
	cases := map[string]string{
		"see " + strings.ToUpper(host) + " and " + host: "see nuc and nuc",
		"MAC " + strings.ToUpper(mac):                   "MAC a4:5e:60:c1:2b:3d",
		strings.ToUpper(person) + " and " + person:      strings.ToUpper(person) + " and Ruth",
	}
	for in, want := range cases {
		if got, _ := r.Restore(in, false); got != want {
			t.Errorf("Restore(%q) = %q, want %q", in, got, want)
		}
	}
	if hits := tb.RestoredHits(); hits[host] != 2 || hits[mac] != 1 || hits[person] != 1 {
		t.Fatalf("hits = %v, want host 2, mac 1, person 1", hits)
	}
	// Holdback sees the upper-case spelling too.
	if n := r.Holdback("x " + strings.ToUpper(host[:len(host)-2])); n != len(host)-2 {
		t.Fatalf("Holdback of an upper-case prefix = %d, want %d", n, len(host)-2)
	}
}

// TestRestorer_DomainWithoutReservedSuffix: a model that recognises
// ".invalid" as a marker drops it and writes the bare token; the bare
// spelling restores, in upper case too, with a glued suffix, and still
// only at token boundaries. The full spelling keeps winning where present.
func TestRestorer_DomainWithoutReservedSuffix(t *testing.T) {
	addr := "sophie" + "@" + "example.org" // built at run time: a literal address would be pseudonymized in transit
	tb := mapping.NewTable(genFunc(func(_ detect.Kind, value string, _ int) string {
		return map[string]string{
			"example.de": "d-aaaaaaaaaaaa.invalid",
			addr:         "u-bbbbbbbbbbbb@d-cccccccccccc.invalid",
			"seg":        "d-dddddddddddd",
			"nuc":        "h-eeeeeeeeeeee",
		}[value]
	}))
	dom := tb.Lookup(detect.KindDomain, "example.de")
	mail := tb.Lookup(detect.KindEmail, addr)
	seg := tb.Lookup(detect.KindPathSegment, "seg")
	host := tb.Lookup(detect.KindHost, "nuc")
	bare := strings.TrimSuffix(dom, ".invalid")
	bareMail := strings.TrimSuffix(mail, ".invalid")
	r := tb.Restorer()
	cases := map[string]string{
		"zone " + dom:                       "zone example.de",
		"zone " + bare:                      "zone example.de",
		"zone " + strings.ToUpper(bare):     "zone example.de",
		"copy " + bare + ".bak":             "copy example.de.bak",
		"mail " + bareMail + " and " + mail: "mail " + addr + " and " + addr,
		"not " + bare + "x":                 "not " + bare + "x",
		"dir " + seg + " host " + host:      "dir seg host nuc", // other d- and h- rows untouched
	}
	for in, want := range cases {
		if got, _ := r.Restore(in, false); got != want {
			t.Errorf("Restore(%q) = %q, want %q", in, got, want)
		}
	}
	// On the stream the bare token may still grow into the full one, so it
	// is held back at the edge of a chunk until the next byte decides; the
	// full spelling is complete, but a letter behind it would glue it to a
	// word, so it waits for that byte as well.
	if n := r.Holdback("zone " + bare); n != len(bare) {
		t.Errorf("Holdback of a bare domain at the chunk edge = %d, want %d", n, len(bare))
	}
	if n := r.Holdback("zone " + bare + " "); n != 0 {
		t.Errorf("Holdback after a delimiter = %d, want 0", n)
	}
	if n := r.Holdback("zone " + dom); n != len(dom) {
		t.Errorf("Holdback of the full spelling = %d, want %d", n, len(dom))
	}
	if n := r.Holdback("zone " + dom + "."); n != 0 {
		t.Errorf("Holdback of the full spelling before a delimiter = %d, want 0", n)
	}
	if hits := tb.RestoredHits(); hits[dom] != 4 || hits[mail] != 2 {
		t.Fatalf("hits = %v, want domain 4, email 2", hits)
	}
}

// TestRestorer_UnknownShapePassesThrough: a token that has the shape of a
// pseudonym but is in no table, such as a file name the model invented in
// the pattern of the ones it saw, reaches the client unchanged. The return
// path restores, it never detects; this is the contract that keeps a new
// file from being created under a name of the plugin's own making.
func TestRestorer_UnknownShapePassesThrough(t *testing.T) {
	tb := mapping.NewTable(genFunc(func(_ detect.Kind, value string, _ int) string {
		return map[string]string{"notes.md": "f-aaaaaaaaaaaa.md", "kunde-x": "d-bbbbbbbbbbbb"}[value]
	}))
	known := tb.Lookup(detect.KindFileName, "notes.md")
	seg := tb.Lookup(detect.KindPathSegment, "kunde-x")
	r := tb.Restorer()
	invented := "f-" + strings.Repeat("c", 12) + ".md"
	text := "write " + seg + "/" + invented + " next to " + seg + "/" + known
	want := "write kunde-x/" + invented + " next to kunde-x/notes.md"
	if got, _ := r.Restore(text, false); got != want {
		t.Fatalf("Restore = %q, want %q", got, want)
	}
	if n := r.Holdback(text + " "); n != 0 {
		t.Fatalf("Holdback after a delimiter = %d, want 0", n)
	}
	if hits := tb.RestoredHits(); hits[known] != 1 || hits[seg] != 2 || len(hits) != 2 {
		t.Fatalf("hits = %v, want file 1, segment 2, nothing else", hits)
	}
}

// TestStore_SetTTL: the new lifetime applies to a table that is already
// held, measured from its last use; a non-positive value is ignored.
func TestStore_SetTTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	s := mapping.NewStore(mapping.StoreConfig{TTL: time.Minute, Now: clock})
	s.Put("a", mapping.NewTable(fakeGen{}))
	s.SetTTL(0)
	s.SetTTL(-time.Second)
	now = now.Add(90 * time.Second)
	if _, err := s.Get("a"); err != mapping.ErrTableNotFound {
		t.Fatal("table must expire under the unchanged one-minute TTL")
	}
	s.Put("b", mapping.NewTable(fakeGen{}))
	s.SetTTL(time.Hour)
	now = now.Add(30 * time.Minute)
	if _, err := s.Get("b"); err != nil {
		t.Fatalf("table must survive under the longer TTL: %v", err)
	}
	now = now.Add(2 * time.Minute)
	s.SetTTL(time.Minute)
	if _, err := s.Get("b"); err != mapping.ErrTableNotFound {
		t.Fatal("a shorter TTL must apply to the held table from its last use")
	}
}

// TestTable_SessionIsTheStoreKey: a table knows the key the store filed it
// under, so a later pass over the same table can derive its generator from
// it; a table built outside a store has none until it is bound.
func TestTable_SessionIsTheStoreKey(t *testing.T) {
	s := mapping.NewStore(mapping.StoreConfig{})
	if got := s.Open("caller\x00conv-1", fakeGen{}).Session(); got != "caller\x00conv-1" {
		t.Fatalf("Session() = %q, want the key Open was given", got)
	}
	loose := mapping.NewTable(fakeGen{})
	if loose.Session() != "" {
		t.Fatalf("a table outside a store reports session %q", loose.Session())
	}
	s.Bind("req-1", loose)
	if loose.Session() != "req-1" {
		t.Fatalf("Session() = %q after Bind, want the request it was filed under", loose.Session())
	}
}

// TestTable_PseudonymSpans: the spans at which the table's pseudonyms stand
// on their own in a text, by the rule of Restore: one followed by the "#"
// of a collision suffix or by a delimiter is found, one glued into a longer
// word is not, and an empty table finds nothing.
func TestTable_PseudonymSpans(t *testing.T) {
	if got := mapping.NewTable(fakeGen{}).PseudonymSpans("nothing here"); got != nil {
		t.Fatalf("an empty table found spans: %v", got)
	}
	tb := mapping.NewTable(fakeGen{})
	a := tb.Lookup(detect.KindHost, "athene.lan")
	b := tb.Lookup(detect.KindIPv4, "10.1.2.3")
	text := "ping " + a + "#1024, then " + b + " and " + a + "x end"
	ia, ib := strings.Index(text, a), strings.Index(text, b)
	want := [][2]int{{ia, ia + len(a)}, {ib, ib + len(b)}}
	got := tb.PseudonymSpans(text)
	if len(got) != len(want) {
		t.Fatalf("PseudonymSpans = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("PseudonymSpans = %v, want %v", got, want)
		}
	}
}

func TestRestorer_Holdback(t *testing.T) {
	tb := mapping.NewTable(fakeGen{})
	p := tb.Lookup(detect.KindHost, "athene.lan") // "host:athene.lan:0"
	if p == "" {
		t.Fatal("Lookup returned an empty pseudonym")
	}
	r := mapping.NewRestorer(tb)
	if r == nil {
		t.Fatal("NewRestorer returned nil")
	}
	cases := map[string]int{
		"":                       0,
		"text ohne Rest":         0,
		"foo " + p[:1]:           1,
		"foo " + p[:5]:           5,
		"foo " + p[:len(p)-1]:    len(p) - 1,
		"foo " + p:               len(p), // complete, but the next byte may glue it to a word
		"foo " + p + " ":         0,      // the space decided it
		"foo " + p + " " + p[:3]: 3,
		"foo " + p + p[:3]:       len(p) + 3, // may become two pseudonyms back to back, which restore as a run
		"foo " + p + "hx":        0,          // continues the word in front and begins no pseudonym
		"Müller " + p[:2]:        2,
		"x hos":                  3,
		"xhos":                   0, // continues the word in front: never restored, so not held
		"x ho" + "ü":             0, // the ü is not a prefix; nothing held back mid-rune
	}
	for text, want := range cases {
		if got := r.Holdback(text); got != want {
			t.Errorf("Holdback(%q) = %d, want %d", text, got, want)
		}
	}
	if mapping.NewRestorer(mapping.NewTable(fakeGen{})).Holdback("anything") != 0 {
		t.Fatal("empty table must never hold back")
	}
}

// genFunc adapts a function to mapping.Generator.
type genFunc func(kind detect.Kind, value string, attempt int) string

func (f genFunc) Pseudonym(kind detect.Kind, value string, attempt int) string {
	return f(kind, value, attempt)
}

// TestRestorer_HoldbackKeepsCompletePseudonym is the regression test for
// the live fault: a pseudonym whose last byte begins another pseudonym of
// the table was cut in two by the holdback, and neither piece was ever
// restored. The complete pseudonym must be restored, and a pseudonym that
// is a prefix of a longer one must wait until the text decides.
func TestRestorer_HoldbackKeepsCompletePseudonym(t *testing.T) {
	tb := mapping.NewTable(genFunc(func(_ detect.Kind, value string, _ int) string {
		return map[string]string{
			"a": "d-aaaaaaaaaaad", // ends in the byte every "d-" pseudonym begins with
			"b": "d-bbbbbbbbbbbb",
			"p": "P",
			"q": "PQ",
		}[value]
	}))
	a := tb.Lookup(detect.KindPathSegment, "a")
	tb.Lookup(detect.KindPathSegment, "b")
	tb.Lookup(detect.KindPerson, "p")
	tb.Lookup(detect.KindPerson, "q")
	r := tb.Restorer()

	cases := map[string]int{
		"/home/" + a:          14, // complete, and "d-a…" cannot grow into "d-b…", but a letter may follow
		"/home/" + a + "/src": 0,
		"/home/" + a[:13]:     13, // one byte short: still growing
		"/home/d":             1,
		"say P":               1, // "P" is complete but may become "PQ"
		"say PQ":              2, // complete, and the next byte decides whether it stands alone
		"say P ":              0, // the space decided it
		"say PX":              0, // never a pseudonym
	}
	for text, want := range cases {
		if got := r.Holdback(text); got != want {
			t.Errorf("Holdback(%q) = %d, want %d", text, got, want)
		}
	}
	// Delivered through a Tail, fragment by fragment, the text restores
	// exactly as the whole text would, wherever it is cut.
	for _, text := range []string{"/home/" + a + "/src", "say P ", "say PQ", "/home/" + a + "x", "say PQx", "x%20" + a + "%20" + a, "%20" + a} {
		whole, _ := r.Restore(text, false)
		for cut := 1; cut < len(text); cut++ {
			tail := mapping.NewTail(r)
			head, _ := tail.Push(text[:cut], false)
			mid, _ := tail.Push(text[cut:], false)
			rest, _ := tail.Flush(false)
			if got := head + mid + rest; got != whole {
				t.Errorf("Tail over %q cut at %d = %q, whole text restores to %q", text, cut, got, whole)
			}
		}
	}
}

func TestStore_PutGetDelete(t *testing.T) {
	s := mapping.NewStore(mapping.StoreConfig{})
	if s == nil {
		t.Fatal("NewStore returned nil")
	}
	if _, err := s.Get("req-1"); err != mapping.ErrTableNotFound {
		t.Fatalf("Get on empty store = %v, want ErrTableNotFound", err)
	}
	tb := mapping.NewTable(fakeGen{})
	s.Put("req-1", tb)
	got, err := s.Get("req-1")
	if err != nil || got != tb {
		t.Fatalf("Get = %v, %v", got, err)
	}
	s.Delete("req-1")
	s.Delete("req-1") // no-op
	if _, err := s.Get("req-1"); err != mapping.ErrTableNotFound {
		t.Fatalf("Get after Delete = %v", err)
	}
}

func TestStore_TTL(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := mapping.NewStore(mapping.StoreConfig{TTL: time.Minute, Now: func() time.Time { return now }})
	s.Put("a", mapping.NewTable(fakeGen{}))
	now = now.Add(59 * time.Second)
	if n := s.Sweep(); n != 0 || s.Len() != 1 {
		t.Fatalf("Sweep before TTL removed %d, Len = %d", n, s.Len())
	}
	now = now.Add(2 * time.Second)
	if _, err := s.Get("a"); err != mapping.ErrTableNotFound {
		t.Fatalf("Get after TTL = %v, want ErrTableNotFound", err)
	}

	// The lifetime runs from the last use, not from Put: a conversation
	// that keeps reading its table keeps it.
	s.Put("b", mapping.NewTable(fakeGen{}))
	for i := 0; i < 3; i++ {
		now = now.Add(59 * time.Second)
		if _, err := s.Get("b"); err != nil {
			t.Fatalf("Get %d after a use inside the TTL = %v", i, err)
		}
	}
	now = now.Add(61 * time.Second)
	if n := s.Sweep(); n != 1 {
		t.Fatalf("Sweep = %d, want 1", n)
	}
	if s.Len() != 0 {
		t.Fatalf("Len after Sweep = %d", s.Len())
	}
}

func TestStore_MaxTablesEvictsOldest(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := mapping.NewStore(mapping.StoreConfig{MaxTables: 2, Now: func() time.Time { return now }})
	s.Put("a", mapping.NewTable(fakeGen{}))
	now = now.Add(time.Second)
	s.Put("b", mapping.NewTable(fakeGen{}))
	now = now.Add(time.Second)
	s.Put("c", mapping.NewTable(fakeGen{}))
	if s.Len() != 2 {
		t.Fatalf("Len = %d, want 2", s.Len())
	}
	if _, err := s.Get("a"); err != mapping.ErrTableNotFound {
		t.Fatal("oldest table must be evicted")
	}
	if _, err := s.Get("c"); err != nil {
		t.Fatal("newest table must survive")
	}
}
