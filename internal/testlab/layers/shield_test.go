package layers

import (
	"strconv"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// Exclude judges by the conversation's mapping table, not by the shape of a
// value. A term whose value lies in the range a kind draws its pseudonyms
// from, an address out of the carrier-grade NAT range or a hardware address
// with the locally administered prefix, is therefore replaced like any
// other, and the table never hands such a value out as the pseudonym of
// something else. The shape test of the generator still exists for its own
// output and is not the exclude any more.
func TestLayers_ATermInThePseudonymRangeIsReplaced(t *testing.T) {
	g := lab.Gen()
	addr := lab.V4(100, 100, 20, 5)
	mac := lab.MAC(0x02, 0x42, 0xac, 0x11, 0x00, 0x02)
	if !g.IsPseudonym(addr) || !g.IsPseudonym(mac) {
		t.Fatalf("the probes do not have the shape of a pseudonym; the ranges have moved")
	}

	terms := lab.Terms(t,
		detect.Term{Value: addr, Kind: detect.KindIPv4},
		detect.Term{Value: mac, Kind: detect.KindMAC},
	)
	text := "ssh " + addr + " hw " + mac
	tab := lab.Table()
	c := detect.NewComposite(tab.Knows, terms)
	got := c.Scan(text)
	if len(got) != 2 {
		t.Fatalf("composite = %s, want both term hits", where(got))
	}
	out := lab.Forward(text, c, tab)
	if strings.Contains(out, addr) || strings.Contains(out, mac) {
		t.Fatalf("a term in the pseudonym range leaves in the clear: %q", out)
	}
	if back := lab.Back(out, tab); back != text {
		t.Fatalf("round trip returned %q, want %q", back, text)
	}
	// A second pass over the output changes nothing: the table knows its
	// own pseudonyms.
	if again := lab.Forward(out, c, tab); again != out {
		t.Fatalf("second pass changed the text: %q -> %q", out, again)
	}
}

// The table refuses to hand out a pseudonym that equals a value it holds as
// an original, or a literal the plugin's term list names, so the same token
// never stands in a text with two meanings. The collision counter moves
// past such a value like past a taken pseudonym.
func TestLayers_ATermIsNeverHandedOutAsAPseudonym(t *testing.T) {
	tab := lab.Table()
	addr := lab.V4(100, 100, 20, 6)
	tab.SetAvoid(func(p string) bool { return p == addr })
	// A generator that returns the avoided value first.
	fake := &fixedGen{first: addr}
	tab2 := mappingTableWith(fake)
	tab2.SetAvoid(func(p string) bool { return p == addr })
	if got := tab2.Lookup(detect.KindIPv4, lab.V4(10, 0, 0, 1)); got == addr {
		t.Fatalf("the avoided value %q was handed out as a pseudonym", addr)
	}
	own := tab2.Lookup(detect.KindIPv4, addr)
	if own == addr {
		t.Fatalf("a value was mapped onto itself")
	}
	_ = tab
}

// An excluded hit keeps its rank and shields its span against the later
// layers. That is what keeps a second forward pass a no-op. With the table
// as the exclude only a pseudonym the table produced shields anything; a
// real value that merely looks like one, the node address in the name of a
// customer directory, shields nothing, and the directory is replaced.
func TestLayers_AnExcludedHitShieldsTheSegmentAroundIt(t *testing.T) {
	g := lab.Gen()
	addr := lab.V4(100, 100, 20, 7)
	customer := dir(12)
	segment := customer + "-" + addr
	text := abs("mnt", segment, "data")

	patterns := lab.Patterns(t, detect.PatternsConfig{IPv4: true})
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})
	tab := lab.Table()

	// The real address inside the segment is not a pseudonym of the table,
	// so it shields nothing: the segment that contains it is promoted and
	// replaced whole.
	c := detect.NewComposite(tab.Knows, patterns, paths)
	got := c.Scan(text)
	if len(got) != 1 || got[0].Value != segment {
		t.Fatalf("composite = %q, want the whole segment", spans(got))
	}
	out := lab.Forward(text, c, tab)
	if strings.Contains(out, customer) || strings.Contains(out, addr) {
		t.Fatalf("a part of the segment leaves in the clear: %q", out)
	}
	if back := lab.Back(out, tab); back != text {
		t.Fatalf("round trip returned %q, want %q", back, text)
	}

	// A pseudonym of the table inside a segment does shield it: the
	// segment around the plugin's own output is not replaced again.
	p := tab.Lookup(detect.KindIPv4, lab.V4(10, 9, 8, 7))
	if !g.IsPseudonym(p) {
		t.Fatalf("the generator's output %q is not a pseudonym shape", p)
	}
	shielded := abs("mnt", customer+"-"+p, "data")
	if got := c.Scan(shielded); got != nil {
		t.Fatalf("composite = %q over the plugin's own output, want nothing", spans(got))
	}
}

// The person kind has a door of its own besides the table: the plugin
// builds its renderers from the term list, a name on it leaves the pool, and
// the shape test then no longer claims it. So a listed name is never the
// pseudonym of another person.
func TestLayers_ThePersonKindAlreadyHonoursTheTermList(t *testing.T) {
	g := lab.Gen()
	name := g.Pseudonym(detect.KindPerson, node(13), 0)
	if !g.IsPseudonym(name) {
		t.Fatalf("a name out of the pool is not recognised as a pseudonym")
	}

	renderers, dropped := pseudo.RenderersExcludingNames([]string{name})
	if len(dropped) != 1 {
		t.Fatalf("RenderersExcludingNames dropped %d entries, want 1", len(dropped))
	}
	g2 := pseudo.NewGenerator([]byte(lab.Secret), []byte(lab.Salt), renderers)
	if g2.IsPseudonym(name) {
		t.Fatalf("a name taken out of the pool is still claimed by the shape test")
	}

	terms := lab.Terms(t, detect.Term{Value: name, Kind: detect.KindPerson})
	text := "call " + name + " back"
	got := detect.NewComposite(g2.IsPseudonym, terms).Scan(text)
	if len(got) != 1 || got[0].Kind != detect.KindPerson {
		t.Fatalf("composite reported %d hits, want the term hit", len(got))
	}
	if out := roundTrip(t, text, detect.NewComposite(g2.IsPseudonym, terms)); strings.Contains(out, name) {
		t.Fatalf("the listed name leaves in the clear")
	}
}

// An excluded match is dropped by the composite that produced it, so a
// composite used as a layer of another composite no longer shields its
// span. The plugin builds one flat composite; this is a note for whoever
// nests them.
func TestLayers_NestedCompositeLosesTheShield(t *testing.T) {
	g := lab.Gen()
	p := g.Pseudonym(detect.KindHost, node(14), 0)
	text := "key " + p + " end"
	narrow := fakeLayer{"narrow", detect.KindHost, [][2]int{{4, 4 + len(p)}}}
	wide := fakeLayer{"wide", detect.KindSecret, [][2]int{{0, len(text)}}}

	if got := detect.NewComposite(g.IsPseudonym, narrow, wide).Scan(text); got != nil {
		t.Fatalf("flat composite reported %d hits, want the wide match shielded", len(got))
	}
	nested := detect.NewComposite(g.IsPseudonym, detect.NewComposite(g.IsPseudonym, narrow), wide)
	got := nested.Scan(text)
	if len(got) != 1 || got[0].Source != "wide" {
		t.Fatalf("nested composite = %q from %q", spans(got), sources(got))
	}
	t.Logf("nested in a second composite the excluded hit no longer shields its span")
}

// fixedGen returns first for attempt 0 and a distinct token afterwards, so a
// test can force the table onto an avoided value.
type fixedGen struct{ first string }

func (f *fixedGen) Pseudonym(kind detect.Kind, value string, attempt int) string {
	if attempt == 0 {
		return f.first
	}
	return string(kind) + ":" + value + ":" + strconv.Itoa(attempt)
}

func mappingTableWith(g mapping.Generator) *mapping.Table { return mapping.NewTable(g) }
