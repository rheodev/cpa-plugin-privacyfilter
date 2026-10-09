package layers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// The path layer with ReplaceUnknown is the net for the directory nobody put
// on the term list. A term that hits inside such a directory must not take
// the span away from the net: the segment that contains the term is
// promoted and replaced whole, so putting the host name on the list never
// makes the protection of a directory worse than leaving it off.
func TestLayers_TermInsideAnUnknownSegmentUncoversTheRest(t *testing.T) {
	host, customer := node(7), dir(8)
	segment := host + "-" + customer
	text := abs("mnt", segment, "data")
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})

	without := roundTrip(t, text, detect.NewComposite(nil, paths))
	if strings.Contains(without, customer) {
		t.Fatalf("without the term layer the directory name is still in the outbound text")
	}

	with := roundTrip(t, text, detect.NewComposite(nil, lab.Host(t, host), paths))
	if strings.Contains(with, customer) {
		t.Fatalf("the term hit uncovers the rest of the segment: the directory name of %d bytes leaves in the clear", len(customer))
	}
}

// And on an address: a short term that falls inside a dotted quad must not
// take the span from the address pattern, or a broken address would leave
// with its remaining octets in the clear. The containing address is
// promoted and replaced whole.
func TestLayers_TermInsideAnAddressBreaksItApart(t *testing.T) {
	project := fmt.Sprintf("%d", 108)
	addr := lab.V4(10, 108, 0, 7)
	tail := fmt.Sprintf(".%d.%d", 0, 7)
	text := "ping " + addr + " from the office"

	patterns := lab.Patterns(t, detect.PatternsConfig{IPv4: true})
	terms := lab.Terms(t, detect.Term{Value: project, Kind: detect.KindPathSegment})

	without := roundTrip(t, text, detect.NewComposite(nil, patterns))
	if strings.Contains(without, addr) {
		t.Fatalf("the address pattern alone leaves the address in the outbound text")
	}

	c := detect.NewComposite(nil, terms, patterns)
	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if len(got) != 1 || got[0].Value != addr {
		t.Fatalf("composite = %q, want the containing address promoted", spans(got))
	}
	if with := roundTrip(t, text, c); strings.Contains(with, tail) {
		t.Fatalf("the term of %d bytes breaks the address of %d bytes apart and its tail leaves in the clear",
			len(project), len(addr))
	}
}

// An address that is a whole path segment: the structural layer runs before
// the path layer and reports it as an address, so it keeps the shape of an
// address for the model instead of becoming a directory token.
func TestLayers_AddressInsideAPathKeepsItsKind(t *testing.T) {
	addr := lab.V4(10, 20, 30, 40)
	text := abs("var", "log", addr, "access.log")
	patterns := lab.Patterns(t, detect.PatternsConfig{IPv4: true})
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})
	c := detect.NewComposite(nil, patterns, paths)

	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if len(got) != 1 || got[0].Kind != detect.KindIPv4 || got[0].Value != addr {
		t.Fatalf("composite = %q from %q, want the address as an address", spans(got), sources(got))
	}
	if out := roundTrip(t, text, c); strings.Contains(out, addr) {
		t.Fatalf("the address survives the outbound path")
	}
}

// A network spans the slash between two path segments. The structural layer
// takes it as one value, so the path layer's segments lose against it and
// the prefix length survives inside the pseudonym.
func TestLayers_NetworkSpanningASlashInsideAPath(t *testing.T) {
	prefixLen := fmt.Sprintf("%d", 16)
	network := lab.V4(10, 20, 0, 0) + sep + prefixLen
	text := abs("etc", network, "notes")
	patterns := lab.Patterns(t, detect.PatternsConfig{CIDR: true})
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})
	c := detect.NewComposite(nil, patterns, paths)

	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if len(got) != 2 || got[0].Kind != detect.KindCIDR || got[0].Value != network {
		t.Fatalf("composite = %q from %q", spans(got), sources(got))
	}
	out := roundTrip(t, text, c)
	if strings.Contains(out, network) {
		t.Fatalf("the network survives the outbound path")
	}
	if want := sep + prefixLen; !strings.Contains(out, want) {
		t.Fatalf("the prefix length is gone from the outbound text")
	}
}

// All layers over one text: nothing of the originals survives, a second
// forward pass over the result changes nothing, and the way back is exact.
func TestLayers_AllLayersRoundTripAndASecondPassIsQuiet(t *testing.T) {
	host, customer := node(9), dir(10)
	addr := lab.V4(10, 20, 30, 41)
	mac := lab.MAC(0xa4, 0xbb, 0x6d, 0x11, 0x22, 0x33)
	person, domain := local(6), zone(5)

	terms := lab.Terms(t,
		detect.Term{Value: host, Kind: detect.KindHost},
		detect.Term{Value: customer, Kind: detect.KindPathSegment},
	)
	patterns := lab.Patterns(t, detect.PatternsConfig{IPv4: true, MAC: true, Email: true})
	paths := lab.Paths(t, detect.PathsConfig{ReplaceUnknown: true})
	tab := lab.Table()
	c := detect.NewComposite(tab.Knows, terms, patterns, paths)

	text := strings.Join([]string{
		"ssh " + host,
		"ip " + addr + " hw " + mac,
		"mail " + person + "@" + domain,
		abs("mnt", customer, "data", "x.txt"),
	}, "\n")

	checkDisjoint(t, text, c.Scan(text))
	out := lab.Forward(text, c, tab)
	for _, v := range []string{host, customer, addr, mac, person, domain} {
		if strings.Contains(out, v) {
			t.Fatalf("a value of %d bytes survives the outbound path", len(v))
		}
	}
	if again := lab.Forward(out, c, tab); again != out {
		t.Fatalf("a second forward pass changed the text")
	}
	if back := lab.Back(out, tab); back != text {
		t.Fatalf("the way back is not byte exact")
	}
}
