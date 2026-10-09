package layers

import (
	"strings"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
)

// Composite promotes a mail address of a later layer ahead of every layer
// when it contains a hit of an earlier one. Without it the domain term would
// win over the longer mail match and the local part would stay in clear
// text. This is the rule working.
func TestLayers_MailAddressIsPromotedOverAnInnerTerm(t *testing.T) {
	person, domain := local(4), zone(3)
	text := "reply to " + person + "@" + domain + " today"
	patterns := lab.Patterns(t, detect.PatternsConfig{Email: true})
	terms := lab.Terms(t, detect.Term{Value: domain, Kind: detect.KindDomain})

	c := detect.NewComposite(nil, terms, patterns)
	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if len(got) != 1 || got[0].Kind != detect.KindEmail || got[0].Value != person+"@"+domain {
		t.Fatalf("composite = %s, want the whole address as one mail match", where(got))
	}
	out := roundTrip(t, text, c)
	for _, v := range []string{person, domain} {
		if strings.Contains(out, v) {
			t.Fatalf("a part of %d bytes of the address stays in the outbound text", len(v))
		}
	}
}

// The promotion holds for every kind: a later match that contains an
// earlier one whole wins as a whole. The same domain inside a URL is
// promoted like the mail address around it, and the kind of the containing
// match decides the shape.
func TestLayers_PromotionHoldsForEveryKind(t *testing.T) {
	person, domain := local(8), zone(9)
	mail := person + "@" + domain
	terms := lab.Terms(t, detect.Term{Value: domain, Kind: detect.KindDomain})
	patterns := lab.Patterns(t, detect.PatternsConfig{Email: true, URL: true})

	if got := detect.NewComposite(nil, terms, patterns).Scan(" " + mail + " "); len(got) != 1 || got[0].Kind != detect.KindEmail {
		t.Fatalf("mail address = %s, want one promoted mail match", where(got))
	}

	url := "https:" + sep + sep + domain + sep + "a"
	got := detect.NewComposite(nil, terms, patterns).Scan(" " + url + " ")
	if len(got) != 1 || got[0].Kind != detect.KindURL || got[0].Value != url {
		t.Fatalf("url = %s, want the whole URL promoted", where(got))
	}
}

// Promotion applies to a match that contains the earlier one strictly. A
// later match over exactly the same span is not promoted, so the earlier
// layer keeps the say over the kind of a value both report: a term the
// user declared as a person stays a person even where the structural layer
// sees an address.
func TestLayers_SameSpanKeepsTheKindOfTheTerm(t *testing.T) {
	mail := local(11) + "@" + zone(12)
	text := "write to " + mail + " please"
	terms := lab.Terms(t, detect.Term{Value: mail, Kind: detect.KindPerson})
	patterns := lab.Patterns(t, detect.PatternsConfig{Email: true})

	got := detect.NewComposite(nil, terms, patterns).Scan(text)
	if len(got) != 1 {
		t.Fatalf("composite = %s, want one match", where(got))
	}
	if got[0].Kind != detect.KindPerson || got[0].Source != "terms" {
		t.Fatalf("composite = %s, want the term hit with its declared kind", where(got))
	}
	roundTrip(t, text, detect.NewComposite(nil, terms, patterns))
}

// A domain on the term list that stands both alone and inside a mail address
// keeps its relation: the mail renderer builds its domain part from the
// domain, not from the whole address, so the model still sees one domain in
// two places. The promotion does not cost that.
func TestLayers_PromotionKeepsTheDomainRelation(t *testing.T) {
	person, domain := local(13), zone(14)
	text := "mail " + person + "@" + domain + " and the site " + domain
	terms := lab.Terms(t, detect.Term{Value: domain, Kind: detect.KindDomain})
	patterns := lab.Patterns(t, detect.PatternsConfig{Email: true})
	c := detect.NewComposite(nil, terms, patterns)

	got := c.Scan(text)
	checkDisjoint(t, text, got)
	if len(got) != 2 || got[0].Kind != detect.KindEmail || got[1].Kind != detect.KindDomain {
		t.Fatalf("composite = %s, want a mail match and a bare domain", where(got))
	}
	out := roundTrip(t, text, c)
	alone := lab.Gen().Pseudonym(detect.KindDomain, domain, 0)
	if n := strings.Count(out, alone); n != 2 {
		t.Fatalf("the domain pseudonym stands %d times in the outbound text, want twice", n)
	}
}

// An inner match that Exclude accepted does not promote, so an address built
// from a pseudonym domain and a local part of its own is shielded and leaves
// unchanged. That keeps a second forward pass quiet; the price is the local
// part beside a pseudonym domain.
func TestLayers_PromotionSkipsAnExcludedInnerMatch(t *testing.T) {
	g := lab.Gen()
	domain := g.Pseudonym(detect.KindDomain, zone(15), 0)
	person := local(16)
	text := "write to " + person + "@" + domain + " now"
	patterns := lab.Patterns(t, detect.PatternsConfig{Email: true})
	inner := fakeLayer{"inner", detect.KindDomain, [][2]int{{9 + len(person) + 1, 9 + len(person) + 1 + len(domain)}}}

	c := detect.NewComposite(g.IsPseudonym, inner, patterns)
	if got := c.Scan(text); got != nil {
		t.Fatalf("composite = %s, want nothing: the excluded domain shields the address", where(got))
	}
	if out := roundTrip(t, text, c); !strings.Contains(out, person) {
		t.Fatalf("the local part was replaced after all; the rule has changed")
	}
	t.Logf("a local part of %d bytes beside a pseudonym domain leaves unchanged", len(person))
}

// containsEarlier looks at the earlier matches that begin inside a later
// one, so a mail log whose lines carry the host name from the term list and
// an address that has nothing to do with it costs a pass over the matches,
// not a product of the two lists.
func TestLayers_PromotionCostGrowsWithTheNumberOfAddresses(t *testing.T) {
	host := node(20)
	unit := host + " " + local(21) + "@" + zone(22) + "\n"
	terms := lab.Host(t, host)
	patterns := lab.Patterns(t, detect.PatternsConfig{Email: true})
	c := detect.NewComposite(nil, terms, patterns)

	took := func(n int) time.Duration {
		text := strings.Repeat(unit, n)
		start := time.Now()
		got := c.Scan(text)
		d := time.Since(start)
		if len(got) != 2*n {
			t.Fatalf("n=%d: %d matches, want %d", n, len(got), 2*n)
		}
		return d
	}
	small, large := took(1000), took(4000)
	ratio := float64(large) / float64(max(small, time.Microsecond))
	t.Logf("1000 lines in %v, 4000 in %v, 12000 in %v: four times the input costs %.1f times the run",
		small, large, took(12000), ratio)
	if large > 2*time.Second {
		t.Fatalf("4000 lines take %v, which no request may cost", large)
	}
}
