package props

// Round-trip properties. The forward pass is the interceptor's, rebuilt in
// lab.Forward; the return pass is the table's own restorer. What is asserted
// is not a single example but the property over whatever the corpus and the
// fuzzer produce.

import (
	"testing"
	"unicode/utf8"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"

	"github.com/rheodev/cpa-plugin-privacyfilter/internal/testlab/lab"
)

// The term layer alone: replace, replace again, restore. The second pass has
// to be a no-op and the circle has to close.
func FuzzPropsRoundTripTerms(f *testing.F) {
	for _, seed := range textSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInput {
			return
		}
		r := termRig(t)
		mid := r.forwardOnce(text)
		checkIdempotent(t, r, text, mid)
		checkNoOriginals(t, r, text, mid)
		checkRoundTrip(t, r, text, mid)
	})
}

// The structural layer alone, under the same three assertions.
func FuzzPropsRoundTripPatterns(f *testing.F) {
	for _, seed := range textSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInput {
			return
		}
		r := patternRig(t)
		mid := r.forwardOnce(text)
		checkIdempotent(t, r, text, mid)
		checkNoOriginals(t, r, text, mid)
		checkRoundTrip(t, r, text, mid)
	})
}

// Both layers in the plugin's order. Only the round trip and the absence of
// the replaced originals are asserted here, not idempotence: what a second
// pass makes of a term that lies inside a structural hit is a question about
// the interplay of the layers and belongs to that area, not to this one.
func FuzzPropsRoundTripComposite(f *testing.F) {
	for _, seed := range textSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > maxFuzzInput {
			return
		}
		r := newRig(t, lab.Terms(t, fixtureTerms()...), lab.Patterns(t, fixturePatterns()))
		mid := r.forwardOnce(text)
		checkNoOriginals(t, r, text, mid)
		checkRoundTrip(t, r, text, mid)
	})
}

// literalKinds are the kinds a maintained list gives its literals. KindURL is
// left out: it has no renderer of its own and falls back to the opaque token,
// which the form probes of this lab already hold against it.
func literalKinds() []detect.Kind {
	return []detect.Kind{
		detect.KindHost, detect.KindDomain, detect.KindPathSegment,
		detect.KindFileName, detect.KindPerson, detect.KindSecret,
		detect.KindEmail, detect.KindSerial,
	}
}

// A term list the fuzzer writes itself: one literal of its choosing, under a
// kind of its choosing, over a text of its choosing. Only the round trip is
// asserted. A short or odd literal may well match inside its own pseudonym on
// a second pass, which says something about the list, not about the circle.
func FuzzPropsRoundTripAnyTerm(f *testing.F) {
	f.Add(termHost, uint8(0), false, "ssh "+termHost)
	f.Add(termSegment, uint8(2), false, "/mnt/"+termSegment+"/berichte")
	f.Add("Straßburger", uint8(4), true, "STRASSBURGER und straßburger")
	f.Add("lan", uint8(0), false, "vlan_lan und plan")
	f.Add("a", uint8(0), false, "a a a")
	f.Fuzz(func(t *testing.T, value string, kindIndex uint8, ignoreCase bool, text string) {
		if value == "" || len(value) > 64 || len(text) > maxFuzzInput {
			return
		}
		if !utf8.ValidString(value) {
			return
		}
		kinds := literalKinds()
		kind := kinds[int(kindIndex)%len(kinds)]

		gen := lab.Gen()
		tab := mapping.NewTable(gen)
		r := &rig{
			gen: gen,
			tab: tab,
			det: detect.NewComposite(tab.Knows,
				lab.Terms(t, detect.Term{Value: value, Kind: kind, IgnoreCase: ignoreCase})),
		}
		mid := r.forwardOnce(text)
		checkNoOriginals(t, r, text, mid)
		checkRoundTrip(t, r, text, mid)
	})
}
