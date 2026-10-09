package pseudo_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/internal/fixtures"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

// A term equal to a list entry, by full name or given name, drops that entry:
// it is never rendered and no longer counts as a pseudonym shape, while every
// digest that did not select it renders exactly as before.
func TestPersonRendererExcluding(t *testing.T) {
	target := pseudo.Names[3]
	given := strings.Fields(target)[0]
	next := pseudo.Names[4]
	plain := pseudo.DefaultRenderers()[detect.KindPerson]

	r, dropped := pseudo.PersonRendererExcluding([]string{" " + strings.ToUpper(given) + " ", "Markus"})
	if len(dropped) != 1 || dropped[0] != target {
		t.Fatalf("dropped = %q, want [%q]", dropped, target)
	}
	for _, s := range []string{target, given, strings.ToLower(given), strings.ToUpper(target)} {
		if r.Matches(s) {
			t.Fatalf("Matches(%q) = true for an excluded entry", s)
		}
	}
	if !r.Matches(pseudo.Names[0]) || !r.Matches(strings.Fields(pseudo.Names[0])[0]) {
		t.Fatal("an entry that was not excluded must still match")
	}
	hitTarget := 0
	for i := 0; i < 4000; i++ {
		digest := sha256.Sum256([]byte(fmt.Sprint(i)))
		want := plain.Render(digest[:], "Ingrid Muster")
		got := r.Render(digest[:], "Ingrid Muster")
		switch {
		case got == target:
			t.Fatalf("digest %d rendered the excluded entry", i)
		case want == target:
			hitTarget++
			if got != next {
				t.Fatalf("digest %d: excluded slot rendered %q, want the next entry %q", i, got, next)
			}
		case got != want:
			t.Fatalf("digest %d: %q changed to %q although its slot was not excluded", i, want, got)
		}
	}
	if hitTarget == 0 {
		t.Fatal("no digest selected the excluded slot; the test proves nothing")
	}

	if _, none := pseudo.PersonRendererExcluding([]string{"Markus", "nuc"}); none != nil {
		t.Fatalf("a value that is no list entry dropped %q", none)
	}
	byFull, droppedFull := pseudo.PersonRendererExcluding([]string{target})
	if len(droppedFull) != 1 || droppedFull[0] != target || byFull.Matches(given) {
		t.Fatalf("exclusion by full name: dropped %q, Matches(given) = %v", droppedFull, byFull.Matches(given))
	}

	// Through the generator: the excluded name is no pseudonym shape, and
	// a person is still rendered from the list.
	renderers, _ := pseudo.RenderersExcludingNames([]string{given})
	g := pseudo.NewGenerator(fixtures.Secret, pseudo.DeriveSalt(fixtures.Secret, fixtures.SessionA), renderers)
	if g.IsPseudonym(target) || g.IsPseudonym(given) {
		t.Fatal("IsPseudonym accepts the excluded entry")
	}
	if p := g.Pseudonym(detect.KindPerson, given, 0); p == given || p == "" || pseudo.IsName(p) == false {
		t.Fatalf("Pseudonym(person %q) = %q, want another list name", given, p)
	}
}
