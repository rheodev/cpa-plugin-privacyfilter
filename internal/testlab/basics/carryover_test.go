package basics

// A pseudonym that reaches the client unresolved becomes ordinary text in the
// conversation. With a table per request the original never appeared again:
// the forward pass skipped the pseudonym, it was never entered into the new
// table, and the return pass had nothing to resolve it with. The table now
// belongs to the conversation, so the pseudonym of an earlier request
// resolves in every later one.
//
// The finding was not theory. It happened in a session: a command written
// with a directory name came back with the pseudonym in its place and failed
// with "no such package".

import (
	"strings"
	"testing"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

func gen(t *testing.T) *pseudo.Generator {
	t.Helper()
	return pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
}

// Request one carries the value, request two carries only the pseudonym the
// model wrote back. With one table per conversation the second request
// restores it; a fresh table, the old rule, could not.
func TestCarry_PseudonymInTheHistoryIsNotResolvable(t *testing.T) {
	g := gen(t)
	terms := newTerms(t, detect.Term{Value: "zeus.lan", Kind: detect.KindHost})
	st := mapping.NewStore(mapping.StoreConfig{})
	first := st.Open("session-a", g)
	comp := detect.NewComposite(first.Knows, terms)

	// Request one: the value is in the text, the table learns it.
	sent := forward("der Dienst läuft auf zeus.lan", comp, first)
	alias := first.Lookup(detect.KindHost, "zeus.lan")
	if !strings.Contains(sent, alias) {
		t.Fatalf("the forward pass did not use the table's pseudonym: %q", sent)
	}
	// The answer comes back and is restored, so far so good.
	if got := back("ich sehe "+alias, first); !strings.Contains(got, "zeus.lan") {
		t.Fatalf("request one did not restore: %q", got)
	}

	// Request two: the history now contains the model's own answer. Suppose
	// one of them was not restored - through a pseudonym the model
	// reshaped, or a value that came only as a pseudonym - so the history
	// carries the pseudonym as plain text. The second request opens the
	// same conversation and gets the same table.
	second := st.Open("session-a", g)
	if second != first {
		t.Fatalf("the second request of the conversation got another table")
	}
	history := "vorhin sagtest du: ich sehe " + alias
	if sentAgain := forward(history, comp, second); sentAgain != history {
		t.Errorf("the second request rewrote the history: %q", sentAgain)
	}
	if second.Len() != 1 {
		t.Errorf("the pseudonym was entered as a value: %d rows", second.Len())
	}

	// The model repeats it, as models do, and the table resolves it.
	answer := "dann prüfe ich " + alias
	got := back(answer, second)
	if strings.Contains(got, alias) || !strings.Contains(got, "zeus.lan") {
		t.Errorf("the pseudonym reaches the client as text: %q", got)
	}

	// The old rule for comparison: a fresh table has nothing to resolve
	// it with.
	fresh := mapping.NewTable(g)
	if got := back(answer, fresh); !strings.Contains(got, alias) {
		t.Errorf("a fresh table resolved a pseudonym it never produced: %q", got)
	}
}

// The same table resolves it; this is the property the conversation-wide
// table rests on.
func TestCarry_SameTableStillResolves(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")
	if got := back("prüfe "+alias, tab); got != "prüfe zeus.lan" {
		t.Errorf("even the same table failed: %q", got)
	}
}

// How a pseudonym gets into the history in the first place: three ways, all
// of them seen in a session. The conversation-wide table closes the first;
// the other two stay, by contract.
func TestCarry_WaysIntoTheHistory(t *testing.T) {
	g := gen(t)
	tab := mapping.NewTable(g)
	alias := tab.Lookup(detect.KindHost, "zeus.lan")

	t.Run("table gone", func(t *testing.T) {
		empty := mapping.NewTable(g)
		if got := back(alias, empty); got != alias {
			t.Errorf("unexpected: %q", got)
		}
		t.Logf("an expired or evicted table leaves %q standing; the lifetime runs from the last use now", alias)
	})

	t.Run("model reshaped it", func(t *testing.T) {
		cut := alias[:len(alias)-1]
		if got := back(cut, tab); got != cut {
			t.Errorf("unexpected: %q", got)
		}
		t.Logf("a shortened pseudonym %q cannot be resolved and stays", cut)
	})

	t.Run("model invented it", func(t *testing.T) {
		invented := "h-" + strings.Repeat("a", 12)
		if got := back(invented, tab); got != invented {
			t.Errorf("an invented pseudonym was resolved: %q", got)
		}
		t.Logf("an invented %q passes through, as the contract requires", invented)
	})
}
