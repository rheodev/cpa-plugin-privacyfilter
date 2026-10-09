package basics

// The store is the part that fails in production, not in a unit test: tables
// are written on the forward pass and read while the answer streams back,
// they expire on a clock, and they are evicted when too many pile up. Run
// this file with -race.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/detect"
	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
	"github.com/rheodev/cpa-plugin-privacyfilter/pseudo"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// One table, written by the forward pass and read by every stream chunk. The
// documentation promises this is safe; -race is the proof.
func TestRace_TableUnderLoad(t *testing.T) {
	tab := newTable(t)
	r := tab.Restorer()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				tab.Lookup(detect.KindHost, fmt.Sprintf("host%d-%d.lan", i, j))
			}
		}(i)
	}
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				r.Restore("some text with h-000000000000 in it", false)
				r.Holdback("text ending in h-0000000")
				tab.Len()
			}
		}()
	}
	wg.Wait()
	t.Logf("entries after the run: %d", tab.Len())
}

// The store is shared by every request in flight.
func TestRace_StoreUnderLoad(t *testing.T) {
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	st := mapping.NewStore(mapping.StoreConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				id := fmt.Sprintf("req-%d-%d", i, j%7)
				st.Put(id, mapping.NewTable(gen))
				if tab, err := st.Get(id); err == nil {
					tab.Lookup(detect.KindHost, "zeus.lan")
				}
				if j%5 == 0 {
					st.Delete(id)
				}
				if j%11 == 0 {
					st.Sweep()
				}
				st.Len()
			}
		}(i)
	}
	wg.Wait()
	t.Logf("tables left: %d", st.Len())
}

// A long answer streams for longer than the table's lifetime. Every chunk
// reads the table, and every read counts as a use, so the table lives as
// long as the answer runs.
func TestStore_TableExpiresWhileTheAnswerRuns(t *testing.T) {
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	c := &clock{now: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
	st := mapping.NewStore(mapping.StoreConfig{TTL: 10 * time.Minute, Now: c.Now})
	st.Put("req-1", mapping.NewTable(gen))

	// The answer is still streaming, chunk after chunk, for twelve minutes.
	for i := 0; i < 12; i++ {
		c.advance(time.Minute)
		st.Sweep()
		if _, err := st.Get("req-1"); err != nil {
			t.Fatalf("minute %2d: table gone while the answer streams (%v)", i+1, err)
		}
	}
	// Once the conversation is quiet, the lifetime runs out.
	c.advance(11 * time.Minute)
	st.Sweep()
	if _, err := st.Get("req-1"); !errors.Is(err, mapping.ErrTableNotFound) {
		t.Fatalf("a quiet conversation kept its table past the lifetime: %v", err)
	}
}

// The lifetime runs from the last use, not from the moment the table was
// stored.
func TestStore_UseRefreshesTheDeadline(t *testing.T) {
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	c := &clock{now: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
	st := mapping.NewStore(mapping.StoreConfig{TTL: 10 * time.Minute, Now: c.Now})
	st.Put("req-1", mapping.NewTable(gen))
	for i := 0; i < 9; i++ {
		c.advance(time.Minute)
		if _, err := st.Get("req-1"); err != nil {
			t.Fatalf("minute %d: gone too early: %v", i+1, err)
		}
	}
	c.advance(2 * time.Minute) // eleven minutes since Put, two since the last use
	st.Sweep()
	if _, err := st.Get("req-1"); err != nil {
		t.Fatalf("the deadline runs from Put, regardless of use: %v", err)
	}
}

// When the store is full, the table unused longest is evicted, not the one
// stored longest ago: a busy conversation is old but alive.
func TestStore_EvictionPicksTheRightVictim(t *testing.T) {
	gen := pseudo.NewGenerator([]byte("test-secret-not-a-real-one"), []byte("test-salt"), pseudo.DefaultRenderers())
	c := &clock{now: time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)}
	st := mapping.NewStore(mapping.StoreConfig{TTL: time.Hour, MaxTables: 3, Now: c.Now})
	for _, id := range []string{"old-but-busy", "b", "c"} {
		st.Put(id, mapping.NewTable(gen))
		c.advance(time.Second)
	}
	// The oldest table is the one still in use.
	for i := 0; i < 5; i++ {
		c.advance(time.Second)
		if _, err := st.Get("old-but-busy"); err != nil {
			t.Fatalf("lost before the pressure: %v", err)
		}
	}
	st.Put("d", mapping.NewTable(gen))
	if _, err := st.Get("old-but-busy"); err != nil {
		t.Fatalf("the busy conversation was evicted: %v", err)
	}
	if _, err := st.Get("b"); err == nil {
		t.Fatalf("the table unused longest survived the eviction")
	}
}

// Two conversations, two salts: the same value must not produce the same
// pseudonym across sessions, or one session's table restores another's text.
func TestSalt_SessionsDoNotShare(t *testing.T) {
	secret := []byte("test-secret-not-a-real-one-32-by")
	a := pseudo.NewGenerator(secret, pseudo.DeriveSalt(secret, "session-a"), pseudo.DefaultRenderers())
	b := pseudo.NewGenerator(secret, pseudo.DeriveSalt(secret, "session-b"), pseudo.DefaultRenderers())
	ta, tb := mapping.NewTable(a), mapping.NewTable(b)
	pa := ta.Lookup(detect.KindHost, "zeus.lan")
	pb := tb.Lookup(detect.KindHost, "zeus.lan")
	if pa == pb {
		t.Errorf("both sessions produced %q for the same value", pa)
	}
	if again := ta.Lookup(detect.KindHost, "zeus.lan"); again != pa {
		t.Errorf("the same session produced two pseudonyms: %q and %q", pa, again)
	}
	// A pseudonym of the other session must pass through untouched.
	if got, changed := tb.Restorer().Restore("check "+pa, false); changed || !strings.Contains(got, pa) {
		t.Errorf("session b touched session a's pseudonym: %q", got)
	}
	t.Logf("session a: %s   session b: %s", pa, pb)
}
