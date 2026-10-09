package mapping_test

import (
	"testing"
	"time"

	"github.com/rheodev/cpa-plugin-privacyfilter/mapping"
)

// TestStore_MemoryOutlivesTheTable: the memory of a session is still there
// when its table has expired, with everything it was told, and expires on
// its own, longer, clock.
func TestStore_MemoryOutlivesTheTable(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	s := mapping.NewStore(mapping.StoreConfig{TTL: time.Minute, MemoryTTL: time.Hour, Now: clock})
	s.Put("a", mapping.NewTable(fakeGen{}))
	m := s.Memory("a")
	m.MarkSeen("seen-1")
	m.MarkAuthored("own-1")
	if seen, own := m.Counts(); seen != 1 || own != 1 {
		t.Fatalf("Counts = %d, %d, want 1, 1", seen, own)
	}

	now = now.Add(2 * time.Minute)
	if _, err := s.Get("a"); err != mapping.ErrTableNotFound {
		t.Fatal("the table must have expired")
	}
	again := s.Memory("a")
	if again != m || !again.Seen("seen-1") || !again.Authored("own-1") || again.Seen("own-1") || again.Authored("seen-1") {
		t.Fatal("the memory must survive the table with its marks, each in its own set")
	}

	now = now.Add(2 * time.Hour)
	if later := s.Memory("a"); later == m || later.Seen("seen-1") || later.Authored("own-1") {
		t.Fatal("the memory must expire after its own TTL")
	}
	if s.Memories() != 1 {
		t.Fatalf("Memories = %d, want 1", s.Memories())
	}
}

// TestStore_MemoryIsBounded: the store holds as many memories as tables and
// evicts the one used least recently.
func TestStore_MemoryIsBounded(t *testing.T) {
	s := mapping.NewStore(mapping.StoreConfig{MaxTables: 2})
	a := s.Memory("a")
	a.MarkSeen("k")
	s.Memory("b")
	s.Memory("c")
	if s.Memories() != 2 {
		t.Fatalf("Memories = %d, want 2", s.Memories())
	}
	if s.Memory("a").Seen("k") {
		t.Fatal("the memory used least recently must have been evicted")
	}
}

// TestStore_SweepDropsExpiredMemories: Sweep clears memories as it clears
// tables.
func TestStore_SweepDropsExpiredMemories(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	s := mapping.NewStore(mapping.StoreConfig{MemoryTTL: time.Hour, Now: clock})
	s.Memory("a")
	now = now.Add(2 * time.Hour)
	s.Sweep()
	if s.Memories() != 0 {
		t.Fatalf("Memories = %d after sweep, want 0", s.Memories())
	}
}
