package mapping

import (
	"sync"
	"time"
)

// MemoryKeyLen is the length of a memory key in bytes. The plugin derives
// the key from the conversation's own digest of a value, so the memory
// holds no clear text.
const MemoryKeyLen = 16

// defaultMemoryTTL is how long a conversation's memory lives without being
// used. It is measured in hours where the table is measured in minutes: the
// table holds originals and is dropped as soon as the conversation pauses,
// the memory holds digests only and has to bridge the pause, because the
// decision it serves, whether the model or the user's side had a value
// first, has to come out the same after the pause as before it.
const defaultMemoryTTL = 24 * time.Hour

// Memory is what a conversation remembers beyond its table: the digests of
// the values the forward pass has replaced, and the digests of the values it
// has left standing because the model wrote them first. The forward pass
// consults it when it decides who had a value first; see the plugin's
// authorship. A Memory is safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	seen     map[string]struct{}
	authored map[string]struct{}
}

func newMemory() *Memory {
	return &Memory{seen: make(map[string]struct{}), authored: make(map[string]struct{})}
}

// Seen reports whether a value with this key was ever replaced in the
// conversation.
func (m *Memory) Seen(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[key]
	return ok
}

// MarkSeen records that a value with this key was replaced.
func (m *Memory) MarkSeen(key string) {
	m.mu.Lock()
	m.seen[key] = struct{}{}
	m.mu.Unlock()
}

// Authored reports whether a value with this key was left standing as the
// model's own.
func (m *Memory) Authored(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.authored[key]
	return ok
}

// MarkAuthored records that a value with this key was left standing as the
// model's own.
func (m *Memory) MarkAuthored(key string) {
	m.mu.Lock()
	m.authored[key] = struct{}{}
	m.mu.Unlock()
}

// Counts returns how many keys the memory holds of each kind, for logs and
// tests.
func (m *Memory) Counts() (seen, authored int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen), len(m.authored)
}

// memoryEntry is one held memory with the moment it was last used.
type memoryEntry struct {
	mem     *Memory
	lastUse time.Time
	seq     uint64
}

// Memory returns the memory of the conversation sessionID, creating an
// empty one when the store holds none, and counts the call as a use. The
// memory lives on its own clock: it is not dropped with the table, and the
// store bounds the number of memories as it bounds the tables.
func (s *Store) Memory(sessionID string) *Memory {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepMemoriesLocked(now)
	e, ok := s.memories[sessionID]
	if !ok {
		s.evictMemoryForLocked()
		e = &memoryEntry{mem: newMemory()}
		s.memories[sessionID] = e
	}
	s.seq++
	e.lastUse = now
	e.seq = s.seq
	return e.mem
}

// Memories returns the number of memories currently held, including
// expired ones that have not been swept yet.
func (s *Store) Memories() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.memories)
}

func (s *Store) sweepMemoriesLocked(now time.Time) int {
	n := 0
	for id, e := range s.memories {
		if !now.Before(e.lastUse.Add(s.memTTL)) {
			delete(s.memories, id)
			n++
		}
	}
	return n
}

// evictMemoryForLocked makes room for one more memory by evicting the ones
// used least recently while the store is full.
func (s *Store) evictMemoryForLocked() {
	for len(s.memories) >= s.maxTable {
		var (
			oldest *memoryEntry
			id     string
		)
		for candidateID, e := range s.memories {
			if oldest == nil || e.lastUse.Before(oldest.lastUse) ||
				(e.lastUse.Equal(oldest.lastUse) && e.seq < oldest.seq) {
				oldest, id = e, candidateID
			}
		}
		if oldest == nil {
			return
		}
		delete(s.memories, id)
	}
}
