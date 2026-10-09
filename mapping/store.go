package mapping

import (
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// StoreConfig bounds the store.
type StoreConfig struct {
	// TTL is how long a session's table lives without being used. Every
	// request of the conversation, every response and every stream chunk
	// counts as use. Default 10 minutes.
	TTL time.Duration
	// MaxTables is the number of session tables kept at once. When it is
	// reached, the table used least recently is evicted and the eviction is
	// logged. Default 1024.
	MaxTables int
	// MemoryTTL is how long a session's memory lives without being used,
	// see Memory. Default 24 hours.
	MemoryTTL time.Duration
	// Now returns the current time; nil means time.Now. Tests inject a clock.
	Now func() time.Time
}

const (
	defaultTTL       = 10 * time.Minute
	defaultMaxTables = 1024
)

// sessionEntry is one held table with the moment it was last used. seq
// breaks ties when the clock stands still between two uses, so eviction
// stays in order of use.
type sessionEntry struct {
	table   *Table
	lastUse time.Time
	seq     uint64
}

// binding ties a RequestID to its session and remembers the hit counts of
// the table at the moment the request was bound, so the swaps of this one
// request can be told apart from those of the requests before it.
type binding struct {
	session    string
	hitsBefore map[string]int
}

// Store keeps the tables of the open conversations by session and the
// requests in flight by RequestID. It is safe for concurrent use.
type Store struct {
	ttl      time.Duration
	maxTable int
	now      func() time.Time

	mu       sync.Mutex
	sessions map[string]*sessionEntry
	requests map[string]binding
	seq      uint64

	// memories are the conversations' memories by session, on their own
	// lifetime memTTL; see Memory.
	memTTL   time.Duration
	memories map[string]*memoryEntry
}

// NewStore creates a store. Zero fields of cfg take their defaults.
func NewStore(cfg StoreConfig) *Store {
	s := &Store{
		ttl:      cfg.TTL,
		maxTable: cfg.MaxTables,
		now:      cfg.Now,
		sessions: make(map[string]*sessionEntry),
		requests: make(map[string]binding),
		memTTL:   cfg.MemoryTTL,
		memories: make(map[string]*memoryEntry),
	}
	if s.ttl <= 0 {
		s.ttl = defaultTTL
	}
	if s.memTTL <= 0 {
		s.memTTL = defaultMemoryTTL
	}
	if s.maxTable <= 0 {
		s.maxTable = defaultMaxTables
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Open returns the table of the conversation sessionID, creating an empty
// one when the store holds none, and counts the call as a use. gen becomes
// the generator for the rows added from now on, so a configuration reload
// reaches a running conversation; rows that exist keep their pseudonyms.
// Open binds no request: the forward pass calls Bind once it has finished,
// so a request that is blocked leaves no binding behind.
func (s *Store) Open(sessionID string, gen Generator) *Table {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(now)
	e, ok := s.sessions[sessionID]
	if !ok {
		s.evictForLocked()
		t := NewTable(gen)
		t.session = sessionID
		e = &sessionEntry{table: t}
		s.sessions[sessionID] = e
	} else {
		e.table.setGenerator(gen)
	}
	s.touchLocked(e, now)
	return e.table
}

// Bind ties requestID to t, so the return path finds t under the
// RequestID the host sends with the response, the stream and the
// completion. t is filed as the table of its session when the store does
// not hold it yet; a table built with NewTable outside the store becomes a
// session of its own, named after the request. Binding the same RequestID
// twice replaces the earlier binding.
func (s *Store) Bind(requestID string, t *Table) {
	if t == nil || requestID == "" {
		return
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(now)
	if t.session == "" {
		t.session = requestID
	}
	e, ok := s.sessions[t.session]
	if !ok || e.table != t {
		if !ok {
			s.evictForLocked()
		}
		e = &sessionEntry{table: t}
		s.sessions[t.session] = e
	}
	s.touchLocked(e, now)
	s.requests[requestID] = binding{session: t.session, hitsBefore: t.RestoredHits()}
}

// Put files t as a session of its own named requestID and binds requestID
// to it. It is Bind for a table that belongs to no conversation, which is
// what tests and diagnostics build; the plugin goes through Open and Bind.
func (s *Store) Put(requestID string, t *Table) {
	if t == nil {
		return
	}
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sweepLocked(now)
	t.session = requestID
	e, ok := s.sessions[requestID]
	if !ok {
		s.evictForLocked()
		e = &sessionEntry{}
		s.sessions[requestID] = e
	}
	e.table = t
	s.touchLocked(e, now)
	s.requests[requestID] = binding{session: requestID, hitsBefore: t.RestoredHits()}
}

// Get returns the table bound to requestID or ErrTableNotFound if the
// request is unknown or its session has expired. Get counts as a use of the
// session, so a conversation that keeps streaming keeps its table.
func (s *Store) Get(requestID string) (*Table, error) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.requests[requestID]
	if !ok {
		return nil, ErrTableNotFound
	}
	e, ok := s.sessions[b.session]
	if !ok || s.expiredLocked(e, now) {
		if ok {
			delete(s.sessions, b.session)
		}
		delete(s.requests, requestID)
		return nil, ErrTableNotFound
	}
	s.touchLocked(e, now)
	return e.table, nil
}

// Has reports whether requestID is bound to a table that has not expired,
// without counting as a use.
func (s *Store) Has(requestID string) bool {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.requests[requestID]
	if !ok {
		return false
	}
	e, ok := s.sessions[b.session]
	return ok && !s.expiredLocked(e, now)
}

// Discard drops t from the store if no request is bound to it and it holds
// no row: the forward pass opened it and then failed, so nothing refers to
// it. A table with rows or bindings is left alone.
func (s *Store) Discard(t *Table) {
	if t == nil || t.Len() > 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.sessions[t.session]
	if !ok || e.table != t {
		return
	}
	for _, b := range s.requests {
		if b.session == t.session {
			return
		}
	}
	delete(s.sessions, t.session)
}

// Complete removes the binding of requestID and returns the table it was
// bound to and how often each pseudonym was swapped back while the request
// was bound, or nil, nil and false for a request the store does not know.
// The table itself stays with its session for the requests still to come.
// The lifecycle handler calls it on request.complete.
func (s *Store) Complete(requestID string) (*Table, map[string]int, bool) {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.requests[requestID]
	if !ok {
		return nil, nil, false
	}
	delete(s.requests, requestID)
	e, ok := s.sessions[b.session]
	if !ok || s.expiredLocked(e, now) {
		if ok {
			delete(s.sessions, b.session)
		}
		return nil, nil, false
	}
	s.touchLocked(e, now)
	return e.table, hitsSince(e.table.RestoredHits(), b.hitsBefore), true
}

// hitsSince returns the counts of now that exceed those of before.
func hitsSince(now, before map[string]int) map[string]int {
	out := make(map[string]int, len(now))
	for k, n := range now {
		if d := n - before[k]; d > 0 {
			out[k] = d
		}
	}
	return out
}

// Delete removes the binding of requestID. Deleting an unknown ID is a
// no-op. The table stays with its session.
func (s *Store) Delete(requestID string) {
	s.Complete(requestID)
}

// SetTTL changes the lifetime applied to every table, held ones included,
// from their own last use. The store outlives the plugin instance that
// created it, so a configuration reload with a new mapping_ttl reaches the
// tables through this instead of through a new store. A non-positive
// value keeps the current TTL.
func (s *Store) SetTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
}

// Sweep removes the tables that have not been used for the TTL, with the
// bindings of their requests, and returns how many tables it removed. Get,
// Open and Bind also drop expired tables lazily; Sweep exists so a
// background ticker can bound memory when a conversation never comes back.
func (s *Store) Sweep() int {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

// Len returns the number of session tables currently held, including
// expired ones that have not been swept yet.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// Bound returns the number of requests currently bound to a table.
func (s *Store) Bound() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *Store) touchLocked(e *sessionEntry, now time.Time) {
	s.seq++
	e.lastUse = now
	e.seq = s.seq
}

func (s *Store) expiredLocked(e *sessionEntry, now time.Time) bool {
	return !now.Before(e.lastUse.Add(s.ttl))
}

func (s *Store) sweepLocked(now time.Time) int {
	n := 0
	for id, e := range s.sessions {
		if s.expiredLocked(e, now) {
			delete(s.sessions, id)
			n++
		}
	}
	if n > 0 {
		s.dropOrphanBindingsLocked()
	}
	s.sweepMemoriesLocked(now)
	return n
}

// dropOrphanBindingsLocked removes the bindings whose session is gone.
func (s *Store) dropOrphanBindingsLocked() {
	for id, b := range s.requests {
		if _, ok := s.sessions[b.session]; !ok {
			delete(s.requests, id)
		}
	}
}

// evictForLocked makes room for one more session by evicting the least
// recently used ones while the store is full.
func (s *Store) evictForLocked() {
	evicted := false
	for len(s.sessions) >= s.maxTable {
		id, ok := s.leastRecentLocked()
		if !ok {
			break
		}
		delete(s.sessions, id)
		evicted = true
		logrus.WithFields(logrus.Fields{
			"max_tables": s.maxTable,
		}).Warn("privacyfilter: mapping store full, evicted the table used least recently; its responses will not be restored")
	}
	if evicted {
		s.dropOrphanBindingsLocked()
	}
}

// leastRecentLocked returns the session used longest ago.
func (s *Store) leastRecentLocked() (string, bool) {
	var (
		oldest *sessionEntry
		id     string
	)
	for candidateID, e := range s.sessions {
		if oldest == nil || e.lastUse.Before(oldest.lastUse) ||
			(e.lastUse.Equal(oldest.lastUse) && e.seq < oldest.seq) {
			oldest, id = e, candidateID
		}
	}
	return id, oldest != nil
}
