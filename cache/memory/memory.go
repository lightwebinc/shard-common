// Package memory provides an in-process [cache.Backend]: zero infrastructure,
// used for dev/CI and for per-instance frame storage in the retry endpoint.
// It offers no cross-instance coordination: SetNX races are resolved only
// within this process.
//
// # Expiry
//
// Each shard keeps one FIFO expiry queue per distinct TTL. Entries written
// with the same TTL expire in write order, so a queue is sorted by deadline
// and expiring it pops a prefix: expiry work is proportional to the entries
// that expire, never a scan of the map. A background expirer pops expired
// heads every [DefaultExpireInterval] (see [Options]) and each write pops a
// few more, so an expired entry is removed within about one interval of its
// deadline. Get never returns an expired value.
//
// Deletion from the queues is lazy. A rewrite or Del leaves the key's earlier
// item queued, and popping an item deletes its entry only if the entry still
// carries the item's deadline. A shard compacts its queues once such stale
// items outnumber its entries by more than a fixed slack, which bounds the
// queues of a key that is rewritten often.
//
// Every current caller uses a handful of fixed TTLs. A TTL that a shard has
// not seen opens a new queue, and expiry and eviction visit every open queue,
// so a caller deriving a distinct TTL for each write would defeat the design.
//
// # Capacity
//
// With a key cap, each shard holds at most cap/64 entries (at least one). A
// write of a new key into a full shard first expires what it can, then evicts
// the entry with the earliest deadline, so no entry is evicted while one that
// expires sooner remains in its shard. Entries that never expire are evicted
// only when the shard holds no entry with a TTL, least recently written first.
package memory

import (
	"context"
	"math"
	"sync"
	"time"
)

// DefaultExpireInterval is the period of the background expirer used by
// [New], and by [NewWithOptions] when [Options.ExpireInterval] is unset.
const DefaultExpireInterval = 250 * time.Millisecond

const (
	shardCount = 64

	// writeExpireBudget is how many expired items a write pops from the head
	// of its TTL queue, which keeps expiry ahead of the write rate between
	// runs of the expirer.
	writeExpireBudget = 2

	// expireBatch bounds the items the expirer pops per shard lock hold, so a
	// burst of deadlines does not stall the shard's writers.
	expireBatch = 1024

	// compactSlack is how many stale items a shard tolerates beyond its entry
	// count before it compacts its queues.
	compactSlack = 1024

	// queueShrinkCap is the capacity above which a queue moves its items to a
	// smaller array once they fill under an eighth of it, so a burst does not
	// pin its peak memory.
	queueShrinkCap = 1024
)

// Options configures [NewWithOptions].
type Options struct {
	// MaxKeys is the soft key cap across all shards (0 = unbounded).
	MaxKeys int

	// ExpireInterval is the period of the background expirer (<= 0 selects
	// DefaultExpireInterval).
	ExpireInterval time.Duration
}

// Backend is a striped in-memory cache. The keyspace is sharded across
// independently locked maps so concurrent workers do not serialize on a
// single mutex.
type Backend struct {
	shards   [shardCount]shard
	perShard int // entry cap per shard (0 = unbounded)

	stop     chan struct{} // closed by Close
	done     chan struct{} // closed when the expirer exits
	closeOne sync.Once
}

type shard struct {
	mu   sync.RWMutex
	data map[string]entry

	// ttlQueues holds one queue per TTL with items in flight.
	ttlQueues []*queue
	// forever queues the entries that never expire, in write order.
	forever queue
	// writes numbers the writes of entries that never expire (see entry).
	writes int64
	// items counts the items in all queues. Every entry has a current item,
	// so items - len(data) is the number of stale items.
	items int
}

// entry is a cached value. A positive deadline is its expiry on the monotonic
// clock (see monoNow). An entry that never expires holds the negated number
// of its write instead, which identifies its item in the forever queue.
type entry struct {
	value    []byte
	deadline int64
}

func (e entry) live(now int64) bool { return e.deadline <= 0 || now < e.deadline }

// item is one write's place in a queue. key shares the string of the map key
// it was written under, and deadline is the entry's as of that write: the
// item is current while the entry still carries it, and stale once the key is
// rewritten or deleted.
type item struct {
	key      string
	deadline int64
}

// queue is a FIFO of items. The deadlines in a TTL queue never decrease, as
// each is a write time plus the same TTL.
type queue struct {
	ttl   time.Duration // 0 for the forever queue
	items []item
	head  int // items[:head] have been popped
}

// epoch anchors monoNow.
var epoch = time.Now()

// monoNow returns the nanoseconds since epoch on the monotonic clock, so a
// wall-clock step cannot move a deadline.
func monoNow() int64 { return int64(time.Since(epoch)) }

// New constructs an in-memory backend with the given soft key cap (0 =
// unbounded) and the default expirer interval. See the package doc for how
// entries expire and how the cap evicts.
func New(maxKeys int) *Backend {
	return NewWithOptions(Options{MaxKeys: maxKeys})
}

// NewWithOptions constructs an in-memory backend and starts its background
// expirer, which Close stops.
func NewWithOptions(opts Options) *Backend {
	interval := opts.ExpireInterval
	if interval <= 0 {
		interval = DefaultExpireInterval
	}
	b := &Backend{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	if opts.MaxKeys > 0 {
		b.perShard = max(opts.MaxKeys/shardCount, 1)
	}
	for i := range b.shards {
		b.shards[i].data = make(map[string]entry)
	}
	go b.run(interval)
	return b
}

func (b *Backend) shardFor(key []byte) *shard {
	// FNV-1a over the key; keys here (TxIDs, HashKey||SeqNum) are uniform.
	var h uint32 = 2166136261
	for _, c := range key {
		h ^= uint32(c)
		h *= 16777619
	}
	return &b.shards[h%shardCount]
}

// SetNX creates key=val iff key is absent or its entry has expired.
func (b *Backend) SetNX(_ context.Context, key, val []byte, ttl time.Duration) (bool, error) {
	s := b.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := monoNow()
	prev, ok := s.data[string(key)]
	if ok && prev.live(now) {
		return false, nil
	}
	b.put(s, key, val, ttl, now, prev, ok)
	return true, nil
}

// Set unconditionally writes key=val.
func (b *Backend) Set(_ context.Context, key, val []byte, ttl time.Duration) error {
	s := b.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.data[string(key)]
	b.put(s, key, val, ttl, monoNow(), prev, ok)
	return nil
}

// Get returns the live value for key, or (nil, nil) on miss or expiry.
func (b *Backend) Get(_ context.Context, key []byte) ([]byte, error) {
	s := b.shardFor(key)
	s.mu.RLock()
	e, ok := s.data[string(key)]
	s.mu.RUnlock()
	if !ok || !e.live(monoNow()) {
		return nil, nil
	}
	return e.value, nil
}

// Del removes key. Its queue item goes stale and is dropped when popped.
func (b *Backend) Del(_ context.Context, key []byte) error {
	s := b.shardFor(key)
	s.mu.Lock()
	delete(s.data, string(key))
	s.mu.Unlock()
	return nil
}

// Healthy always reports true for the in-memory backend.
func (b *Backend) Healthy(_ context.Context) bool { return true }

// Len reports the current entry count across all shards, including expired
// entries not yet removed (the expirer removes each within about one interval
// of its deadline). Used by the retry endpoint's cache-size sampler.
func (b *Backend) Len() int {
	var n int
	for i := range b.shards {
		b.shards[i].mu.RLock()
		n += len(b.shards[i].data)
		b.shards[i].mu.RUnlock()
	}
	return n
}

// Close stops the background expirer and waits for it to exit. Safe to call
// multiple times.
func (b *Backend) Close() error {
	b.closeOne.Do(func() {
		close(b.stop)
		<-b.done
	})
	return nil
}

// put writes key=val at now. When exists, prev is the entry it replaces (live
// or expired), so no room is needed. Callers hold s.mu, and read now under it
// so each TTL queue stays sorted.
func (b *Backend) put(s *shard, key, val []byte, ttl time.Duration, now int64, prev entry, exists bool) {
	if !exists && b.perShard > 0 && len(s.data) >= b.perShard {
		s.makeRoom(now, b.perShard)
	}
	k := string(key)
	q := &s.forever
	var deadline int64
	// A deadline beyond the int64 range is never reached, so such a TTL is
	// stored as never expiring.
	expires := ttl > 0 && now <= math.MaxInt64-int64(ttl)
	if expires {
		q, deadline = s.queueFor(ttl), now+int64(ttl)
	} else {
		s.writes++
		deadline = -s.writes
	}
	s.data[k] = entry{value: clone(val), deadline: deadline}
	if exists && prev.deadline == deadline {
		// A rewrite within one clock tick: the earlier item carries this
		// deadline too and stays the key's current item.
		return
	}
	q.push(item{key: k, deadline: deadline})
	s.items++
	if expires {
		s.expireQueue(q, now, writeExpireBudget)
	}
	if s.items > 2*len(s.data)+compactSlack {
		s.compact()
	}
}

// queueFor returns the shard's queue for ttl, opening it on first use.
// Callers hold s.mu.
func (s *shard) queueFor(ttl time.Duration) *queue {
	for _, q := range s.ttlQueues {
		if q.ttl == ttl {
			return q
		}
	}
	q := &queue{ttl: ttl}
	s.ttlQueues = append(s.ttlQueues, q)
	return q
}

// makeRoom brings the shard below limit entries for a new key: it removes
// every expired entry, then evicts until there is room. Callers hold s.mu.
func (s *shard) makeRoom(now int64, limit int) {
	s.expire(now, math.MaxInt)
	for len(s.data) >= limit {
		if !s.evict() {
			return
		}
	}
}

// expire pops up to budget expired items across the TTL queues and reports
// whether the budget ran out first. Callers hold s.mu.
func (s *shard) expire(now int64, budget int) bool {
	for _, q := range s.ttlQueues {
		if budget = s.expireQueue(q, now, budget); budget == 0 {
			return true
		}
	}
	return false
}

// expireQueue pops up to budget items from q whose deadline has passed and
// returns the budget left. Callers hold s.mu.
func (s *shard) expireQueue(q *queue, now int64, budget int) int {
	for budget > 0 && q.len() > 0 && q.peek().deadline <= now {
		s.pop(q)
		budget--
	}
	return budget
}

// evict deletes the entry with the earliest deadline or, when no entry has a
// TTL, the least recently written entry that never expires. It reports false
// if the shard is empty. Callers hold s.mu.
func (s *shard) evict() bool {
	var first *queue
	for _, q := range s.ttlQueues {
		s.dropStale(q)
		if q.len() > 0 && (first == nil || q.peek().deadline < first.peek().deadline) {
			first = q
		}
	}
	if first == nil {
		s.dropStale(&s.forever)
		if s.forever.len() == 0 {
			return false
		}
		first = &s.forever
	}
	s.pop(first)
	return true
}

// pop removes q's head item, and its entry too while the item is current.
// Callers hold s.mu.
func (s *shard) pop(q *queue) {
	it := q.pop()
	s.items--
	if s.current(it) {
		delete(s.data, it.key)
	}
}

// dropStale pops the stale items at q's head. Callers hold s.mu.
func (s *shard) dropStale(q *queue) {
	for q.len() > 0 && !s.current(q.peek()) {
		q.pop()
		s.items--
	}
}

// current reports whether it is still the latest write of its key. Callers
// hold s.mu.
func (s *shard) current(it item) bool {
	e, ok := s.data[it.key]
	return ok && e.deadline == it.deadline
}

// compact drops the stale items from every queue. Callers hold s.mu.
func (s *shard) compact() {
	s.items = s.keepCurrent(&s.forever)
	for _, q := range s.ttlQueues {
		s.items += s.keepCurrent(q)
	}
}

// keepCurrent filters q down to its current items, in order, and returns how
// many remain. Callers hold s.mu.
func (s *shard) keepCurrent(q *queue) int {
	kept := q.items[:0]
	for _, it := range q.items[q.head:] {
		if s.current(it) {
			kept = append(kept, it)
		}
	}
	clear(q.items[len(kept):])
	q.items, q.head = kept, 0
	return len(kept)
}

// dropEmptyQueues forgets the TTL queues with no items, so a TTL that falls
// out of use costs nothing. Callers hold s.mu.
func (s *shard) dropEmptyQueues() {
	open := s.ttlQueues[:0]
	for _, q := range s.ttlQueues {
		if q.len() > 0 {
			open = append(open, q)
		}
	}
	clear(s.ttlQueues[len(open):])
	s.ttlQueues = open
}

func (q *queue) len() int { return len(q.items) - q.head }

// peek returns the head item. q must not be empty.
func (q *queue) peek() item { return q.items[q.head] }

func (q *queue) push(it item) { q.items = append(q.items, it) }

// pop removes and returns the head item. q must not be empty. Once half the
// array has been popped the rest moves to the front, which keeps popping O(1)
// amortized.
func (q *queue) pop() item {
	it := q.items[q.head]
	q.head++
	if 2*q.head >= len(q.items) {
		q.compact()
	}
	return it
}

// compact moves the unpopped items to the front of the array, or to a smaller
// array when they fill under an eighth of it. What is left behind is cleared
// so popped keys can be collected.
func (q *queue) compact() {
	rest := q.items[q.head:]
	if c := cap(q.items); c > queueShrinkCap && 8*len(rest) < c {
		q.items = append(make([]item, 0, 2*len(rest)), rest...)
	} else {
		n := copy(q.items, rest)
		clear(q.items[n:])
		q.items = q.items[:n]
	}
	q.head = 0
}

// run is the background expirer: one pass every interval until Close.
func (b *Backend) run(interval time.Duration) {
	defer close(b.done)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			b.expireAll()
		case <-b.stop:
			return
		}
	}
}

// expireAll removes every expired entry, popping at most expireBatch items
// per shard lock hold, and forgets the TTL queues left empty.
func (b *Backend) expireAll() {
	for i := range b.shards {
		s := &b.shards[i]
		for more := true; more; {
			s.mu.Lock()
			more = s.expire(monoNow(), expireBatch)
			if !more {
				s.dropEmptyQueues()
			}
			s.mu.Unlock()
		}
	}
}

func clone(v []byte) []byte {
	if v == nil {
		return nil
	}
	c := make([]byte, len(v))
	copy(c, v)
	return c
}
