// Package arena provides an in-process [cache.Backend] that keeps every value
// in one block of memory it allocates once. It is the in-memory backend for a
// cache that turns over fast: a retry endpoint caching every fragment in
// flight stores gigabytes a minute, and a value allocated per write costs an
// allocation, the zeroing of new memory, and a collector that walks every live
// entry. Here a write is a copy into the block and an index entry with no
// pointers in it, so nothing is allocated per write and the collector has
// nothing to walk.
//
// Like the memory backend it offers no cross-instance coordination: SetNX
// races are resolved only within this process.
//
// # The block
//
// Values are written one after another and the block wraps around: a write
// takes the space after the previous one, and what it overwrites is the
// oldest data in the block. An entry is gone once the block has lapped it,
// which makes [Options.Bytes] the cap on the bytes cached: the block holds
// the most recent Bytes written, whatever their TTL. Each record keeps its
// key beside its value, and a lookup compares the whole key, so a lookup
// returns the value stored under that key or nothing, never another entry's
// bytes.
//
// # Expiry and the key cap
//
// TTLs and the key cap behave as in the memory backend. Get never returns an
// expired value. Each shard keeps one FIFO queue per distinct TTL, a
// background expirer drops expired entries from the index every
// [DefaultExpireInterval], and a write of a new key into a full shard evicts
// the entry with the earliest deadline. As there, a caller should use a
// handful of fixed TTLs.
//
// # Leases
//
// [Backend.Lease] copies a value into the block before its key is known and
// returns it there; [Backend.Commit] then stores it under a key without a
// second copy. A lease pins its bytes: until [Backend.Release] the block will
// not overwrite them, and a write that would have to is refused with
// [ErrBusy] (a Set) or an empty lease (a Lease).
package arena

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultExpireInterval is the period of the background expirer when
// [Options.ExpireInterval] is unset.
const DefaultExpireInterval = 250 * time.Millisecond

// DefaultMaxLeases is the number of leases that may be outstanding at once
// when [Options.MaxLeases] is unset.
const DefaultMaxLeases = 1 << 14

const (
	shardCount = 64

	// leaseKeyRoom is the room a lease keeps after its value for the key it
	// is committed under. A longer key is stored with a copy instead.
	leaseKeyRoom = 64

	// maxLeases bounds Options.MaxLeases.
	maxLeases = 1 << 24

	// maxLen bounds a key and a value, whose lengths a record keeps in 32
	// bits.
	maxLen = math.MaxUint32

	// expireBatch bounds the items the expirer pops per shard lock hold.
	expireBatch = 1024

	// compactSlack is how many stale items a shard tolerates beyond its entry
	// count before it compacts its queues.
	compactSlack = 1024
)

var (
	// ErrTooLarge reports a key and value that do not fit the block.
	ErrTooLarge = errors.New("arena: value larger than the arena")

	// ErrBusy reports a write that would have overwritten a leased value.
	ErrBusy = errors.New("arena: write would overwrite a leased value")
)

// Options configures [New].
type Options struct {
	// Bytes is the size of the block, and so the cap on the bytes of the
	// values and keys cached. Required.
	Bytes int

	// MaxKeys is the soft key cap across all shards (0 = bounded by Bytes
	// only).
	MaxKeys int

	// MaxLeases is how many leases may be outstanding at once (<= 0 selects
	// DefaultMaxLeases). It is rounded up to a power of two.
	MaxLeases int

	// ExpireInterval is the period of the background expirer (<= 0 selects
	// DefaultExpireInterval).
	ExpireInterval time.Duration
}

// Backend is the arena cache. See the package doc.
type Backend struct {
	buf  []byte
	size uint64

	// mu guards every copy into and out of buf, the advance of cursor, and
	// the lease table. Lock order: a shard's mu, then mu.
	mu sync.Mutex
	// cursor is the count of bytes ever taken from the block. The block holds
	// the absolute positions [cursor-size, cursor); position p is at
	// buf[p%size]. Written under mu, read anywhere.
	cursor atomic.Uint64
	leases leaseTable

	shards   [shardCount]shard
	perShard int // entry cap per shard (0 = unbounded)
	seed     maphash.Seed

	stop     chan struct{}
	done     chan struct{}
	closeOne sync.Once
}

// Lease is a value held in the block before it has a key (see
// [Backend.Lease]). The zero Lease is empty.
type Lease struct {
	// Buf is the value, in the block. It is read-only, and valid until the
	// lease is released. Nil for an empty lease.
	Buf []byte
	pos uint64
	seq uint64
}

// loc is where an entry's record is. A record is the value followed by the
// key. deadline is the expiry on the monotonic clock, or forever.
type loc struct {
	pos      uint64
	deadline int64
	vlen     uint32
	klen     uint32
}

const forever = math.MaxInt64

// item is one write's place in a queue: the entry it wrote is current while
// the index still maps hash to pos.
type item struct {
	hash uint64
	pos  uint64
}

// queue is a FIFO of the items written with one TTL, so in deadline order.
type queue struct {
	ttl   time.Duration // 0 for the entries that never expire
	items []item
	head  int
}

type shard struct {
	mu     sync.RWMutex
	idx    map[uint64]loc
	queues []*queue
	items  int // items in all queues; items - len(idx) are stale
}

// leaseTable is the leases outstanding, in the order granted, as a ring.
type leaseTable struct {
	pos  []uint64
	done []bool
	head uint64 // next sequence number
	tail uint64 // oldest outstanding
}

var epoch = time.Now()

func monoNow() int64 { return int64(time.Since(epoch)) }

// New constructs an arena backend and starts its background expirer, which
// Close stops. It allocates the block at once; the memory is touched, and so
// resident, only as it is first written.
func New(opts Options) (*Backend, error) {
	if opts.Bytes <= 0 {
		return nil, errors.New("arena: Bytes must be positive")
	}
	interval := opts.ExpireInterval
	if interval <= 0 {
		interval = DefaultExpireInterval
	}
	n := opts.MaxLeases
	if n <= 0 {
		n = DefaultMaxLeases
	}
	if n > maxLeases {
		return nil, fmt.Errorf("arena: MaxLeases %d over the limit %d", n, maxLeases)
	}
	slots := 1
	for slots < n {
		slots <<= 1
	}
	b := &Backend{
		buf:  make([]byte, opts.Bytes),
		size: uint64(opts.Bytes),
		seed: maphash.MakeSeed(),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	b.leases.pos = make([]uint64, slots)
	b.leases.done = make([]bool, slots)
	if opts.MaxKeys > 0 {
		b.perShard = max(opts.MaxKeys/shardCount, 1)
	}
	for i := range b.shards {
		b.shards[i].idx = make(map[uint64]loc)
	}
	go b.run(interval)
	return b, nil
}

// Bytes reports the size of the block.
func (b *Backend) Bytes() int { return len(b.buf) }

func (b *Backend) hash(key []byte) uint64 { return maphash.Bytes(b.seed, key) }

func (b *Backend) shardOf(h uint64) *shard { return &b.shards[h%shardCount] }

// lapped reports whether the block has overwritten the record at pos.
func (b *Backend) lapped(pos uint64) bool { return b.cursor.Load()-pos > b.size }

// take reserves n contiguous bytes and returns their absolute position. It
// fails when n does not fit the block or taking it would overwrite a leased
// value. Callers hold b.mu.
func (b *Backend) take(n uint64) (uint64, error) {
	if n > b.size {
		return 0, ErrTooLarge
	}
	// An empty record still takes a byte: a position names one record.
	n = max(n, 1)
	c := b.cursor.Load()
	if off := c % b.size; off+n > b.size {
		c += b.size - off // a record never straddles the end of the block
	}
	if lt := &b.leases; lt.tail != lt.head {
		if oldest := lt.pos[lt.tail&uint64(len(lt.pos)-1)]; c+n-oldest > b.size {
			return 0, ErrBusy
		}
	}
	b.cursor.Store(c + n)
	return c, nil
}

func (b *Backend) at(pos uint64, n uint32) []byte {
	off := pos % b.size
	return b.buf[off : off+uint64(n) : off+uint64(n)]
}

// write copies val then key into the block and returns the record's place.
func (b *Backend) write(key, val []byte) (loc, error) {
	if uint64(len(val)) > maxLen || uint64(len(key)) > maxLen {
		return loc{}, ErrTooLarge
	}
	n := uint64(len(val)) + uint64(len(key))
	b.mu.Lock()
	pos, err := b.take(n)
	if err != nil {
		b.mu.Unlock()
		return loc{}, err
	}
	off := pos % b.size
	copy(b.buf[off:], val)
	copy(b.buf[off+uint64(len(val)):], key)
	b.mu.Unlock()
	return loc{pos: pos, vlen: uint32(len(val)), klen: uint32(len(key))}, nil
}

// holds reports whether the record at l is intact and stored under key.
// Callers hold b.mu.
func (b *Backend) holds(l loc, key []byte) bool {
	return !b.lapped(l.pos) && int(l.klen) == len(key) && bytes.Equal(b.at(l.pos+uint64(l.vlen), l.klen), key)
}

func deadlineFor(ttl time.Duration, now int64) (int64, time.Duration) {
	if ttl > 0 && now <= math.MaxInt64-int64(ttl) {
		return now + int64(ttl), ttl
	}
	return forever, 0
}

// Set unconditionally writes key=val.
func (b *Backend) Set(_ context.Context, key, val []byte, ttl time.Duration) error {
	l, err := b.write(key, val)
	if err != nil {
		return err
	}
	h := b.hash(key)
	s := b.shardOf(h)
	s.mu.Lock()
	b.index(s, h, l, ttl)
	s.mu.Unlock()
	return nil
}

// SetNX creates key=val iff key is absent or its entry has expired or been
// overwritten.
func (b *Backend) SetNX(_ context.Context, key, val []byte, ttl time.Duration) (bool, error) {
	h := b.hash(key)
	s := b.shardOf(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.idx[h]; ok && l.deadline > monoNow() {
		b.mu.Lock()
		live := b.holds(l, key)
		b.mu.Unlock()
		if live {
			return false, nil
		}
	}
	l, err := b.write(key, val)
	if err != nil {
		return false, err
	}
	b.index(s, h, l, ttl)
	return true, nil
}

// Get returns a copy of the live value for key, or (nil, nil) on a miss:
// absent, expired, or overwritten by the block.
func (b *Backend) Get(_ context.Context, key []byte) ([]byte, error) {
	h := b.hash(key)
	s := b.shardOf(h)
	s.mu.RLock()
	l, ok := s.idx[h]
	s.mu.RUnlock()
	if !ok || l.deadline <= monoNow() {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.holds(l, key) {
		return nil, nil
	}
	return bytes.Clone(b.at(l.pos, l.vlen)), nil
}

// Del removes key.
func (b *Backend) Del(_ context.Context, key []byte) error {
	h := b.hash(key)
	s := b.shardOf(h)
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.idx[h]; ok {
		b.mu.Lock()
		same := b.lapped(l.pos) || b.holds(l, key)
		b.mu.Unlock()
		if same {
			delete(s.idx, h)
		}
	}
	return nil
}

// Lease copies val into the block and returns it there, pinned: the block
// does not overwrite it until Release. The returned bytes are read-only. An
// empty lease (nil Buf) means the block could not take the value now (it is
// larger than the block, too many leases are out, or the space it needs is
// leased); the caller then keeps val in memory of its own and uses Set.
func (b *Backend) Lease(val []byte) Lease {
	if uint64(len(val)) > maxLen {
		return Lease{}
	}
	n := uint64(len(val)) + leaseKeyRoom
	b.mu.Lock()
	defer b.mu.Unlock()
	lt := &b.leases
	if lt.head-lt.tail == uint64(len(lt.pos)) {
		return Lease{}
	}
	pos, err := b.take(n)
	if err != nil {
		return Lease{}
	}
	copy(b.buf[pos%b.size:], val)
	i := lt.head & uint64(len(lt.pos)-1)
	lt.pos[i], lt.done[i] = pos, false
	lt.head++
	return Lease{Buf: b.at(pos, uint32(len(val))), pos: pos, seq: lt.head - 1}
}

// Commit stores the leased value under key without copying it. The lease
// stays pinned, and may be committed once; Release it when done with Buf. A
// key longer than a lease has room for is stored with a copy.
func (b *Backend) Commit(ctx context.Context, key []byte, l Lease, ttl time.Duration) error {
	if l.Buf == nil {
		return errors.New("arena: commit of an empty lease")
	}
	if len(key) > leaseKeyRoom {
		return b.Set(ctx, key, l.Buf, ttl)
	}
	b.mu.Lock()
	copy(b.buf[(l.pos+uint64(len(l.Buf)))%b.size:], key)
	b.mu.Unlock()
	h := b.hash(key)
	s := b.shardOf(h)
	s.mu.Lock()
	b.index(s, h, loc{pos: l.pos, vlen: uint32(len(l.Buf)), klen: uint32(len(key))}, ttl)
	s.mu.Unlock()
	return nil
}

// Release unpins a lease. Every non-empty lease must be released exactly
// once, committed or not; its Buf must not be read afterward.
func (b *Backend) Release(l Lease) {
	if l.Buf == nil {
		return
	}
	b.mu.Lock()
	lt := &b.leases
	mask := uint64(len(lt.pos) - 1)
	if l.seq-lt.tail < lt.head-lt.tail { // outstanding
		lt.done[l.seq&mask] = true
		for lt.tail != lt.head && lt.done[lt.tail&mask] {
			lt.tail++
		}
	}
	b.mu.Unlock()
}

// Leased reports the leases outstanding.
func (b *Backend) Leased() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.leases.head - b.leases.tail)
}

// index records l under h in s and queues it for expiry. Callers hold s.mu.
func (b *Backend) index(s *shard, h uint64, l loc, ttl time.Duration) {
	now := monoNow()
	if _, exists := s.idx[h]; !exists && b.perShard > 0 && len(s.idx) >= b.perShard {
		b.sweep(s, now, math.MaxInt)
		for len(s.idx) >= b.perShard {
			if !s.evict() {
				break
			}
		}
	}
	var qttl time.Duration
	l.deadline, qttl = deadlineFor(ttl, now)
	s.idx[h] = l
	s.queueFor(qttl).push(item{hash: h, pos: l.pos})
	s.items++
	if s.items > 2*len(s.idx)+compactSlack {
		s.compact()
	}
}

func (s *shard) queueFor(ttl time.Duration) *queue {
	for _, q := range s.queues {
		if q.ttl == ttl {
			return q
		}
	}
	q := &queue{ttl: ttl}
	s.queues = append(s.queues, q)
	return q
}

// current reports whether it is still the entry the index holds.
func (s *shard) current(it item) (loc, bool) {
	l, ok := s.idx[it.hash]
	return l, ok && l.pos == it.pos
}

// sweep pops, from the head of each queue, up to budget items that are
// stale, expired or lapped, and reports whether the budget ran out. Callers
// hold s.mu.
func (b *Backend) sweep(s *shard, now int64, budget int) bool {
	for _, q := range s.queues {
		for q.len() > 0 {
			it := q.peek()
			l, cur := s.current(it)
			if cur && l.deadline > now && !b.lapped(it.pos) {
				break
			}
			if budget == 0 {
				return true
			}
			budget--
			q.pop()
			s.items--
			if cur {
				delete(s.idx, it.hash)
			}
		}
	}
	return false
}

// evict deletes the entry with the earliest deadline and reports false if
// the shard has none. Callers hold s.mu.
func (s *shard) evict() bool {
	var first *queue
	var firstDeadline int64
	for _, q := range s.queues {
		for q.len() > 0 {
			l, cur := s.current(q.peek())
			if !cur {
				q.pop()
				s.items--
				continue
			}
			if first == nil || l.deadline < firstDeadline {
				first, firstDeadline = q, l.deadline
			}
			break
		}
	}
	if first == nil {
		return false
	}
	it := first.pop()
	s.items--
	delete(s.idx, it.hash)
	return true
}

// compact drops the stale items from every queue. Callers hold s.mu.
func (s *shard) compact() {
	s.items = 0
	for _, q := range s.queues {
		kept := q.items[:0]
		for _, it := range q.items[q.head:] {
			if _, cur := s.current(it); cur {
				kept = append(kept, it)
			}
		}
		q.items, q.head = kept, 0
		s.items += len(kept)
	}
}

func (q *queue) len() int     { return len(q.items) - q.head }
func (q *queue) peek() item   { return q.items[q.head] }
func (q *queue) push(it item) { q.items = append(q.items, it) }

// pop removes and returns the head item. Once half the array has been popped
// the rest moves to the front, which keeps popping O(1) amortized.
func (q *queue) pop() item {
	it := q.items[q.head]
	q.head++
	if 2*q.head >= len(q.items) {
		n := copy(q.items, q.items[q.head:])
		q.items, q.head = q.items[:n], 0
	}
	return it
}

// Healthy always reports true.
func (b *Backend) Healthy(_ context.Context) bool { return true }

// Len reports the entries in the index, including expired or overwritten
// entries the expirer has not yet dropped (each within about one interval).
func (b *Backend) Len() int {
	var n int
	for i := range b.shards {
		b.shards[i].mu.RLock()
		n += len(b.shards[i].idx)
		b.shards[i].mu.RUnlock()
	}
	return n
}

// Close stops the background expirer. Safe to call multiple times.
func (b *Backend) Close() error {
	b.closeOne.Do(func() {
		close(b.stop)
		<-b.done
	})
	return nil
}

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

// expireAll drops every expired or overwritten entry from the index, at most
// expireBatch items per shard lock hold, and forgets the queues left empty.
func (b *Backend) expireAll() {
	for i := range b.shards {
		s := &b.shards[i]
		for more := true; more; {
			s.mu.Lock()
			more = b.sweep(s, monoNow(), expireBatch)
			if !more {
				open := s.queues[:0]
				for _, q := range s.queues {
					if q.len() > 0 {
						open = append(open, q)
					}
				}
				clear(s.queues[len(open):])
				s.queues = open
			}
			s.mu.Unlock()
		}
	}
}
