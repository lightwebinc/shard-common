// local.go: tier-1 in-process TxID set with TTL bound.

package txidset

import (
	"sync"
	"time"
)

// localSet is a fixed-capacity ring-buffer + map set of [32]byte keys with
// per-entry TTL. Inserts past capacity evict the oldest key in FIFO order.
// A SeenAndAdd hit on an expired key is treated as a miss and replaces the
// entry. ttl <= 0 disables expiry (capacity-only eviction).
//
// The set is goroutine-safe via a single mutex.
type localSet struct {
	mu sync.Mutex

	capacity int
	ttl      time.Duration
	entries  map[[32]byte]int64 // key → expiry unix-nanos (zero when ttl<=0)
	ring     [][32]byte
	head     int
	count    int
}

func newLocalSet(capacity int, ttl time.Duration) *localSet {
	if capacity <= 0 {
		// Degenerate "always cold" set — every SeenAndAdd reports false.
		return &localSet{}
	}
	return &localSet{
		capacity: capacity,
		ttl:      ttl,
		entries:  make(map[[32]byte]int64, capacity),
		ring:     make([][32]byte, capacity),
	}
}

// SeenAndAdd reports whether key was already present (and not expired) and
// inserts/refreshes it when not. A disabled (capacity=0) set always returns
// false.
func (l *localSet) SeenAndAdd(key [32]byte) bool {
	if l.capacity == 0 {
		return false
	}
	now := time.Now().UnixNano()
	expiry := int64(0)
	if l.ttl > 0 {
		expiry = now + l.ttl.Nanoseconds()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if exp, ok := l.entries[key]; ok {
		if l.ttl <= 0 || exp >= now {
			// Refresh expiry but report as duplicate.
			l.entries[key] = expiry
			return true
		}
		// Stale: fall through and re-insert.
	}

	if l.count == l.capacity {
		old := l.ring[l.head]
		delete(l.entries, old)
	} else {
		l.count++
	}
	l.ring[l.head] = key
	l.head = (l.head + 1) % l.capacity
	l.entries[key] = expiry
	return false
}

// Len reports the current populated-slot count.
func (l *localSet) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count
}
