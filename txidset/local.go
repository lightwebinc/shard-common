// local.go: tier-1 in-process TxID set with TTL bound.

package txidset

import (
	"encoding/binary"
	"sync"
	"time"
)

// localShards is the number of independently-locked stripes inside a
// [localSet]. Selected by shard = first-8-bytes-of-key mod localShards.
// TxIDs are SHA256-derived (≈uniform) so even distribution is automatic.
//
// Sized to dilute mutex contention without paying memory tax: at the
// default 1 MiB capacity, each shard holds 16k entries.
const localShards = 64

// localSet is a fixed-capacity striped ring-buffer + map of [32]byte keys
// with per-entry TTL. Sharded internally to avoid a global mutex on the
// hot dedup path — without sharding the single mutex serialises every
// worker and dominates the proxy's CPU at high pps.
//
// Inserts past capacity evict the oldest key in FIFO order within their
// shard (global FIFO is not required for dedup correctness). A
// SeenAndAdd hit on an expired key is treated as a miss and replaces
// the entry. ttl <= 0 disables expiry (capacity-only eviction).
//
// Goroutine-safe: each shard has its own mutex.
type localSet struct {
	disabled bool
	shards   [localShards]*localShard
}

type localShard struct {
	mu       sync.Mutex
	capacity int // per-shard
	ttl      time.Duration
	entries  map[[32]byte]int64 // key → expiry unix-nanos (zero when ttl<=0)
	ring     [][32]byte
	head     int
	count    int
}

func newLocalSet(capacity int, ttl time.Duration) *localSet {
	if capacity <= 0 {
		// Degenerate "always cold" set — every SeenAndAdd reports false.
		return &localSet{disabled: true}
	}
	// Distribute capacity across shards. Round up so total ≥ requested.
	perShard := (capacity + localShards - 1) / localShards
	s := &localSet{}
	for i := range s.shards {
		s.shards[i] = &localShard{
			capacity: perShard,
			ttl:      ttl,
			entries:  make(map[[32]byte]int64, perShard),
			ring:     make([][32]byte, perShard),
		}
	}
	return s
}

// SeenAndAdd reports whether key was already present (and not expired) and
// inserts/refreshes it when not. A disabled (capacity=0) set always returns
// false.
func (l *localSet) SeenAndAdd(key [32]byte) bool {
	if l.disabled {
		return false
	}
	// Shard by the first 8 bytes of the key. TxIDs are uniform.
	idx := binary.LittleEndian.Uint64(key[:8]) % localShards
	return l.shards[idx].seenAndAdd(key)
}

func (s *localShard) seenAndAdd(key [32]byte) bool {
	now := time.Now().UnixNano()
	expiry := int64(0)
	if s.ttl > 0 {
		expiry = now + s.ttl.Nanoseconds()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.entries[key]; ok {
		if s.ttl <= 0 || exp >= now {
			// Refresh expiry but report as duplicate.
			s.entries[key] = expiry
			return true
		}
		// Stale: fall through and re-insert.
	}

	if s.count == s.capacity {
		old := s.ring[s.head]
		delete(s.entries, old)
	} else {
		s.count++
	}
	s.ring[s.head] = key
	s.head = (s.head + 1) % s.capacity
	s.entries[key] = expiry
	return false
}
