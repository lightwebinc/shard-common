// Package memory provides an in-process [cache.Backend]: zero infrastructure,
// used for dev/CI and for per-instance frame storage in the retry endpoint.
// It offers no cross-instance coordination — SetNX races are resolved only
// within this process.
package memory

import (
	"context"
	"sync"
	"time"
)

// entry holds a cached value with its expiration deadline. A zero expires
// means the entry never expires.
type entry struct {
	value   []byte
	expires time.Time
}

// Backend is a striped in-memory cache. The keyspace is sharded across
// independently-locked maps so concurrent workers do not serialise on a
// single mutex.
type Backend struct {
	shards  [shardCount]shard
	maxKeys int // soft cap across all shards (0 = unbounded)

	stopGC   chan struct{}
	gcTicker *time.Ticker
	closeOne sync.Once
}

const shardCount = 64

type shard struct {
	mu   sync.RWMutex
	data map[string]entry
}

// New constructs an in-memory backend with the given soft key cap (0 =
// unbounded). The cap is enforced per shard (maxKeys/shardCount) with simple
// oldest-wins eviction, which is sufficient for the bounded TTL workloads
// here.
func New(maxKeys int) *Backend {
	b := &Backend{
		maxKeys: maxKeys,
		stopGC:  make(chan struct{}),
	}
	for i := range b.shards {
		b.shards[i].data = make(map[string]entry)
	}
	b.startGC()
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

func deadline(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}

func (e entry) live(now time.Time) bool {
	return e.expires.IsZero() || now.Before(e.expires)
}

// SetNX creates key=val iff absent (or its prior entry has expired).
func (b *Backend) SetNX(_ context.Context, key, val []byte, ttl time.Duration) (bool, error) {
	s := b.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	k := string(key)
	if e, ok := s.data[k]; ok && e.live(time.Now()) {
		return false, nil
	}
	b.evictIfFull(s)
	s.data[k] = entry{value: clone(val), expires: deadline(ttl)}
	return true, nil
}

// Set unconditionally writes key=val.
func (b *Backend) Set(_ context.Context, key, val []byte, ttl time.Duration) error {
	s := b.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[string(key)]; !ok {
		b.evictIfFull(s)
	}
	s.data[string(key)] = entry{value: clone(val), expires: deadline(ttl)}
	return nil
}

// Get returns the live value for key, or (nil, nil) on miss/expiry.
func (b *Backend) Get(_ context.Context, key []byte) ([]byte, error) {
	s := b.shardFor(key)
	s.mu.RLock()
	e, ok := s.data[string(key)]
	s.mu.RUnlock()
	if !ok || !e.live(time.Now()) {
		return nil, nil
	}
	return e.value, nil
}

// Del removes key.
func (b *Backend) Del(_ context.Context, key []byte) error {
	s := b.shardFor(key)
	s.mu.Lock()
	delete(s.data, string(key))
	s.mu.Unlock()
	return nil
}

// Healthy always reports true for the in-memory backend.
func (b *Backend) Healthy(_ context.Context) bool { return true }

// Len reports the current entry count across all shards (including expired
// entries not yet swept). Used by the retry endpoint's cache-size sampler.
func (b *Backend) Len() int {
	var n int
	for i := range b.shards {
		b.shards[i].mu.RLock()
		n += len(b.shards[i].data)
		b.shards[i].mu.RUnlock()
	}
	return n
}

// Close stops the background GC. Safe to call multiple times.
func (b *Backend) Close() error {
	b.closeOne.Do(func() {
		close(b.stopGC)
		if b.gcTicker != nil {
			b.gcTicker.Stop()
		}
	})
	return nil
}

// evictIfFull drops one arbitrary entry from the shard when the per-shard cap
// is reached. Caller holds s.mu.
func (b *Backend) evictIfFull(s *shard) {
	if b.maxKeys <= 0 {
		return
	}
	per := b.maxKeys / shardCount
	if per < 1 {
		per = 1
	}
	if len(s.data) < per {
		return
	}
	for k := range s.data {
		delete(s.data, k)
		break
	}
}

func (b *Backend) startGC() {
	b.gcTicker = time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-b.gcTicker.C:
				b.sweep()
			case <-b.stopGC:
				return
			}
		}
	}()
}

func (b *Backend) sweep() {
	now := time.Now()
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.Lock()
		for k, e := range s.data {
			if !e.live(now) {
				delete(s.data, k)
			}
		}
		s.mu.Unlock()
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
