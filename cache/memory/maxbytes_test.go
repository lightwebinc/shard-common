package memory

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// shardBytes recounts a shard's value bytes from its map, the truth the
// running count must match.
func shardBytes(s *shard) int {
	n := 0
	for _, e := range s.data {
		n += len(e.value)
	}
	return n
}

func checkBytes(t *testing.T, b *Backend) {
	t.Helper()
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.RLock()
		got, want := s.bytes, shardBytes(s)
		s.mu.RUnlock()
		if got != want {
			t.Fatalf("shard %d counts %d bytes, holds %d", i, got, want)
		}
	}
}

// TestMaxBytesBoundsOneShard: writes of mixed sizes into one shard keep its
// values under the cap, the newest writes survive, and the count is exact
// through overwrites, deletes and expiry.
func TestMaxBytesBoundsOneShard(t *testing.T) {
	ctx := context.Background()
	b := NewWithOptions(Options{MaxBytes: shardCount * 10000, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	keys := keysInShard(b, 3, 400)
	s := &b.shards[3]
	sizes := []int{9000, 1, 4500, 120, 9000, 3000}
	for i, k := range keys {
		if err := b.Set(ctx, k, bytes.Repeat([]byte{byte(i)}, sizes[i%len(sizes)]), time.Minute); err != nil {
			t.Fatal(err)
		}
		s.mu.RLock()
		over := s.bytes > b.perShardBytes
		s.mu.RUnlock()
		if over {
			t.Fatalf("after write %d the shard holds %d bytes, cap %d", i, s.bytes, b.perShardBytes)
		}
	}
	checkBytes(t, b)
	last := keys[len(keys)-1]
	if v, _ := b.Get(ctx, last); len(v) != sizes[(len(keys)-1)%len(sizes)] {
		t.Fatalf("the newest write is gone: %d bytes", len(v))
	}
	if v, _ := b.Get(ctx, keys[0]); v != nil {
		t.Fatal("the oldest write survived a full shard")
	}

	// Overwrites, larger and smaller, and a delete.
	_ = b.Set(ctx, last, bytes.Repeat([]byte{1}, 9999), time.Minute)
	checkBytes(t, b)
	_ = b.Set(ctx, last, []byte{2}, time.Minute)
	checkBytes(t, b)
	_ = b.Del(ctx, last)
	_ = b.Del(ctx, last)
	checkBytes(t, b)

	// Expiry returns the bytes.
	short := keysInShard(b, 5, 3)
	for _, k := range short {
		_ = b.Set(ctx, k, bytes.Repeat([]byte{3}, 700), time.Nanosecond)
	}
	time.Sleep(time.Millisecond)
	s5 := &b.shards[5]
	s5.mu.Lock()
	s5.expire(monoNow(), 1<<30)
	s5.mu.Unlock()
	checkBytes(t, b)
	if s5.bytes != 0 {
		t.Fatalf("expired entries still count %d bytes", s5.bytes)
	}
}

// TestMaxBytesRewriteEvictsItself: rewriting the only key of a full shard
// with a larger value evicts the key's old entry to make room and stores the
// new one, current in its queue.
func TestMaxBytesRewriteEvictsItself(t *testing.T) {
	ctx := context.Background()
	b := NewWithOptions(Options{MaxBytes: shardCount * 100, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := keysInShard(b, 7, 1)[0]
	_ = b.Set(ctx, k, bytes.Repeat([]byte{1}, 90), time.Minute)
	_ = b.Set(ctx, k, bytes.Repeat([]byte{2}, 100), time.Minute)
	checkBytes(t, b)
	if v, _ := b.Get(ctx, k); len(v) != 100 || v[0] != 2 {
		t.Fatalf("got %d bytes", len(v))
	}
	s := &b.shards[7]
	s.mu.Lock()
	ok := s.evict()
	s.mu.Unlock()
	if !ok {
		t.Fatal("the rewritten key has no current item to evict")
	}
	checkBytes(t, b)
}

// TestMaxBytesWithMaxKeys: with both caps, the tighter one holds.
func TestMaxBytesWithMaxKeys(t *testing.T) {
	ctx := context.Background()
	b := NewWithOptions(Options{MaxKeys: shardCount * 4, MaxBytes: shardCount * 1 << 20, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	for _, k := range keysInShard(b, 1, 10) {
		_ = b.Set(ctx, k, []byte("x"), time.Minute)
	}
	if n := len(b.shards[1].data); n > 4 {
		t.Fatalf("%d keys under a cap of 4", n)
	}
	checkBytes(t, b)
}
