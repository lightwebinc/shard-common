package arena_test

import (
	"context"
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/cache"
	"github.com/lightwebinc/shard-common/cache/arena"
	"github.com/lightwebinc/shard-common/cache/memory"
)

// The benchmarks store fragment-sized values under frame keys into a cache
// at its steady state: 64 MiB of them live, each write displacing the oldest.

const (
	fragSize  = 8192
	liveBytes = 64 << 20
	liveKeys  = liveBytes / fragSize
)

var frag = make([]byte, fragSize)

func frameKey(k *[26]byte, n uint64) []byte {
	copy(k[:], "bre:frame:")
	binary.BigEndian.PutUint64(k[18:], n)
	return k[:]
}

func benchStore(b *testing.B, store func(key, val []byte)) {
	var k [26]byte
	var i uint64
	for ; i < 2*liveKeys; i++ {
		store(frameKey(&k, i), frag)
	}
	b.SetBytes(fragSize)
	b.ReportAllocs()
	for b.Loop() {
		store(frameKey(&k, i), frag)
		i++
	}
}

func BenchmarkStoreMemory(b *testing.B) {
	m := memory.NewWithOptions(memory.Options{MaxKeys: liveKeys})
	defer func() { _ = m.Close() }()
	ctx := context.Background()
	benchStore(b, func(key, val []byte) { _ = m.Set(ctx, key, val, time.Minute) })
}

func BenchmarkStoreArena(b *testing.B) {
	a, err := arena.New(arena.Options{Bytes: liveBytes})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	ctx := context.Background()
	benchStore(b, func(key, val []byte) { _ = a.Set(ctx, key, val, time.Minute) })
}

func BenchmarkStoreArenaLease(b *testing.B) {
	a, err := arena.New(arena.Options{Bytes: liveBytes})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	ctx := context.Background()
	var l cache.Leaser = a
	benchStore(b, func(key, val []byte) {
		ls := l.Lease(val)
		_ = l.Commit(ctx, key, ls, time.Minute)
		l.Release(ls)
	})
}

// BenchmarkStoreArenaParallel is BenchmarkStoreArena from every CPU at once:
// the copy into the block is outside the cache's lock, so the stored rate
// grows with the writers (until the memory bus is the limit).
func BenchmarkStoreArenaParallel(b *testing.B) {
	a, err := arena.New(arena.Options{Bytes: liveBytes})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	ctx := context.Background()
	b.SetBytes(fragSize)
	b.ReportAllocs()
	var next atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		var k [26]byte
		for pb.Next() {
			_ = a.Set(ctx, frameKey(&k, next.Add(1)), frag, time.Minute)
		}
	})
}
