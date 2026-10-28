package memory_test

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/cache/memory"
)

// The benchmarks use only the exported API, so they also run against earlier
// versions of the package for comparison.

const benchLive = 1_000_000

var (
	benchCtx = context.Background()
	benchVal = make([]byte, 128)
)

// frameKey is a reusable key shaped like the retry endpoint's frame keys: a
// namespace prefix, then HashKey||SeqNum.
type frameKey [26]byte

func newFrameKey() *frameKey {
	var k frameKey
	copy(k[:], "bre:frame:")
	binary.BigEndian.PutUint64(k[10:], 0x0123456789abcdef)
	return &k
}

func (k *frameKey) seq(n uint64) []byte {
	binary.BigEndian.PutUint64(k[18:], n)
	return k[:]
}

// loaded returns a backend holding benchLive entries with an hour's TTL.
func loaded(b *testing.B, maxKeys int) *memory.Backend {
	b.Helper()
	m := memory.New(maxKeys)
	b.Cleanup(func() { _ = m.Close() })
	k := newFrameKey()
	for i := range uint64(benchLive) {
		_ = m.Set(benchCtx, k.seq(i), benchVal, time.Hour)
	}
	return m
}

// BenchmarkSet rewrites the keys of a backend holding 1M live entries. Two
// passes of rewrites run first, so the measurement is of the steady state.
func BenchmarkSet(b *testing.B) {
	m := loaded(b, 0)
	k := newFrameKey()
	var i uint64
	for ; i < 2*benchLive; i++ {
		_ = m.Set(benchCtx, k.seq(i%benchLive), benchVal, time.Hour)
	}
	for b.Loop() {
		_ = m.Set(benchCtx, k.seq(i%benchLive), benchVal, time.Hour)
		i++
	}
}

// BenchmarkGet reads the keys of a backend holding 1M live entries.
func BenchmarkGet(b *testing.B) {
	m := loaded(b, 0)
	k := newFrameKey()
	var i uint64
	for b.Loop() {
		if v, _ := m.Get(benchCtx, k.seq(i%benchLive)); v == nil {
			b.Fatal("miss")
		}
		i++
	}
}

// BenchmarkChurn writes new keys into a backend capped at 1M entries, so
// every write evicts one: the retry endpoint's frame store at its cap. One
// pass of new keys runs first, so the measurement is of the steady state.
func BenchmarkChurn(b *testing.B) {
	m := loaded(b, benchLive)
	k := newFrameKey()
	i := uint64(benchLive)
	for ; i < 2*benchLive; i++ {
		_ = m.Set(benchCtx, k.seq(i), benchVal, time.Hour)
	}
	for b.Loop() {
		_ = m.Set(benchCtx, k.seq(i), benchVal, time.Hour)
		i++
	}
}

// BenchmarkChurnTTL writes new keys with a 1 ms TTL on top of 1M live
// entries, so expiry rather than a cap must keep the map at its live size.
// excess-keys is how many entries beyond the 1M were still held at the end.
func BenchmarkChurnTTL(b *testing.B) {
	m := loaded(b, 0)
	k := newFrameKey()
	i := uint64(benchLive)
	for b.Loop() {
		_ = m.Set(benchCtx, k.seq(i), benchVal, time.Millisecond)
		i++
	}
	b.ReportMetric(float64(m.Len()-benchLive), "excess-keys")
}
