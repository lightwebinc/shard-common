package txidset

import (
	"encoding/binary"
	"testing"
	"time"
)

// BenchmarkClaimLocalHit measures the hot-path steady state: a TxID already
// present in the tier-1 LRU. This path must NOT touch the tier-2 backend and
// must not allocate — it is the per-packet dedup gate the proxy and listener
// run at line rate. Refactoring tier-2 onto cache.Backend must not regress it.
func BenchmarkClaimLocalHit(b *testing.B) {
	s, err := New(Config{TTL: time.Minute, LocalCapacity: 1 << 16})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	var txid [32]byte
	binary.LittleEndian.PutUint64(txid[:8], 0xDEADBEEF)
	// Prime the local set so every benchmark iteration is a hit.
	s.Claim("bsp:tx:", txid)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if won, _ := s.Claim("bsp:tx:", txid); won {
			b.Fatal("expected local hit (suppress), got win")
		}
	}
}

// BenchmarkClaimLocalMiss measures a tier-1 miss in local-only mode (no
// backend): the cold path that inserts into the LRU. Backend == nil so no
// network call occurs — this is the zero-Redis topology.
func BenchmarkClaimLocalMiss(b *testing.B) {
	s, err := New(Config{TTL: time.Minute, LocalCapacity: 1 << 20})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	b.ReportAllocs()
	b.ResetTimer()
	var txid [32]byte
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(txid[:8], uint64(i))
		s.Claim("bsp:tx:", txid)
	}
}
