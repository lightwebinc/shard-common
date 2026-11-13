package arena

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

func newArena(t testing.TB, opts Options) *Backend {
	t.Helper()
	if opts.ExpireInterval == 0 {
		opts.ExpireInterval = 5 * time.Millisecond
	}
	b, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func key(i int) []byte { return fmt.Appendf(nil, "bre:frame:%08d", i) }

// val is a value that names its key, so a lookup that returned another
// entry's bytes is caught.
func val(i, n int) []byte {
	v := make([]byte, n)
	for j := 0; j+8 <= n; j += 8 {
		binary.BigEndian.PutUint64(v[j:], uint64(i))
	}
	return v
}

func mustGet(t *testing.T, b *Backend, k []byte) []byte {
	t.Helper()
	got, err := b.Get(ctx, k)
	if err != nil {
		t.Fatalf("Get(%s): %v", k, err)
	}
	return got
}

func TestNewRejectsNoBytes(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New with no Bytes succeeded")
	}
}

func TestNewRejectsTooManyLeases(t *testing.T) {
	if _, err := New(Options{Bytes: 1024, MaxLeases: maxLeases + 1}); err == nil {
		t.Fatal("New with MaxLeases over the limit succeeded")
	}
}

// An empty key and value is a record like any other: rewriting it does not
// queue items the index cannot tell apart.
func TestEmptyRecord(t *testing.T) {
	b := newArena(t, Options{Bytes: 1 << 20, ExpireInterval: time.Hour})
	for range 10 * compactSlack {
		if err := b.Set(ctx, nil, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	got, err := b.Get(ctx, nil)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("Get of the empty record = (%v, %v)", got, err)
	}
	s := b.shardOf(b.hash(nil))
	s.mu.Lock()
	items := s.items
	s.mu.Unlock()
	if items > 2+compactSlack+1 {
		t.Fatalf("%d queued items for one entry", items)
	}
	l := b.Lease(nil)
	if l.Buf == nil {
		t.Fatal("lease of an empty value refused")
	}
	b.Release(l)
}

// A lapped entry is a miss, and a hit is always the bytes stored under that
// key: write several blocks' worth and look every key up after every write.
func TestLappedEntryIsAMiss(t *testing.T) {
	const size, n, total = 4096, 100, 400
	b := newArena(t, Options{Bytes: size})
	for i := range total {
		if err := b.Set(ctx, key(i), val(i, n), time.Minute); err != nil {
			t.Fatal(err)
		}
		hits := 0
		for j := 0; j <= i; j++ {
			got := mustGet(t, b, key(j))
			if got == nil {
				continue
			}
			hits++
			if !bytes.Equal(got, val(j, n)) {
				t.Fatalf("after write %d: Get(%d) returned other bytes", i, j)
			}
		}
		// The newest entry is always there, and no more than fit the block.
		if got := mustGet(t, b, key(i)); got == nil {
			t.Fatalf("newest entry %d missing", i)
		}
		if most := size / (n + len(key(0))); hits > most {
			t.Fatalf("after write %d: %d hits, the block fits %d", i, hits, most)
		}
	}
	if got := mustGet(t, b, key(0)); got != nil {
		t.Fatal("entry 0 survived three laps")
	}
}

// The expirer drops lapped entries from the index.
func TestLappedEntriesLeaveTheIndex(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	for i := range 400 {
		_ = b.Set(ctx, key(i), val(i, 100), time.Minute)
	}
	most := 4096 / 100
	deadline := time.Now().Add(2 * time.Second)
	for b.Len() > most {
		if time.Now().After(deadline) {
			t.Fatalf("Len = %d, want at most %d", b.Len(), most)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestGetReturnsACopy(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	_ = b.Set(ctx, key(1), val(1, 64), time.Minute)
	got := mustGet(t, b, key(1))
	clear(got)
	if !bytes.Equal(mustGet(t, b, key(1)), val(1, 64)) {
		t.Fatal("writing a returned value changed the cache")
	}
}

// Two keys with one hash: the index holds the later one, and the earlier is
// a miss, not the later one's value.
func TestHashCollisionIsAMiss(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	_ = b.Set(ctx, key(1), val(1, 64), time.Minute)
	h1, h2 := b.hash(key(1)), b.hash(key(2))
	s1 := b.shardOf(h1)
	s1.mu.Lock()
	l := s1.idx[h1]
	s1.mu.Unlock()
	s2 := b.shardOf(h2)
	s2.mu.Lock()
	s2.idx[h2] = l // key 2's hash now leads to key 1's record
	s2.mu.Unlock()
	if got := mustGet(t, b, key(2)); got != nil {
		t.Fatalf("Get(2) = %d bytes of another key's value", len(got))
	}
	if won, err := b.SetNX(ctx, key(2), val(2, 64), time.Minute); err != nil || !won {
		t.Fatalf("SetNX over a colliding entry = (%v, %v), want (true, nil)", won, err)
	}
	if !bytes.Equal(mustGet(t, b, key(2)), val(2, 64)) {
		t.Fatal("Get(2) after SetNX")
	}
}

func TestExpiry(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	_ = b.Set(ctx, key(1), val(1, 64), 20*time.Millisecond)
	_ = b.Set(ctx, key(2), val(2, 64), time.Minute)
	_ = b.Set(ctx, key(3), val(3, 64), 0) // never expires
	if mustGet(t, b, key(1)) == nil {
		t.Fatal("entry missing before its deadline")
	}
	time.Sleep(60 * time.Millisecond)
	if mustGet(t, b, key(1)) != nil {
		t.Fatal("expired entry returned")
	}
	if mustGet(t, b, key(2)) == nil || mustGet(t, b, key(3)) == nil {
		t.Fatal("unexpired entry missing")
	}
	if n := b.Len(); n != 2 {
		t.Fatalf("Len = %d after expiry, want 2", n)
	}
	if won, _ := b.SetNX(ctx, key(1), val(9, 64), time.Minute); !won {
		t.Fatal("SetNX on an expired key lost")
	}
}

func TestSetNXOnLappedEntry(t *testing.T) {
	b := newArena(t, Options{Bytes: 1024})
	if won, _ := b.SetNX(ctx, key(0), val(0, 100), time.Minute); !won {
		t.Fatal("first SetNX lost")
	}
	if won, _ := b.SetNX(ctx, key(0), val(0, 100), time.Minute); won {
		t.Fatal("second SetNX won")
	}
	for i := 1; i < 20; i++ {
		_ = b.Set(ctx, key(i), val(i, 100), time.Minute)
	}
	if won, _ := b.SetNX(ctx, key(0), val(0, 100), time.Minute); !won {
		t.Fatal("SetNX on a lapped key lost")
	}
}

func TestOverwriteAndDel(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	_ = b.Set(ctx, key(1), val(1, 64), time.Minute)
	_ = b.Set(ctx, key(1), val(7, 32), time.Minute)
	if !bytes.Equal(mustGet(t, b, key(1)), val(7, 32)) {
		t.Fatal("overwrite not read back")
	}
	if n := b.Len(); n != 1 {
		t.Fatalf("Len = %d, want 1", n)
	}
	_ = b.Del(ctx, key(1))
	_ = b.Del(ctx, key(2)) // absent
	if mustGet(t, b, key(1)) != nil || b.Len() != 0 {
		t.Fatal("deleted entry still there")
	}
}

// Many rewrites of one key do not grow its shard's queue without bound.
func TestStaleItemsCompacted(t *testing.T) {
	b := newArena(t, Options{Bytes: 1 << 20, ExpireInterval: time.Hour})
	for range 10 * compactSlack {
		_ = b.Set(ctx, key(1), val(1, 16), time.Minute)
	}
	s := b.shardOf(b.hash(key(1)))
	s.mu.Lock()
	items := s.items
	s.mu.Unlock()
	if items > 2+compactSlack+1 {
		t.Fatalf("%d queued items for one entry", items)
	}
}

// The key cap evicts the entry with the earliest deadline, not the oldest.
func TestKeyCapEvictsEarliestDeadline(t *testing.T) {
	b := newArena(t, Options{Bytes: 1 << 20, MaxKeys: 2 * shardCount, ExpireInterval: time.Hour})
	var same []int // three keys of one shard, which holds two
	first := b.shardOf(b.hash(key(0)))
	for i := 0; len(same) < 3; i++ {
		if b.shardOf(b.hash(key(i))) == first {
			same = append(same, i)
		}
	}
	_ = b.Set(ctx, key(same[0]), val(0, 16), time.Hour)
	_ = b.Set(ctx, key(same[1]), val(1, 16), time.Minute)
	_ = b.Set(ctx, key(same[2]), val(2, 16), time.Hour)
	if mustGet(t, b, key(same[1])) != nil {
		t.Fatal("the entry with the earliest deadline was kept")
	}
	if mustGet(t, b, key(same[0])) == nil || mustGet(t, b, key(same[2])) == nil {
		t.Fatal("an entry with a later deadline was evicted")
	}
}

func TestKeyCapHolds(t *testing.T) {
	const cap = 4 * shardCount
	b := newArena(t, Options{Bytes: 1 << 20, MaxKeys: cap, ExpireInterval: time.Hour})
	for i := range 20 * cap {
		_ = b.Set(ctx, key(i), val(i, 16), time.Minute)
		if n := b.Len(); n > cap {
			t.Fatalf("Len = %d over the cap %d", n, cap)
		}
	}
	if b.Len() < cap/2 {
		t.Fatalf("Len = %d, far under the cap", b.Len())
	}
}

func TestTooLarge(t *testing.T) {
	b := newArena(t, Options{Bytes: 256})
	if err := b.Set(ctx, key(1), make([]byte, 256), time.Minute); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Set = %v, want ErrTooLarge", err)
	}
	if l := b.Lease(make([]byte, 256)); l.Buf != nil {
		t.Fatal("Lease of a value larger than the block succeeded")
	}
	if err := b.Set(ctx, key(1), make([]byte, 200), time.Minute); err != nil {
		t.Fatal(err)
	}
}

// A record that does not fit the end of the block starts at its beginning.
func TestRecordDoesNotStraddleTheEnd(t *testing.T) {
	b := newArena(t, Options{Bytes: 1000})
	for i := range 50 {
		if err := b.Set(ctx, key(i), val(i, 300), time.Minute); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mustGet(t, b, key(i)), val(i, 300)) {
			t.Fatalf("entry %d not read back", i)
		}
	}
}

func inBlock(b *Backend, p []byte) bool {
	for i := range b.buf {
		if &b.buf[i] == &p[0] {
			return true
		}
	}
	return false
}

func TestLeaseCommit(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	src := val(5, 200)
	l := b.Lease(src)
	if l.Buf == nil || !bytes.Equal(l.Buf, src) {
		t.Fatal("lease does not hold the value")
	}
	if !inBlock(b, l.Buf) {
		t.Fatal("leased bytes are not in the block")
	}
	if mustGet(t, b, key(5)) != nil {
		t.Fatal("leased value visible before commit")
	}
	if err := b.Commit(ctx, key(5), l, time.Minute); err != nil {
		t.Fatal(err)
	}
	b.Release(l)
	if !bytes.Equal(mustGet(t, b, key(5)), src) {
		t.Fatal("committed value not read back")
	}
	if err := b.Commit(ctx, key(6), Lease{}, time.Minute); err == nil {
		t.Fatal("commit of an empty lease succeeded")
	}
	b.Release(Lease{}) // no-op
}

func TestLeaseLongKeyIsCopied(t *testing.T) {
	b := newArena(t, Options{Bytes: 4096})
	long := bytes.Repeat([]byte("k"), leaseKeyRoom+1)
	l := b.Lease(val(1, 100))
	if err := b.Commit(ctx, long, l, time.Minute); err != nil {
		t.Fatal(err)
	}
	b.Release(l)
	if !bytes.Equal(mustGet(t, b, long), val(1, 100)) {
		t.Fatal("value under a long key not read back")
	}
}

// A leased value is not overwritten: writes that would need its space are
// refused until it is released.
func TestLeasePinsItsBytes(t *testing.T) {
	b := newArena(t, Options{Bytes: 1024})
	src := val(1, 100)
	l := b.Lease(src)
	var refused error
	for i := range 20 {
		if err := b.Set(ctx, key(i), val(i, 100), time.Minute); err != nil {
			refused = err
			break
		}
	}
	if !errors.Is(refused, ErrBusy) {
		t.Fatalf("writes around a full block = %v, want ErrBusy", refused)
	}
	if l2 := b.Lease(val(2, 100)); l2.Buf != nil {
		t.Fatal("a second lease took the first one's space")
	}
	if !bytes.Equal(l.Buf, src) {
		t.Fatal("leased bytes were overwritten")
	}
	if err := b.Commit(ctx, key(100), l, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustGet(t, b, key(100)), src) {
		t.Fatal("committed value not read back")
	}
	b.Release(l)
	b.Release(l) // a second release changes nothing
	for i := range 20 {
		if err := b.Set(ctx, key(i), val(i, 100), time.Minute); err != nil {
			t.Fatalf("write %d after release: %v", i, err)
		}
	}
	if mustGet(t, b, key(100)) != nil {
		t.Fatal("released entry survived a lap")
	}
}

// Leases released out of order: the block stays pinned at the oldest one.
func TestLeasesReleasedOutOfOrder(t *testing.T) {
	b := newArena(t, Options{Bytes: 1024})
	a, c := b.Lease(val(1, 100)), b.Lease(val(2, 100))
	b.Release(c)
	fill := func() error {
		for i := range 20 {
			if err := b.Set(ctx, key(i), val(i, 100), time.Minute); err != nil {
				return err
			}
		}
		return nil
	}
	if err := fill(); !errors.Is(err, ErrBusy) {
		t.Fatalf("fill with the oldest lease out = %v, want ErrBusy", err)
	}
	if !bytes.Equal(a.Buf, val(1, 100)) {
		t.Fatal("oldest lease overwritten")
	}
	b.Release(a)
	if err := fill(); err != nil {
		t.Fatalf("fill after both released: %v", err)
	}
}

func TestLeaseTableFull(t *testing.T) {
	b := newArena(t, Options{Bytes: 1 << 20, MaxLeases: 3}) // rounds up to 4
	var held []Lease
	for range 4 {
		l := b.Lease(val(1, 16))
		if l.Buf == nil {
			t.Fatal("lease refused under the limit")
		}
		held = append(held, l)
	}
	if l := b.Lease(val(1, 16)); l.Buf != nil {
		t.Fatal("lease granted over the limit")
	}
	if n := b.Leased(); n != 4 {
		t.Fatalf("Leased = %d, want 4", n)
	}
	b.Release(held[0])
	if l := b.Lease(val(1, 16)); l.Buf == nil {
		t.Fatal("lease refused after a release")
	}
}

// Writers, leasers and readers at once on a block small enough to lap all
// the time (run with -race): a hit is always the key's own value.
func TestConcurrentUse(t *testing.T) {
	b := newArena(t, Options{Bytes: 64 << 10, MaxKeys: 2048})
	const writers, per, n = 4, 4000, 120
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range per {
				id := w*per + i
				if i%2 == 0 {
					_ = b.Set(ctx, key(id), val(id, n), time.Minute)
					continue
				}
				l := b.Lease(val(id, n))
				if l.Buf == nil {
					continue
				}
				if !bytes.Equal(l.Buf, val(id, n)) {
					t.Errorf("lease %d changed under its holder", id)
				}
				_ = b.Commit(ctx, key(id), l, time.Minute)
				b.Release(l)
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for i := range writers * per {
				got, _ := b.Get(ctx, key(i))
				if got != nil && !bytes.Equal(got, val(i, n)) {
					t.Errorf("Get(%d) returned other bytes", i)
					return
				}
				if i%64 == 0 {
					_, _ = b.SetNX(ctx, key(i), val(i, n), time.Minute)
					_ = b.Del(ctx, key(i+1))
				}
			}
		})
	}
	wg.Wait()
}

func TestCloseIdempotent(t *testing.T) {
	b := newArena(t, Options{Bytes: 1024})
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if !b.Healthy(ctx) || b.Bytes() != 1024 {
		t.Fatal("Healthy or Bytes")
	}
}
