package memory

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

// keysInShard returns n distinct keys that hash to shard idx of b.
func keysInShard(b *Backend, idx, n int) [][]byte {
	var keys [][]byte
	for i := 0; len(keys) < n; i++ {
		k := []byte(fmt.Sprintf("key-%d", i))
		if b.shardFor(k) == &b.shards[idx] {
			keys = append(keys, k)
		}
	}
	return keys
}

func mustSet(t *testing.T, b *Backend, key []byte, val string, ttl time.Duration) {
	t.Helper()
	if err := b.Set(ctx, key, []byte(val), ttl); err != nil {
		t.Fatalf("Set(%s): %v", key, err)
	}
}

func get(b *Backend, key []byte) string {
	v, _ := b.Get(ctx, key)
	return string(v)
}

// wantPresent fails unless exactly the keys marked true are present.
func wantPresent(t *testing.T, b *Backend, keys [][]byte, present ...bool) {
	t.Helper()
	for i, k := range keys {
		if got := get(b, k) != ""; got != present[i] {
			t.Errorf("key %s present = %v, want %v", k, got, present[i])
		}
	}
}

// checkInvariants verifies each shard's bookkeeping: the item count, TTL
// queues sorted by deadline, and a current item for every entry.
func checkInvariants(t *testing.T, b *Backend) {
	t.Helper()
	for i := range b.shards {
		s := &b.shards[i]
		s.mu.Lock()
		current := make(map[string]bool)
		items := 0
		for _, q := range append([]*queue{&s.forever}, s.ttlQueues...) {
			items += q.len()
			for j := q.head; j < len(q.items); j++ {
				if q != &s.forever && j > q.head && q.items[j].deadline < q.items[j-1].deadline {
					t.Errorf("shard %d: ttl %v queue out of deadline order at %d", i, q.ttl, j)
				}
				if s.current(q.items[j]) {
					current[q.items[j].key] = true
				}
			}
		}
		if items != s.items {
			t.Errorf("shard %d: items = %d, queues hold %d", i, s.items, items)
		}
		for k := range s.data {
			if !current[k] {
				t.Errorf("shard %d: entry %q has no current queue item", i, k)
			}
		}
		s.mu.Unlock()
	}
}

// Entries leave the map within one expirer interval of their deadline, with
// no writes to pop them, and never before it.
func TestExpiryWithinOneInterval(t *testing.T) {
	const interval, ttl = 50 * time.Millisecond, 100 * time.Millisecond
	b := NewWithOptions(Options{ExpireInterval: interval})
	defer func() { _ = b.Close() }()

	start := time.Now()
	for i := 0; i < 100; i++ {
		mustSet(t, b, []byte(fmt.Sprint(i)), "v", ttl)
	}
	time.Sleep(ttl / 2)
	if n := b.Len(); n != 100 && time.Since(start) < ttl {
		t.Fatalf("Len = %d before the deadline, want 100", n)
	}
	// The scheduling slack keeps a loaded CI host from flaking the bound.
	limit := ttl + interval + 50*time.Millisecond
	for b.Len() > 0 {
		if el := time.Since(start); el > limit {
			t.Fatalf("%d entries remain %v after the deadline, want none within one %v interval", b.Len(), el-ttl, interval)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if el := time.Since(start); el < ttl {
		t.Fatalf("entries removed after %v, before their %v TTL", el, ttl)
	}
	checkInvariants(t, b)
}

// Get hides an expired entry even before the expirer removes it.
func TestGetHidesExpiredEntry(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := []byte("k")
	mustSet(t, b, k, "v", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if got := get(b, k); got != "" {
		t.Fatalf("Get after deadline = %q, want miss", got)
	}
	if n := b.Len(); n != 1 {
		t.Fatalf("Len = %d, want the expired entry still counted until removed", n)
	}
	b.expireAll()
	if n := b.Len(); n != 0 {
		t.Fatalf("Len after an expirer pass = %d, want 0", n)
	}
}

// An expired entry is re-claimable by SetNX, and the old write's queue item
// must not delete the new value when it is popped.
func TestSetNXOnExpiredEntry(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := []byte("claim")
	if won, _ := b.SetNX(ctx, k, []byte("a"), 10*time.Millisecond); !won {
		t.Fatal("SetNX on absent key lost")
	}
	if won, _ := b.SetNX(ctx, k, []byte("b"), time.Hour); won {
		t.Fatal("SetNX on live key won")
	}
	time.Sleep(20 * time.Millisecond)
	if won, _ := b.SetNX(ctx, k, []byte("c"), time.Hour); !won {
		t.Fatal("SetNX on expired key lost")
	}
	b.expireAll() // pops the first write's item
	if got := get(b, k); got != "c" {
		t.Fatalf("Get = %q after the old item was popped, want c", got)
	}
	checkInvariants(t, b)
}

// A rewrite moves the key's deadline: the earlier write's queue item must
// neither delete the new value nor keep the key alive past the new deadline.
func TestOverwriteAndRefresh(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: 5 * time.Millisecond})
	defer func() { _ = b.Close() }()
	refreshed, pinned, shortened := []byte("refreshed"), []byte("pinned"), []byte("shortened")

	mustSet(t, b, refreshed, "old", 20*time.Millisecond)
	mustSet(t, b, refreshed, "new", time.Hour)
	mustSet(t, b, pinned, "old", 20*time.Millisecond)
	mustSet(t, b, pinned, "new", 0) // now never expires
	mustSet(t, b, shortened, "old", time.Hour)
	mustSet(t, b, shortened, "new", 20*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	if got := get(b, refreshed); got != "new" {
		t.Errorf("refreshed key = %q, want new (old item deleted it?)", got)
	}
	if got := get(b, pinned); got != "new" {
		t.Errorf("key rewritten without a TTL = %q, want new", got)
	}
	if got := get(b, shortened); got != "" {
		t.Errorf("key rewritten with a shorter TTL = %q, want expired", got)
	}
	if n := b.Len(); n != 2 {
		t.Errorf("Len = %d, want 2", n)
	}
	checkInvariants(t, b)
}

// Rewriting a key within one clock tick keeps a single current item, so
// compaction can always clear what rewrites leave behind.
func TestRewriteWithinOneTick(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := []byte("k")
	s := b.shardFor(k)
	s.mu.Lock()
	now := monoNow()
	for i := byte(0); i < 3; i++ {
		prev, ok := s.data[string(k)]
		b.put(s, k, []byte{'a' + i}, time.Minute, now, prev, ok)
	}
	items := s.items
	s.mu.Unlock()
	if items != 1 {
		t.Fatalf("three rewrites in one tick queued %d items, want 1", items)
	}
	if got := get(b, k); got != "c" {
		t.Fatalf("Get = %q, want the last write", got)
	}
	checkInvariants(t, b)
}

// Each TTL class expires on its own deadline.
func TestMixedTTLs(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: 5 * time.Millisecond})
	defer func() { _ = b.Close() }()
	keys := [][]byte{[]byte("short"), []byte("hour"), []byte("medium"), []byte("never")}
	mustSet(t, b, keys[0], "v", 20*time.Millisecond)
	mustSet(t, b, keys[1], "v", time.Hour)
	mustSet(t, b, keys[2], "v", 400*time.Millisecond)
	mustSet(t, b, keys[3], "v", 0)

	time.Sleep(100 * time.Millisecond)
	wantPresent(t, b, keys, false, true, true, true)
	if n := b.Len(); n != 3 {
		t.Errorf("Len = %d after the short TTL, want 3", n)
	}
	time.Sleep(400 * time.Millisecond)
	wantPresent(t, b, keys, false, true, false, true)
	if n := b.Len(); n != 2 {
		t.Errorf("Len = %d after the medium TTL, want 2", n)
	}
	checkInvariants(t, b)
}

// At the cap the entry with the earliest deadline goes, never a fresher one.
func TestCapEvictsOldest(t *testing.T) {
	b := NewWithOptions(Options{MaxKeys: 2 * shardCount, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := keysInShard(b, 7, 4)
	other := keysInShard(b, 8, 1)
	mustSet(t, b, other[0], "v", time.Minute)

	mustSet(t, b, k[0], "v", time.Minute)
	mustSet(t, b, k[1], "v", time.Minute)
	mustSet(t, b, k[2], "v", time.Minute)
	wantPresent(t, b, k[:3], false, true, true)

	// Rewriting k[1] refreshes it past k[2]: the cap must now take k[2].
	mustSet(t, b, k[1], "v2", time.Minute)
	mustSet(t, b, k[3], "v", time.Minute)
	wantPresent(t, b, k, false, true, false, true)
	if got := get(b, other[0]); got == "" {
		t.Error("eviction reached into another shard")
	}
	checkInvariants(t, b)
}

// With mixed TTLs the cap takes the entry that would expire first, and an
// entry that never expires only once no entry with a TTL is left.
func TestCapEvictionOrder(t *testing.T) {
	b := NewWithOptions(Options{MaxKeys: 2 * shardCount, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := keysInShard(b, 3, 6)

	mustSet(t, b, k[0], "v", 10*time.Minute)
	mustSet(t, b, k[1], "v", time.Minute) // written later, expires sooner
	mustSet(t, b, k[2], "v", time.Hour)
	wantPresent(t, b, k[:3], true, false, true)

	b2 := NewWithOptions(Options{MaxKeys: 2 * shardCount, ExpireInterval: time.Hour})
	defer func() { _ = b2.Close() }()
	mustSet(t, b2, k[0], "v", 0)
	mustSet(t, b2, k[1], "v", time.Hour)
	mustSet(t, b2, k[2], "v", 0) // evicts k[1]: the only entry with a TTL
	wantPresent(t, b2, k[:3], true, false, true)
	mustSet(t, b2, k[3], "v", 0) // evicts k[0]: the oldest write
	wantPresent(t, b2, k[:4], false, false, true, true)
	mustSet(t, b2, k[2], "v2", 0) // rewriting k[2] moves it behind k[3]
	mustSet(t, b2, k[4], "v", 0)  // evicts k[3]
	wantPresent(t, b2, k[:5], false, false, true, false, true)
	checkInvariants(t, b)
	checkInvariants(t, b2)
}

// A full shard removes expired entries before it evicts a live one.
func TestCapExpiresBeforeEvicting(t *testing.T) {
	b := NewWithOptions(Options{MaxKeys: 2 * shardCount, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := keysInShard(b, 11, 3)
	mustSet(t, b, k[0], "v", 10*time.Millisecond)
	mustSet(t, b, k[1], "v", time.Hour)
	time.Sleep(20 * time.Millisecond)
	mustSet(t, b, k[2], "v", time.Hour)
	wantPresent(t, b, k, false, true, true)
	if n := b.Len(); n != 2 {
		t.Errorf("Len = %d, want 2", n)
	}
	checkInvariants(t, b)
}

// Writing many keys through a capped backend leaves each shard holding
// exactly its most recent writes.
func TestCapKeepsNewestPerShard(t *testing.T) {
	const per = 50
	b := NewWithOptions(Options{MaxKeys: per * shardCount, ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	written := make(map[*shard][]string)
	for i := 0; i < 400*shardCount; i++ {
		k := []byte(fmt.Sprintf("frame-%06d", i))
		mustSet(t, b, k, "v", time.Minute)
		s := b.shardFor(k)
		written[s] = append(written[s], string(k))
	}
	for s, keys := range written {
		cut := max(len(keys)-per, 0)
		for i, k := range keys {
			if got, want := get(b, []byte(k)) != "", i >= cut; got != want {
				t.Fatalf("shard write %d of %d (%s): present = %v, want %v", i, len(keys), k, got, want)
			}
		}
		if n := len(s.data); n != min(len(keys), per) {
			t.Fatalf("shard holds %d entries, want %d", n, min(len(keys), per))
		}
	}
	checkInvariants(t, b)
}

func TestDel(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: 5 * time.Millisecond})
	defer func() { _ = b.Close() }()
	k := []byte("k")
	if err := b.Del(ctx, k); err != nil {
		t.Fatalf("Del of absent key: %v", err)
	}
	mustSet(t, b, k, "v", 20*time.Millisecond)
	if err := b.Del(ctx, k); err != nil {
		t.Fatal(err)
	}
	if got := get(b, k); got != "" || b.Len() != 0 {
		t.Fatalf("after Del: Get = %q, Len = %d", got, b.Len())
	}
	// A key re-created after Del must survive the deleted write's item.
	mustSet(t, b, k, "again", time.Hour)
	time.Sleep(60 * time.Millisecond)
	if got := get(b, k); got != "again" {
		t.Fatalf("re-created key = %q, want again", got)
	}
	checkInvariants(t, b)
}

func TestLen(t *testing.T) {
	b := New(0)
	defer func() { _ = b.Close() }()
	for i := 0; i < 1000; i++ {
		mustSet(t, b, []byte(fmt.Sprint(i)), "v", time.Hour)
	}
	for i := 0; i < 1000; i += 2 {
		mustSet(t, b, []byte(fmt.Sprint(i)), "v2", 0) // rewrites add no entries
	}
	if n := b.Len(); n != 1000 {
		t.Fatalf("Len = %d, want 1000", n)
	}
	for i := 0; i < 250; i++ {
		_ = b.Del(ctx, []byte(fmt.Sprint(i)))
	}
	if n := b.Len(); n != 750 {
		t.Fatalf("Len after 250 Dels = %d, want 750", n)
	}
	checkInvariants(t, b)
}

func TestCloseIdempotent(t *testing.T) {
	b := New(0)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.done:
	default:
		t.Fatal("expirer still running after Close")
	}
	mustSet(t, b, []byte("k"), "v", time.Hour)
	if got := get(b, []byte("k")); got != "v" {
		t.Fatalf("Get after Close = %q, want v", got)
	}
}

// Stale items from rewrites or deletes cannot pile up in the queues, even in
// the forever queue, which the expirer never pops.
func TestStaleItemsCompacted(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	hot := []byte("hot")
	for i := 0; i < 100_000; i++ {
		mustSet(t, b, hot, "v", 0)
		mustSet(t, b, hot, "v", time.Hour)
		k := []byte(fmt.Sprintf("gone-%d", i))
		mustSet(t, b, k, "v", 0)
		_ = b.Del(ctx, k)
	}
	for i := range b.shards {
		s := &b.shards[i]
		if s.items > 2*len(s.data)+compactSlack {
			t.Errorf("shard %d holds %d queue items for %d entries", i, s.items, len(s.data))
		}
	}
	if got := get(b, hot); got != "v" {
		t.Fatalf("hot key = %q, want v", got)
	}
	checkInvariants(t, b)
}

// A TTL whose deadline overflows int64 nanoseconds never expires.
func TestHugeTTLNeverExpires(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	k := []byte("k")
	mustSet(t, b, k, "v", math.MaxInt64)
	b.expireAll()
	if got := get(b, k); got != "v" {
		t.Fatalf("Get = %q, want v", got)
	}
	if s := b.shardFor(k); s.forever.len() != 1 || len(s.ttlQueues) != 0 {
		t.Fatalf("overflowing TTL queued as expiring: forever=%d ttlQueues=%d", s.forever.len(), len(s.ttlQueues))
	}
}

// The expirer pops a shard's expired items in bounded batches, releasing
// the lock between them, until none remain.
func TestExpireInBatches(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	idx := 5
	for _, k := range keysInShard(b, idx, 10) {
		mustSet(t, b, k, "v", time.Millisecond)
	}
	time.Sleep(5 * time.Millisecond)
	s := &b.shards[idx]
	var passes []bool
	for more := true; more; {
		s.mu.Lock()
		more = s.expire(monoNow(), 3)
		s.mu.Unlock()
		passes = append(passes, more)
	}
	if len(passes) != 4 || len(s.data) != 0 {
		t.Fatalf("10 expired items took %d batches of 3 (%v), %d entries left", len(passes), passes, len(s.data))
	}

	for _, k := range keysInShard(b, idx, expireBatch+500) {
		mustSet(t, b, k, "v", 20*time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	b.expireAll()
	if n := b.Len(); n != 0 {
		t.Fatalf("Len = %d after an expirer pass over more than one batch", n)
	}
	checkInvariants(t, b)
}

// The expirer forgets a TTL queue once it drains.
func TestEmptyQueuesDropped(t *testing.T) {
	b := NewWithOptions(Options{ExpireInterval: time.Hour})
	defer func() { _ = b.Close() }()
	for i := 0; i < 100; i++ {
		mustSet(t, b, []byte(fmt.Sprint(i)), "v", time.Duration(1+i%3)*time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	b.expireAll()
	for i := range b.shards {
		if n := len(b.shards[i].ttlQueues); n != 0 {
			t.Fatalf("shard %d keeps %d drained queues", i, n)
		}
	}
	if n := b.Len(); n != 0 {
		t.Fatalf("Len = %d, want 0", n)
	}
}

// A drained burst gives its queue array back, keeping FIFO order and leaving
// no popped key referenced from the array.
func TestQueueShrinksAfterBurst(t *testing.T) {
	var q queue
	for i := 0; i < 100_000; i++ {
		q.push(item{key: fmt.Sprint(i), deadline: int64(i)})
	}
	for q.len() > 10 {
		q.pop()
	}
	if c := cap(q.items); c > queueShrinkCap {
		t.Fatalf("queue keeps cap %d for %d items", c, q.len())
	}
	for _, it := range q.items[len(q.items):cap(q.items)] {
		if it != (item{}) {
			t.Fatalf("array still references popped item %+v", it)
		}
	}
	for want := int64(100_000 - 10); q.len() > 0; want++ {
		if got := q.pop().deadline; got != want {
			t.Fatalf("pop = %d, want %d", got, want)
		}
	}
}

// Concurrent writers, readers and deleters against a small capped keyspace,
// with the expirer running often. Run with -race.
func TestConcurrentUse(t *testing.T) {
	b := NewWithOptions(Options{MaxKeys: 4 * shardCount, ExpireInterval: time.Millisecond})
	ttls := []time.Duration{0, time.Millisecond, 3 * time.Millisecond, time.Hour}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(seed, 1))
			for i := 0; i < 20_000; i++ {
				k := []byte(fmt.Sprint(rng.IntN(2000)))
				ttl := ttls[rng.IntN(len(ttls))]
				switch rng.IntN(4) {
				case 0:
					_ = b.Set(ctx, k, k, ttl)
				case 1:
					_, _ = b.SetNX(ctx, k, k, ttl)
				case 2:
					if v, _ := b.Get(ctx, k); v != nil && string(v) != string(k) {
						t.Errorf("Get(%s) = %s", k, v)
					}
				case 3:
					_ = b.Del(ctx, k)
				}
			}
		}(uint64(g))
	}
	wg.Wait()
	_ = b.Close()
	checkInvariants(t, b)
	for i := range b.shards {
		if n := len(b.shards[i].data); n > 4 {
			t.Errorf("shard %d holds %d entries, over its cap of 4", i, n)
		}
	}
}
