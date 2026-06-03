package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/lightwebinc/shard-common/cache"
	"github.com/lightwebinc/shard-common/cache/memory"
	"github.com/lightwebinc/shard-common/cache/redis"
)

// conformance exercises the Backend contract shared by every implementation.
func conformance(t *testing.T, b cache.Backend) {
	t.Helper()
	ctx := context.Background()
	key := []byte("k1")
	val := []byte("hello")

	// Miss returns (nil, nil).
	if got, err := b.Get(ctx, key); err != nil || got != nil {
		t.Fatalf("Get miss = (%v, %v), want (nil, nil)", got, err)
	}

	// SetNX on absent key creates it.
	if won, err := b.SetNX(ctx, key, val, time.Minute); err != nil || !won {
		t.Fatalf("SetNX absent = (%v, %v), want (true, nil)", won, err)
	}
	// SetNX again loses.
	if won, err := b.SetNX(ctx, key, []byte("other"), time.Minute); err != nil || won {
		t.Fatalf("SetNX present = (%v, %v), want (false, nil)", won, err)
	}
	// Value is the first writer's.
	if got, err := b.Get(ctx, key); err != nil || string(got) != "hello" {
		t.Fatalf("Get after SetNX = (%q, %v), want (hello, nil)", got, err)
	}

	// Set overwrites unconditionally.
	if err := b.Set(ctx, key, []byte("v2"), time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, _ := b.Get(ctx, key); string(got) != "v2" {
		t.Fatalf("Get after Set = %q, want v2", got)
	}

	// Del removes.
	if err := b.Del(ctx, key); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if got, _ := b.Get(ctx, key); got != nil {
		t.Fatalf("Get after Del = %q, want nil", got)
	}

	if !b.Healthy(ctx) {
		t.Fatalf("Healthy = false, want true")
	}
}

func TestMemoryBackend(t *testing.T) {
	b := memory.New(0)
	defer func() { _ = b.Close() }()
	conformance(t, b)
}

func TestMemoryExpiry(t *testing.T) {
	b := memory.New(0)
	defer func() { _ = b.Close() }()
	ctx := context.Background()
	if _, err := b.SetNX(ctx, []byte("e"), []byte("x"), 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if got, _ := b.Get(ctx, []byte("e")); got != nil {
		t.Fatalf("expired Get = %q, want nil", got)
	}
	// Expired key is re-claimable.
	if won, _ := b.SetNX(ctx, []byte("e"), []byte("y"), time.Minute); !won {
		t.Fatalf("SetNX after expiry = false, want true")
	}
}

func TestRedisBackend(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()

	b, err := redis.New(redis.Options{Addr: mr.Addr()})
	if err != nil {
		t.Fatalf("redis.New: %v", err)
	}
	defer func() { _ = b.Close() }()
	conformance(t, b)
}

func TestOpen(t *testing.T) {
	ctx := context.Background()

	// none → nil backend, no error.
	b, err := cache.Open(ctx, cache.Config{Backend: cache.BackendNone})
	if err != nil || b != nil {
		t.Fatalf("Open(none) = (%v, %v), want (nil, nil)", b, err)
	}

	// memory → usable backend.
	b, err = cache.Open(ctx, cache.Config{Backend: cache.BackendMemory})
	if err != nil || b == nil {
		t.Fatalf("Open(memory) = (%v, %v), want (backend, nil)", b, err)
	}
	defer func() { _ = b.Close() }()

	// unknown → error.
	if _, err := cache.Open(ctx, cache.Config{Backend: "bogus"}); err == nil {
		t.Fatalf("Open(bogus) = nil error, want error")
	}

	// redis without addr → error.
	if _, err := cache.Open(ctx, cache.Config{Backend: cache.BackendRedis}); err == nil {
		t.Fatalf("Open(redis, no addr) = nil error, want error")
	}
}
