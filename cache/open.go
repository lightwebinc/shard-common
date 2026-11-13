package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/lightwebinc/shard-common/cache/aerospike"
	"github.com/lightwebinc/shard-common/cache/arena"
	"github.com/lightwebinc/shard-common/cache/memory"
	"github.com/lightwebinc/shard-common/cache/redis"
)

// Open constructs the [Backend] selected by cfg.Backend. It is fail-closed:
// for the redis and aerospike backends it dials and verifies connectivity,
// returning an error rather than a degraded backend. Callers that want
// fail-open boot (run with tier-1 LRU only when the backend is down) should
// catch the error and fall back to BackendNone themselves.
//
// BackendNone returns (nil, nil): the caller runs without a cross-instance
// backend (dedup on tier-1 LRU only). Frame-store callers must reject a nil
// backend.
// The in-memory backend keeps a handed-over value without a copy.
var _ OwnedSetter = (*memory.Backend)(nil)

// Lease is a value held in a backend's own memory before it has a key.
type Lease = arena.Lease

// Leaser is an optional extension of [Backend] for callers that receive a
// value before they know its key: Lease copies the value into the backend's
// memory, Commit stores it under a key without a second copy, and Release
// ends the caller's use of the leased bytes. Lease returns an empty Lease
// (nil Buf) when the backend cannot take the value now; the caller then
// falls back to Set. Every non-empty lease is released exactly once,
// committed or not, and committed at most once. The arena backend
// implements it; callers type-assert.
type Leaser interface {
	Lease(val []byte) Lease
	Commit(ctx context.Context, key []byte, l Lease, ttl time.Duration) error
	Release(l Lease)
}

var _ Leaser = (*arena.Backend)(nil)

func Open(_ context.Context, cfg Config) (Backend, error) {
	switch cfg.Backend {
	case BackendNone, "":
		return nil, nil
	case BackendMemory:
		if cfg.MemoryArenaBytes > 0 {
			return arena.New(arena.Options{Bytes: cfg.MemoryArenaBytes, MaxKeys: cfg.MemoryMaxKeys})
		}
		return memory.NewWithOptions(memory.Options{MaxKeys: cfg.MemoryMaxKeys, MaxBytes: cfg.MemoryMaxBytes}), nil
	case BackendRedis:
		return redis.New(redis.Options{
			Addr:        cfg.RedisAddr,
			DialTimeout: cfg.DialTimeout,
			OpTimeout:   cfg.OpTimeout,
		})
	case BackendAerospike:
		return aerospike.New(aerospike.Options{
			Hosts:       cfg.AeroHosts,
			Namespace:   cfg.AeroNamespace,
			Set:         cfg.AeroSet,
			DialTimeout: cfg.DialTimeout,
			OpTimeout:   cfg.OpTimeout,
		})
	default:
		return nil, fmt.Errorf("cache: unknown backend %q (want memory|redis|aerospike|none)", cfg.Backend)
	}
}
