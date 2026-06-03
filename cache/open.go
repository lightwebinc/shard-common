package cache

import (
	"context"
	"fmt"

	"github.com/lightwebinc/shard-common/cache/aerospike"
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
func Open(_ context.Context, cfg Config) (Backend, error) {
	switch cfg.Backend {
	case BackendNone, "":
		return nil, nil
	case BackendMemory:
		return memory.New(cfg.MemoryMaxKeys), nil
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
