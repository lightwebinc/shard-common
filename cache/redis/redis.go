// Package redis provides a Redis-protocol [cache.Backend]. It targets any
// server speaking the Redis wire protocol — Redis, Valkey, Dragonfly, or a
// Redis Cluster — selected by address alone. SetNX maps to SET NX EX.
//
// All operations use the per-op timeout configured at construction and a
// MaxRetries of -1, so dedup callers fail open quickly on a slow or
// unavailable server rather than blocking the hot path.
package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Backend is a Redis-protocol cache backend. Keys are used verbatim; callers
// own namespacing.
type Backend struct {
	client    *goredis.Client
	opTimeout time.Duration
}

// Options configures [New].
type Options struct {
	Addr        string
	DialTimeout time.Duration // <=0 → 200ms
	OpTimeout   time.Duration // <=0 → 50ms
}

// New dials addr and verifies connectivity with a bounded ping-retry window
// (tolerates a co-started Redis container). It returns an error on failure
// rather than degrading silently; callers wanting fail-open boot can fall
// back to the memory or none backend.
func New(opts Options) (*Backend, error) {
	if opts.Addr == "" {
		return nil, fmt.Errorf("redis: addr required")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 200 * time.Millisecond
	}
	if opts.OpTimeout <= 0 {
		opts.OpTimeout = 50 * time.Millisecond
	}
	client := goredis.NewClient(&goredis.Options{
		Addr:         opts.Addr,
		DialTimeout:  opts.DialTimeout,
		ReadTimeout:  opts.OpTimeout,
		WriteTimeout: opts.OpTimeout,
		MaxRetries:   -1, // fail open at the application layer
	})
	if err := pingWithRetry(client, 10*time.Second); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: ping %s: %w", opts.Addr, err)
	}
	return &Backend{client: client, opTimeout: opts.OpTimeout}, nil
}

// SetNX maps to SET key val NX EX ttl.
func (b *Backend) SetNX(ctx context.Context, key, val []byte, ttl time.Duration) (bool, error) {
	return b.client.SetNX(ctx, string(key), val, ttl).Result()
}

// Set maps to SET key val EX ttl.
func (b *Backend) Set(ctx context.Context, key, val []byte, ttl time.Duration) error {
	return b.client.Set(ctx, string(key), val, ttl).Err()
}

// Get returns the value, or (nil, nil) on miss.
func (b *Backend) Get(ctx context.Context, key []byte) ([]byte, error) {
	v, err := b.client.Get(ctx, string(key)).Bytes()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Del removes key.
func (b *Backend) Del(ctx context.Context, key []byte) error {
	return b.client.Del(ctx, string(key)).Err()
}

// Healthy pings the server with the configured op-timeout.
func (b *Backend) Healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, b.opTimeout)
	defer cancel()
	return b.client.Ping(ctx).Err() == nil
}

// Close releases the client connection pool.
func (b *Backend) Close() error { return b.client.Close() }

func pingWithRetry(c *goredis.Client, total time.Duration) error {
	deadline := time.Now().Add(total)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		lastErr = c.Ping(ctx).Err()
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return lastErr
}
