// Package cache defines a modular, TTL'd key-value backend with an atomic
// create-only operation (SetNX). It is the shared substrate for the two
// caching surfaces in the multicast stack:
//
//   - Dedup / claim stores — the proxy ingress gate and the listener egress
//     gate (via shard-common/txidset) use SetNX as the cross-instance "who
//     forwards this TxID" race. The hot path is short-circuited by an
//     in-process tier-1 LRU inside txidset; a Backend is consulted only on a
//     tier-1 miss (a novel TxID), so backend latency never touches the
//     per-packet steady state.
//
//   - Frame KV cache — the retry-endpoint stores raw frames keyed by
//     HashKey||SeqNum (Set), serves them on NACK (Get), and dedups
//     retransmissions (SetNX).
//
// # Backend selection
//
// Backends are chosen at runtime via [Config.Backend] and constructed with
// [Open]. The interface is deliberately minimal so that Redis-compatible
// servers (Redis, Valkey, Dragonfly, Redis Cluster) work through the single
// "redis" backend by address alone, while "aerospike" targets the Aerospike
// Community Edition client for the largest fleets.
//
// # Fail-open contract
//
// Dedup callers treat a SetNX error as "proceed" (fail-open): a backend
// outage must never stop frames from forwarding. Backends therefore use
// short per-op timeouts and surface errors rather than blocking. The
// retry-endpoint frame store treats Get/Set errors as cache misses for the
// same reason.
package cache

import (
	"context"
	"time"
)

// Backend is a TTL'd key-value store with an atomic create-only operation.
//
// All methods are safe for concurrent use. Keys and values are opaque byte
// slices; callers own namespacing (prefixes are not applied by the backend).
// A missing key is reported as (nil, nil) by Get — never as an error.
type Backend interface {
	// SetNX atomically creates key=val with the given ttl iff key is absent.
	//
	//   - (true, nil)  — created; the caller won the race (proceed / forward).
	//   - (false, nil) — key already existed; another claimant holds it (suppress).
	//   - (_, err)     — backend error; dedup callers fail open and proceed.
	//
	// ttl <= 0 means "no expiry" where the backend supports it.
	SetNX(ctx context.Context, key, val []byte, ttl time.Duration) (bool, error)

	// Set unconditionally writes key=val with the given ttl, overwriting any
	// existing value. ttl <= 0 means "no expiry" where supported.
	Set(ctx context.Context, key, val []byte, ttl time.Duration) error

	// Get returns the value stored under key, or (nil, nil) on miss/expiry.
	Get(ctx context.Context, key []byte) ([]byte, error)

	// Del removes key. Removing an absent key is not an error.
	Del(ctx context.Context, key []byte) error

	// Healthy is a cold-path readiness probe (/readyz). It must not be called
	// on the hot path. In-memory backends always report true.
	Healthy(ctx context.Context) bool

	// Close releases any resources (connections, background sweepers).
	Close() error
}

// Backend kind identifiers accepted by [Config.Backend] and [Open].
const (
	// BackendMemory is a per-process in-memory store: zero infrastructure,
	// used for dev/CI and for per-instance frame storage in the retry
	// endpoint. It provides no cross-instance coordination.
	BackendMemory = "memory"

	// BackendRedis targets any Redis-protocol server (Redis, Valkey,
	// Dragonfly, Redis Cluster) via go-redis. SetNX maps to SET NX EX.
	BackendRedis = "redis"

	// BackendAerospike targets an Aerospike Community Edition cluster. SetNX
	// maps to a CREATE_ONLY write; TTL granularity is whole seconds (floor 1s).
	BackendAerospike = "aerospike"

	// BackendNone disables the backend entirely. Dedup stores fall back to
	// tier-1 local LRU only (per-process, no cross-instance coordination);
	// the retry frame store cannot run with BackendNone and rejects it.
	BackendNone = "none"
)
