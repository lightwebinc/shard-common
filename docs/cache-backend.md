# Modular Cache Backend

This document is the canonical reference for the pluggable cache backend used
by the cache-enabled components: **shard-proxy**, **shard-listener**, and
**retry-endpoint**. Everything else (per-repo `docs/configuration.md`, Helm
`values.yaml`, deployment tooling) links here. The backend is opt-in per
service; see [Adoption](#adoption) for the defaults.

## Motivation

Two caching surfaces share one primitive, **TTL'd key-value with an atomic
create-only operation**:

| Surface | Access pattern | Components |
|---------|----------------|------------|
| Dedup / claim store | `SetNX(key, ttl) → won?` + async `Mark` | proxy ingress, listener egress + courtesy mark (`shard-common/txidset` tier-2) |
| Frame KV cache | `Store / Retrieve / Delete` (+ SetNX dedup) | retry-endpoint |

One backend interface serves both, so operators choose the substrate per
deployment (single Redis for small fabrics; a horizontally scaled store for
large ones) without touching component code.

## The interface: `shard-common/cache`

```go
type Backend interface {
    SetNX(ctx, key, val []byte, ttl time.Duration) (bool, error) // atomic create-only
    Set(ctx, key, val []byte, ttl time.Duration) error           // unconditional write
    Get(ctx, key []byte) ([]byte, error)                         // (nil,nil) on miss
    Del(ctx, key []byte) error
    Healthy(ctx) bool   // cold-path /readyz probe; never on the hot path
    Close() error
}
```

- **Keys/values are opaque `[]byte`.** Callers own namespacing; backends apply
  no prefixes. Key shapes: `bsp:tx:`, `bsl:egr:…`, `bre:frame:`, `bre:dedup:`.
- **Miss is `(nil, nil)`, never an error.**
- **Fail-open contract.** Dedup callers treat a `SetNX` error as *proceed*; the
  frame store treats `Get`/`Set` errors as a miss. A backend outage must never
  stop frames from forwarding.

Construction is via `cache.Open(ctx, cache.Config)` (fail-closed: dials and
verifies redis/aerospike, returns an error rather than a degraded backend).
`Config.Backend` selects `memory | redis | aerospike | none`.

## Shipped backends

| Backend | Package | SetNX | TTL | Use case |
|---------|---------|-------|-----|----------|
| `memory` | `cache/memory` | per-process map (striped, 64 shards) | sub-second OK | dev/CI; per-instance retry frame store |
| `redis` | `cache/redis` | `SET NX EX` | sub-second OK | **default for scale-up**; any Redis-protocol server |
| `aerospike` | `cache/aerospike` | `CREATE_ONLY` write | **whole seconds, floor 1s** | largest fleets; auto-sharded, hybrid RAM/SSD |
| `none` | n/a | n/a | n/a | tier-1 LRU only (dedup); rejected by the frame store |

### Memory backend

`cache/memory` stripes the keyspace across 64 independently locked shards.
Each shard keeps one FIFO expiry queue per distinct TTL: entries written with
the same TTL expire in write order, so expiring a queue pops a prefix and the
work is proportional to the entries that expire, never a scan of the map. A
background expirer runs every 250 ms and each write pops a few expired heads,
so an expired entry is removed within about one interval of its deadline;
`Get` never returns an expired value.

With a key cap (`-cache-memory-max-keys`, or the consumer's own cap flag) each
shard holds at most cap/64 entries (at least one). A write of a new key into a
full shard first expires what it can, then evicts the entry with the earliest
deadline, so no entry is evicted while one that expires sooner remains in its
shard. Entries that never expire are evicted only when the shard holds no
TTL'd entry, least recently written first.

Callers use a handful of fixed TTLs. Each distinct TTL opens a queue that
expiry and eviction must visit, so deriving a distinct TTL per write would
defeat the design.

### Redis backend covers more than Redis

The `redis` backend speaks the Redis wire protocol, so it targets **Redis,
Valkey, Dragonfly, or a Redis Cluster by address alone**, with no code change:

- **Valkey** (BSD-licensed Redis fork): drop-in.
- **Dragonfly**: multi-threaded, scales vertically far past single-thread Redis.
- **Redis Cluster**: horizontal sharding; all operations here are single-key,
  so cluster slot routing is transparent.

### Aerospike Community Edition constraints

- **TTL granularity is whole seconds, floor 1s.** Sub-second TTLs are not
  representable. Every TTL in this stack (dedup 10m/60s, frame caches 60s–10m,
  retransmit dedup-window 60s) satisfies this; the backend rounds up to the
  second.
- **Requires an operator-provisioned namespace** (`-aerospike-namespace`,
  default `cache`). CE has **no XDR / rack-awareness**; for multi-region
  replication use a Redis-compatible backend or Aerospike Enterprise.
- A shared Aerospike frame store also **raises retry-endpoint cache-hit ratio**:
  frames become cross-instance instead of per-pod.

### Backends evaluated but not shipped

- **memcached** (`add` = SetNX, native TTL): viable lightweight dedup-only
  option; client-sharded, no persistence. A backend could be added if demand
  appears.
- **ScyllaDB / Cassandra** LWT (`IF NOT EXISTS`): Paxos per claim is too costly
  for the hot dedup gate. Not recommended.
- **NATS JetStream KV**: weaker high-rate SetNX semantics. Not recommended.

## Performance: no hot-path detriment

The per-packet dedup gate (proxy ingress, listener egress) is served by the
**tier-1 in-process LRU inside `txidset`**, which is *not* behind `Backend`. A
`Backend` call happens only on a tier-1 miss (a novel TxID). `txidset` is
consumed through an interface (`forwarder.TxidDedup`), so the backend adds no
dispatch on the hot path.

Benchmarks (`shard-common/txidset/bench_test.go`):

```
BenchmarkClaimLocalHit-12     151.8 ns/op   0 B/op   0 allocs/op   # tier-1 hit, no backend touched
BenchmarkClaimLocalMiss-12    328.7 ns/op   0 B/op   0 allocs/op   # tier-1 insert, local-only mode
```

The tier-1 hit path is allocation-free and never reaches the backend. Backend
method signatures take `[]byte` so dedup callers add no conversions; the
`prefix + hex(txid)` allocation is on the cold (miss) path.

## Per-component wiring

| Component | Surface | Store(s) | Config prefix |
|-----------|---------|----------|---------------|
| shard-proxy | ingress dedup | one `txidset.Store` (`bsp:tx:`) | `-txid-dedup-*` |
| shard-listener | egress dedup + courtesy ingress mark | two `txidset.Store` (`bsl:egr:…`, `bsp:tx:`) | `-egress-dedup-*`, `-ingress-set-*` |
| retry-endpoint | frame cache + retransmit dedup | `cache.Store` adapter over one `Backend` (`bre:frame:`, `bre:dedup:`) | `-cache-backend`, `-redis-addr`, `-aerospike-*` |

- `txidset.Config.Backend` carries the tier-2 `cache.Backend`. The deprecated
  `RedisAddr` field builds an internal redis backend when `Backend` is nil.
- The listener's two stores are addressed independently; either may use a
  different backend or endpoint.
- The retry endpoint reuses one backend for both the frame store and the
  cross-instance dedup gate (distinct prefixes) when the backend is
  redis/aerospike. With `memory` frames, a separate `-redis-addr` still enables
  the dedup gate.

## Configuration

Flags (each with an UPPERCASE env-var equivalent) are documented in each
consumer's configuration reference:

- shard-proxy (`-txid-dedup-*`):
  [Ingress TxID dedup](https://github.com/lightwebinc/shard-proxy/blob/main/docs/configuration.md#ingress-txid-dedup)
- shard-listener (`-egress-dedup-*`, `-ingress-set-*`):
  [Cross-Listener TxID Deduplication](https://github.com/lightwebinc/shard-listener/blob/main/docs/configuration.md#cross-listener-txid-deduplication)
- retry-endpoint (`-cache-backend`, `-redis-addr`, `-aerospike-*`, `-cache-*-timeout`):
  [Cache](https://github.com/lightwebinc/retry-endpoint/blob/main/docs/configuration.md#cache)

## Adoption

Defaults: the proxy and listener run with no tier-2 backend (tier-1 LRU only);
the retry endpoint defaults to `memory`. Aerospike adopters provision the
namespace and set `-cache-backend=aerospike` / `*-backend=aerospike`.

## Cross-repo surfaces

- **Go services**: `shard-proxy`, `shard-listener`, `retry-endpoint`: flags +
  each repo's own `docs/configuration.md` + `docs/architecture.md` notes (not
  shard-common's `docs/`).
- **shard-common**: `cache` package + README packages table.
- **Helm charts** ([lightwebinc/charts](https://github.com/lightwebinc/charts/tree/main/charts)):
  `charts/retry-endpoint` (`cacheBackend` + `aerospike*`), `charts/shard-proxy`
  (`txidDedup.backend` + `aerospike*`), `charts/shard-listener`
  (`egressDedup*` / `ingressSet*` backend + `aerospike*`): `values.yaml`,
  `values.schema.json` enums, and README values reference. Operators passing
  comma-separated `aerospikeHosts` via `--set` must escape commas.
- **Deployment tooling**: automation that renders service config should
  template the same flags/env vars per host or workload, and provision the
  chosen backend (e.g. an Aerospike namespace) alongside the services.
