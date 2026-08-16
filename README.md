# shard-common

[![CI](https://github.com/lightwebinc/shard-common/actions/workflows/ci.yml/badge.svg)](https://github.com/lightwebinc/shard-common/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lightwebinc/shard-common)](https://github.com/lightwebinc/shard-common/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/lightwebinc/shard-common.svg)](https://pkg.go.dev/github.com/lightwebinc/shard-common)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

> Part of the [**BSV Layered Multicast**](https://github.com/lightwebinc/bsv-multicast) open-source project — see the main repository for the full architecture, design docs, and BRC specifications.

Shared protocol primitives for the BSV transaction sharding pipeline. Imported
by `shard-proxy`, `shard-listener`, `retry-endpoint`, `subtx-generator`,
`shard-manifest`, and `teranode-bridge`.

## Packages

| Package    | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `frame`    | Wire format codec: BRC-12/124/128 frames, BRC-127 announce, BRC-130 fragments, BRC-131 blocks, BRC-132 subtree data, BRC-134 anchor txs, BRC-135 block headers, BRC-139 shard manifest, BRC-142 bundle detection, BRC-148/149 BEEF object frames |
| `bundle`   | BRC-142 coalescing (bundle) frame codec (`Encode`/`Decode`, FrameVer `0x08`, 66-byte header) + `Coalescer` (pack), `Decoalesce` (split), `Rebucketer` (generation re-align). Packs many small txs of one `(group, subtree)` flow into one datagram — the inverse of BRC-130 fragmentation. |
| `objfmt`   | Push/bare object codecs for single-class lanes: `ClassTx` / `ClassSubtree` (BRC-143) / `ClassBlock` (BRC-144) / `ClassBEEF`; BEEF submission + delivery records (BRC-148/149) and the multicast frame wrap. |
| `shard`    | TxID → IPv6 multicast group derivation (consistent-hash); control groups; BRC-148 domain-partitioned object planes (DomainTx/DomainBEEF, TopicID-keyed BEEF-plane derivation) |
| `seqhash`  | XXH64 per-flow HashKey computation                                      |
| `sequence` | Per-shard monotonic counters (`sync/atomic`, zero-alloc)                |
| `pow`      | Stateless block-header proof-of-work gate: one double-SHA256 + big-int compare against the header's claimed target plus a configurable difficulty floor. Permissionless ingress spam filter — deliberately **not** full consensus validation (no chain context). |
| `cache`    | Modular TTL'd KV backend with atomic `SetNX` (create-only). Implementations: `memory`, `redis` (Redis/Valkey/Dragonfly/Cluster), `aerospike` (Community Edition). Shared by `txidset` (tier-2) and the retry-endpoint frame store. See [`docs/cache-backend.md`](docs/cache-backend.md). |
| `txidset`  | Two-tier TxID dedup: tier-1 in-process LRU (zero-alloc hot path) + optional tier-2 `cache.Backend` SETNX; fail-open on backend errors |
| `netjoin`  | IPv6 multicast `Join`/`Leave` — branches `IPV6_JOIN_GROUP` (ASM) and `MCAST_JOIN_SOURCE_GROUP` (SSM, RFC 3678) by source-list presence; token-bucket `Limiter` and `Jitter` helper for cold-start storm protection at scale. Powers the SSM join sites in every receiver. |
| `bootstrap`| DNS-resolving source-set tracker for SSM `(S,G)` bootstrap lists: fail-closed startup, last-good retention on refresh failures, diff-callback for join/leave plumbing. |
| `manifest` | BRC-139 auto-shard-config consumer: TTL-bounded `Registry` keyed on `(SrcIPv6, InstanceID)` and an `Evaluator` implementing the normative consumer profile (Authoritative quorum, hysteresis, ±1 ShardBits shift bound, manual-pin precedence, divergence telemetry, Successor-block adoption for live re-sharding). Powers proxy and listener auto-config when `-manifest-consumer-enabled` is set. |
| `logging`  | Unified structured-logging entrypoint for every binary: `Init` installs a process-wide `slog` default with the `service.{name,instance.id,version}` identity triple (shared with OTLP metrics) and returns a runtime `*slog.LevelVar`; `LevelHandler` (HTTP `/loglevel`), `InstallSIGHUPToggle`, and a `Throttle` (log-once-then-count) for the data-plane/error log-economy discipline. JSON→stdout, text→stderr. See [`docs/logging.md`](docs/logging.md). |
| `hostinfo` | One-shot host inventory (`Gather` → `host.inventory` log event): OS/kernel, CPU, memory, per-NIC facts incl. **both IPv4 and IPv6** addresses + link speed/driver (Linux sysfs), and the multicast-gating sysctls. Pure-Go (gopsutil); best-effort, never fails startup. |
| `tracing`  | Opt-in OpenTelemetry tracer for control-plane flows. `Init` returns a **no-op tracer when sampling ≤ 0 or no OTLP endpoint** (zero cost); otherwise an OTLP/gRPC exporter mirroring the metrics OTLP path. MUST NOT be wired into the packet hot path. |

The `shard` package also exposes the SSM addressing helpers: `SourceMode`
(asm|ssm), `Scope` (site|global), and `Prefix(mode, scope)` which yields
`FF05` (ASM site), `FF35` (SSM site), `FF3E` (SSM global) and rejects ASM
at global scope per RFC 8815.

The `frame.ShardManifest` codec implements BRC-139's SSM and
live-resharding extensions: `Flags.SourceModeSSM` (bit 3),
`Flags.SourcesValid` (bit 4), `Flags.PilotOnly` (bit 5),
`Flags.SuccessorValid` (bit 6), `SourceCount` at bytes [42:44], the
trailing `SourceCount × 16`-byte sources payload, and the 24-byte
`SuccessorBlock` carrying `(GenerationID, ShardBits, Flags, TransitionEpoch)`
for in-flight generation transitions. See the
[SSM Support Plan](https://github.com/lightwebinc/bsv-multicast/blob/main/DESIGN.md#source-specific-multicast-ssm)
and the
[Automatic Shard Configuration Plan](https://github.com/lightwebinc/bsv-multicast/blob/main/DESIGN.md#automatic-shard-configuration)
for the system-level designs.

## Documentation

- [Wire Protocol Specification](docs/protocol.md) — BRC-124/BRC-128 frame format, legacy BRC-12, BRC-142 coalescing (bundle) frame, shard derivation, proxy forward rules

## Requirements

- Go 1.25 or later

## Build

```bash
go build ./...
go test ./...
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
