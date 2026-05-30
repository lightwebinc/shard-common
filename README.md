# shard-common

[![CI](https://github.com/lightwebinc/shard-common/actions/workflows/ci.yml/badge.svg)](https://github.com/lightwebinc/shard-common/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lightwebinc/shard-common)](https://github.com/lightwebinc/shard-common/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/lightwebinc/shard-common.svg)](https://pkg.go.dev/github.com/lightwebinc/shard-common)
[![Go Report Card](https://goreportcard.com/badge/github.com/lightwebinc/shard-common)](https://goreportcard.com/report/github.com/lightwebinc/shard-common)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Shared protocol primitives for the BSV transaction sharding pipeline. Imported
by `shard-proxy`, `shard-listener`, `retry-endpoint`, `subtx-generator`, and
`shard-manifest`.

## Packages

| Package    | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `frame`    | Wire format codec: BRC-12/124/128 frames, BRC-127 announce, BRC-130 fragments, BRC-131 blocks, BRC-132 subtree data, BRC-134 anchor txs, BRC-135 block headers, BRC-137 shard manifest |
| `shard`    | TxID → IPv6 multicast group derivation (consistent-hash); control groups |
| `seqhash`  | XXH64 per-flow HashKey computation                                      |
| `sequence` | Per-shard monotonic counters (`sync/atomic`, zero-alloc)                |
| `txidset`  | Two-tier TxID dedup (LRU + optional Redis SETNX); fail-open on Redis errors |
| `netjoin`  | IPv6 multicast `Join`/`Leave` — branches `IPV6_JOIN_GROUP` (ASM) and `MCAST_JOIN_SOURCE_GROUP` (SSM, RFC 3678) by source-list presence; token-bucket `Limiter` and `Jitter` helper for cold-start storm protection at scale. Powers the SSM join sites in every receiver. |
| `bootstrap`| DNS-resolving source-set tracker for SSM `(S,G)` bootstrap lists: fail-closed startup, last-good retention on refresh failures, diff-callback for join/leave plumbing. |

The `shard` package also exposes the SSM addressing helpers: `SourceMode`
(asm|ssm), `Scope` (site|global), and `Prefix(mode, scope)` which yields
`FF05` (ASM site), `FF35` (SSM site), `FF3E` (SSM global) and rejects ASM
at global scope per RFC 8815.

The `frame.ShardManifest` codec implements BRC-137's SSM extensions:
`Flags.SourceModeSSM` (bit 3), `Flags.SourcesValid` (bit 4), `SourceCount`
at bytes [42:44], and the trailing `SourceCount × 16`-byte sources
payload appended after the groups payload. See the
[SSM Support Plan](https://github.com/lightwebinc/bsv-multicast/blob/main/docs/SourceSpecificMulticast/ssm-support-plan.md)
for the system-level design.

## Documentation

- [Wire Protocol Specification](docs/protocol.md) — BRC-124/BRC-128 frame format, legacy BRC-12, shard derivation, proxy forward rules

## Requirements

- Go 1.25 or later

## Build

```bash
go build ./...
go test ./...
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
