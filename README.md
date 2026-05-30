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
