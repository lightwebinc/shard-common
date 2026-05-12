# bitcoin-shard-common

[![CI](https://github.com/lightwebinc/bitcoin-shard-common/actions/workflows/ci.yml/badge.svg)](https://github.com/lightwebinc/bitcoin-shard-common/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lightwebinc/bitcoin-shard-common)](https://github.com/lightwebinc/bitcoin-shard-common/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/lightwebinc/bitcoin-shard-common.svg)](https://pkg.go.dev/github.com/lightwebinc/bitcoin-shard-common)
[![Go Report Card](https://goreportcard.com/badge/github.com/lightwebinc/bitcoin-shard-common)](https://goreportcard.com/report/github.com/lightwebinc/bitcoin-shard-common)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Shared protocol primitives for the BSV transaction sharding pipeline. Imported
by `bitcoin-shard-proxy`, `bitcoin-shard-listener`, `bitcoin-retry-endpoint`,
and `bitcoin-subtx-generator`.

## Packages

| Package    | Purpose                                                                 |
| ---------- | ----------------------------------------------------------------------- |
| `frame`    | BRC-12/BRC-124 wire format codec; BRC-127 SubtreeAnnounce codec        |
| `shard`    | TxID → IPv6 multicast group derivation (consistent-hash); control groups |
| `seqhash`  | XXH64 hash chain for PrevSeq/CurSeq stamping                           |
| `sequence` | Per-shard monotonic counters (`sync/atomic`, zero-alloc)                |

## Documentation

- [Wire Protocol Specification](docs/protocol.md) — BRC-124 frame format, legacy v1, shard derivation, proxy forward rules

## Requirements

- Go 1.25 or later

## Build

```bash
go build ./...
go test ./...
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
