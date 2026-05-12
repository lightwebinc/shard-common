# bitcoin-shard-common

[![CI](https://github.com/lightwebinc/bitcoin-shard-common/actions/workflows/ci.yml/badge.svg)](https://github.com/lightwebinc/bitcoin-shard-common/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lightwebinc/bitcoin-shard-common)](https://github.com/lightwebinc/bitcoin-shard-common/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/lightwebinc/bitcoin-shard-common.svg)](https://pkg.go.dev/github.com/lightwebinc/bitcoin-shard-common)
[![Go Report Card](https://goreportcard.com/badge/github.com/lightwebinc/bitcoin-shard-common)](https://goreportcard.com/report/github.com/lightwebinc/bitcoin-shard-common)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Shared protocol primitives for the BSV transaction sharding pipeline.

## Packages

- **`frame`** — BRC-12/BRC-124 BSV-over-UDP wire format: `Encode`, `Decode`, constants, and sentinel errors. Also includes the BRC-127 `SubtreeAnnounce` codec (`EncodeSubtreeAnnounce`, `DecodeSubtreeAnnounce`). See [docs/protocol.md](docs/protocol.md) for the full wire format specification.
- **`shard`** — Deterministic txid → IPv6 multicast group address derivation. Given a txid and a configured bit width, `Engine` derives a consistent-hash group index and the corresponding `net.UDPAddr`. Also provides `ControlGroupAddr` for control-plane multicast groups (beacon, subtree announce, control).
- **`seqhash`** — XXH64-based hash function for computing `PrevSeq`/`CurSeq` values in BRC-124 frames. Input: `senderIPv6 (16B) ∥ groupIdx (4B BE) ∥ counter (8B BE)` = 28 bytes. Used by the proxy to stamp hash-chain fields in-place.
- **`sequence`** — Per-shard monotonic sequence counters backed by `sync/atomic`. One independent `atomic.Uint64` per shard group; zero allocation and no contention between shards.

## Consumers

| Repo | Uses |
|-------------------------------------------------------------------------------------------|------------------------------|
| [`bitcoin-shard-proxy`](https://github.com/lightwebinc/bitcoin-shard-proxy) | `frame`, `shard`, `seqhash` |
| [`bitcoin-shard-listener`](https://github.com/lightwebinc/bitcoin-shard-listener) | `frame`, `shard` |
| [`bitcoin-subtx-generator`](https://github.com/lightwebinc/bitcoin-subtx-generator) | `frame` |
| [`bitcoin-retry-endpoint`](https://github.com/lightwebinc/bitcoin-retry-endpoint) | `frame`, `shard` |

## Requirements

- Go 1.25 or later

## License

Apache 2.0 — see [LICENSE](LICENSE).
