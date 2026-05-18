// Package shard derives IPv6 multicast group addresses from BSV transaction
// IDs for deterministic packet-level sharding across the BSV sharding pipeline.
//
// # Sharding strategy
//
// The derivation is pure arithmetic: no allocation, no locks, safe for
// concurrent use by multiple goroutines without synchronisation.
//
// Given a 256-bit txid and a configured bit width N (1–12), the group index
// is the top N bits of the first 32-bit word of the txid:
//
//	groupIndex = (txid[0:4] as uint32) >> (32 - N)
//
// Using the top bits — rather than a modulo operation on the bottom bits —
// gives consistent-hashing behaviour: when N increases by 1, every existing
// group splits into exactly two child groups. Subscribers only need to join
// additional groups; no existing subscriptions become invalid.
//
// # Address layout (IANA-aligned)
//
//	bits [127:112]   FF0X  multicast prefix + scope nibble  (16 bits)
//	bits [111: 32]   0x00  zero (IANA 96-bit boundary)      (80 bits)
//	bits [ 31: 16]   GID   IANA group-id (default 0x000B)   (16 bits)
//	bits [ 15:  0]   IDX   shard index                      (16 bits)
//
// Bytes: [0:2]=scope, [2:12]=zero, [12:14]=group-id, [14:16]=shard index.
//
// The IANA Bitcoin allocation is FF0X::B (group-id 0x000B). Operators MAY
// override the group-id for testing or private deployments via configuration,
// but the on-wire default is 0x000B for IANA conformance.
//
// The 16-bit index space is divided into three zones (see BRC-129):
// shard groups 0x0000–0x0FFF, free space 0x1000–0xF7FF, network services
// 0xF800–0xFFFF. shardBits is therefore bounded at 12.
package shard

import (
	"encoding/binary"
	"net"
)

// DefaultGroupID is the IANA-assigned IPv6 multicast group-id for Bitcoin
// (FF0X::B). Operators MAY override via configuration but the on-wire default
// must be DefaultGroupID for IANA conformance.
const DefaultGroupID uint16 = 0x000B

// Engine holds the immutable sharding parameters. Construct one with [New]
// and share it freely across goroutines.
type Engine struct {
	mcPrefix  uint16 // upper 16 bits of the IPv6 multicast address, e.g. 0xFF05
	groupID   uint16 // bytes 12-13: IANA group-id (default 0x000B)
	shardBits uint   // number of txid prefix bits used as the group key
	mask      uint32 // (1 << shardBits) - 1; applied after the shift
}

// New creates a shard Engine.
//
//   - mcPrefix is the two-byte IPv6 multicast prefix (e.g. 0xFF05 for
//     site-local scope).
//   - groupID is the 16-bit IANA group-id occupying bytes 12-13 of the
//     address (default [DefaultGroupID] = 0x000B for Bitcoin).
//   - shardBits is the number of bits from the txid prefix that form the
//     group key. Must be in [1, 12].
func New(mcPrefix uint16, groupID uint16, shardBits uint) *Engine {
	return &Engine{
		mcPrefix:  mcPrefix,
		groupID:   groupID,
		shardBits: shardBits,
		mask:      (1 << shardBits) - 1,
	}
}

// GroupIndex returns the shard group index for a given txid.
//
// Only the first four bytes of txid are examined. The top shardBits bits
// of those four bytes are extracted as a big-endian unsigned integer,
// producing a value in [0, NumGroups).
//
// This function is safe for concurrent use without synchronisation.
func (e *Engine) GroupIndex(txid *[32]byte) uint32 {
	prefix32 := binary.BigEndian.Uint32(txid[0:4])
	return (prefix32 >> (32 - e.shardBits)) & e.mask
}

// Addr constructs the 16-byte IPv6 multicast [net.UDPAddr] for the given
// group index and destination port.
//
// The returned address is a newly allocated value on each call; callers may
// cache the result if the group index and port are stable.
//
// groupIndex is treated as a 16-bit value; only the low 16 bits are used.
func (e *Engine) Addr(groupIndex uint32, port int) *net.UDPAddr {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint16(ip[0:2], e.mcPrefix)
	// bytes 2..11 remain zero (IANA 96-bit boundary)
	binary.BigEndian.PutUint16(ip[12:14], e.groupID)
	binary.BigEndian.PutUint16(ip[14:16], uint16(groupIndex))
	return &net.UDPAddr{IP: ip, Port: port}
}

// Prefix returns the configured upper 16-bit scope prefix (e.g. 0xFF05, 0xFF0E).
func (e *Engine) Prefix() uint16 { return e.mcPrefix }

// ShardBits returns the configured bit width for informational and logging use.
func (e *Engine) ShardBits() uint { return e.shardBits }

// GroupID returns the configured IANA group-id (bytes 12-13 of the address).
func (e *Engine) GroupID() uint16 { return e.groupID }

// NumGroups returns the total number of distinct multicast groups in the
// configured shard space (2^ShardBits).
func (e *Engine) NumGroups() uint32 { return e.mask + 1 }
