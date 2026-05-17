// Package seqhash provides the hash function used to compute HashKey values
// in BRC-124/BRC-128 frames.
//
// HashKey is a stable per-flow identifier computed by the proxy as:
//
//	XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID)
//
// where senderIPv6 is the 16-byte IPv6 address of the frame sender,
// groupIdx is the 4-byte big-endian multicast group index, and subtreeID is
// the 32-byte BRC-124 subtree identifier (zero when unset).
//
// HashKey is the same value for every frame in a (sender, group, subtree)
// flow. Gap detection uses a separate monotonic SeqNum counter; HashKey
// provides per-flow identity for cache lookup and NACK dispatch.
//
// Including subtreeID in the hash input keeps every subtree on its own
// independent flow even within a single shard group (BRC-124 §1.2).
package seqhash

import (
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
)

// inputSize is the fixed size of the hash input buffer:
// 16B (IPv6) + 4B (groupIdx uint32 BE) + 32B (subtreeID).
const inputSize = 52

// Hash computes the stable per-flow XXH64 identifier (HashKey).
//
//   - senderIPv6: 16-byte IPv6 address of the originating sender (as returned
//     by net.IP.To16()).
//   - groupIdx: multicast group index for this frame's TxID shard.
//   - subtreeID: 32-byte BRC-124 subtree identifier; all-zero when unset.
//
// The returned value is identical for every frame in the same
// (sender, group, subtree) flow. A separate monotonic SeqNum counter
// provides per-frame ordering; HashKey is never zero in practice (the
// probability of XXH64 collision is negligible at any realistic flow count).
func Hash(senderIPv6 [16]byte, groupIdx uint32, subtreeID [32]byte) uint64 {
	var input [inputSize]byte
	copy(input[0:16], senderIPv6[:])
	binary.BigEndian.PutUint32(input[16:20], groupIdx)
	copy(input[20:52], subtreeID[:])
	return xxhash.Sum64(input[:])
}
