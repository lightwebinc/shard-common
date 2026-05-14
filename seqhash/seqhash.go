// Package seqhash provides the hash function used to compute PrevSeq and
// CurSeq values in BRC-124/BRC-128 frames.
//
// Each frame's CurSeq is computed by the proxy as:
//
//	XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID ∥ counter)
//
// where senderIPv6 is the 16-byte IPv6 address of the frame sender,
// groupIdx is the 4-byte big-endian multicast group index, subtreeID is
// the 32-byte BRC-124 subtree identifier (zero when unset), and counter
// is a per-(sender, group, subtree) monotonic uint64 big-endian counter.
//
// The previous frame's CurSeq becomes the next frame's PrevSeq, forming a
// verifiable hash chain. A chain break (PrevSeq ≠ expected) indicates one
// or more missing frames, triggering NACK-based gap recovery.
//
// Including subtreeID in the hash input keeps every subtree on its own
// independent chain even within a single shard group, so packet loss in one
// subtree cannot create false gaps in another (BRC-124 §1.2 ordering).
package seqhash

import (
	"encoding/binary"

	"github.com/cespare/xxhash/v2"
)

// inputSize is the fixed size of the hash input buffer:
// 16B (IPv6) + 4B (groupIdx uint32 BE) + 32B (subtreeID) + 8B (counter uint64 BE).
const inputSize = 60

// Hash computes the XXH64 hash for one frame in a sequence chain.
//
//   - senderIPv6: 16-byte IPv6 address of the originating sender (as returned
//     by net.IP.To16()).
//   - groupIdx: multicast group index for this frame's TxID shard.
//   - subtreeID: 32-byte BRC-124 subtree identifier; all-zero when unset.
//   - counter: per-(sender, group, subtree) monotonic counter, starting at 1.
//
// Returns 0 only when counter == 0 (counter == 0 means "unset" in the wire
// format); callers must start counters at 1.
func Hash(senderIPv6 [16]byte, groupIdx uint32, subtreeID [32]byte, counter uint64) uint64 {
	var input [inputSize]byte
	copy(input[0:16], senderIPv6[:])
	binary.BigEndian.PutUint32(input[16:20], groupIdx)
	copy(input[20:52], subtreeID[:])
	binary.BigEndian.PutUint64(input[52:60], counter)
	return xxhash.Sum64(input[:])
}
