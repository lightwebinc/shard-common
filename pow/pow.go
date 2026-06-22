// Package pow provides cheap, stateless proof-of-work validation of a BSV
// block header. It is the permissionless complement to operator admission
// control: anyone may announce a block, but the announcement must carry real
// work — verifying costs one double-SHA256 and a big-int compare, while
// forging a passing header costs work proportional to the claimed difficulty.
//
// This is deliberately NOT full consensus validation: it does not know the
// chain, the height, or whether nBits is the correct retarget value. It
// answers one question cheaply — "does this 80-byte header hash under the
// target it claims, and is that target at least as hard as a configured
// floor?" — which is enough to reject spam at ingress. Full validation
// belongs to the consuming node (Teranode), which has chain context.
package pow

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// HeaderSize is the fixed BSV/Bitcoin block-header length.
const HeaderSize = 80

// nBitsOffset is the byte offset of the 4-byte compact difficulty target
// (nBits) within the 80-byte header: version(4) + prevHash(32) + merkle(32) +
// time(4) = 72.
const nBitsOffset = 72

// HeaderHash returns the double-SHA256 of an 80-byte block header. The result
// is the 32-byte hash in internal (little-endian) byte order, the same order
// the PoW comparison uses.
func HeaderHash(header []byte) [32]byte {
	first := sha256.Sum256(header)
	return sha256.Sum256(first[:])
}

// NBits extracts the compact difficulty target (nBits) from an 80-byte header.
func NBits(header []byte) uint32 {
	return binary.LittleEndian.Uint32(header[nBitsOffset : nBitsOffset+4])
}

// CompactToTarget expands a compact "nBits" representation into the full 256-bit
// target. Returns nil for a malformed/overflowing compact value (which callers
// treat as failing PoW). Mirrors Bitcoin's SetCompact: the high byte is the
// exponent (size in bytes) and the low 23 bits are the mantissa; bit 23 is the
// sign flag, which is invalid for a target.
func CompactToTarget(nBits uint32) *big.Int {
	exponent := nBits >> 24
	mantissa := nBits & 0x007fffff
	if nBits&0x00800000 != 0 { // negative flag set — invalid target
		return nil
	}
	if mantissa == 0 {
		return big.NewInt(0)
	}
	t := new(big.Int)
	if exponent <= 3 {
		t.SetUint64(uint64(mantissa) >> (8 * (3 - exponent)))
	} else {
		t.SetUint64(uint64(mantissa))
		t.Lsh(t, 8*(uint(exponent)-3))
	}
	// Targets wider than 256 bits are overflow — reject.
	if t.BitLen() > 256 {
		return nil
	}
	return t
}

// CheckHeader reports whether the header carries valid proof of work: its
// double-SHA256, read as a little-endian 256-bit integer, is ≤ the target its
// own nBits field encodes. floor, when non-nil, is the maximum acceptable
// target (the difficulty floor): a header whose claimed target exceeds floor
// is rejected even if its hash satisfies that easy target, so an attacker
// cannot claim trivial difficulty and pass with negligible work.
//
// Returns false for a malformed header (wrong length, bad nBits).
func CheckHeader(header []byte, floor *big.Int) bool {
	if len(header) != HeaderSize {
		return false
	}
	target := CompactToTarget(NBits(header))
	if target == nil || target.Sign() <= 0 {
		return false
	}
	if floor != nil && target.Cmp(floor) > 0 {
		return false // claimed difficulty below the floor (target too easy)
	}
	h := HeaderHash(header)
	hashVal := littleEndianToBig(h)
	return hashVal.Cmp(target) <= 0
}

// littleEndianToBig interprets a 32-byte hash in little-endian byte order (the
// order block hashes are compared in) as a big.Int.
func littleEndianToBig(h [32]byte) *big.Int {
	var be [32]byte
	for i := 0; i < 32; i++ {
		be[i] = h[31-i]
	}
	return new(big.Int).SetBytes(be[:])
}
