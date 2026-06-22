package pow

import (
	"encoding/binary"
	"math/big"
	"testing"
)

// mainnetMaxTarget is the well-known target encoded by nBits 0x1d00ffff:
// 0x00000000FFFF0000…0000. Verifies CompactToTarget against a fixed value.
func TestCompactToTarget_Mainnet(t *testing.T) {
	got := CompactToTarget(0x1d00ffff)
	want, _ := new(big.Int).SetString("00000000FFFF0000000000000000000000000000000000000000000000000000", 16)
	if got == nil || got.Cmp(want) != 0 {
		t.Fatalf("CompactToTarget(0x1d00ffff) = %x, want %x", got, want)
	}
}

func TestCompactToTarget_Invalid(t *testing.T) {
	if CompactToTarget(0x01800000) != nil { // negative flag set
		t.Error("negative compact must be nil")
	}
	if got := CompactToTarget(0x00000000); got == nil || got.Sign() != 0 {
		t.Errorf("zero mantissa must be 0, got %v", got)
	}
	if CompactToTarget(0xff123456) != nil { // exponent 0xff ⇒ overflow > 256 bits
		t.Error("overflowing compact must be nil")
	}
}

// regtestBits encodes target ~2^255 — easy enough that a few nonce tries find a
// passing header, so the success path is exercised deterministically (the loop
// always converges).
const regtestBits = 0x207fffff

// minedHeader returns an 80-byte header carrying regtestBits that satisfies its
// own PoW, by grinding the nonce field. Cheap at this difficulty.
func minedHeader(t *testing.T) []byte {
	t.Helper()
	h := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(h[nBitsOffset:nBitsOffset+4], regtestBits)
	for nonce := uint32(0); nonce < 1_000_000; nonce++ {
		binary.LittleEndian.PutUint32(h[76:80], nonce)
		if CheckHeader(h, nil) {
			return h
		}
	}
	t.Fatal("could not find a passing nonce at regtest difficulty")
	return nil
}

func TestCheckHeader_ValidPoW(t *testing.T) {
	h := minedHeader(t)
	if !CheckHeader(h, nil) {
		t.Fatal("mined header must pass its own target with no floor")
	}
}

func TestCheckHeader_BelowFloorRejected(t *testing.T) {
	h := minedHeader(t)
	// A floor tighter (smaller) than the claimed regtest target must reject the
	// header even though its hash satisfies the easy claimed target.
	floor := CompactToTarget(0x1d00ffff) // mainnet max target ≪ regtest target
	if CheckHeader(h, floor) {
		t.Fatal("header claiming below-floor difficulty must be rejected")
	}
	// With the floor set to the claimed target (or easier), it passes again.
	if !CheckHeader(h, CompactToTarget(regtestBits)) {
		t.Fatal("header at exactly the floor target must pass")
	}
}

func TestCheckHeader_Malformed(t *testing.T) {
	if CheckHeader(make([]byte, 79), nil) {
		t.Error("wrong-length header must fail")
	}
	bad := make([]byte, HeaderSize)
	binary.LittleEndian.PutUint32(bad[nBitsOffset:nBitsOffset+4], 0x00800000) // negative nBits
	if CheckHeader(bad, nil) {
		t.Error("header with invalid nBits must fail")
	}
}
