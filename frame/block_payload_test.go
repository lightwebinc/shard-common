package frame

import (
	"bytes"
	"testing"
)

func TestEncodeDecodeBlockAnnounce_RoundTrip(t *testing.T) {
	var header [80]byte
	header[0] = 0x01 // version
	header[4] = 0xAA // prevBlockHash[0]

	var coinbaseTxID [32]byte
	coinbaseTxID[0] = 0xBB

	subtrees := make([][32]byte, 5)
	for i := range subtrees {
		subtrees[i][0] = byte(i + 1)
	}

	a := &BlockAnnouncePayload{
		Header:        header,
		CoinbaseTxID:  coinbaseTxID,
		SubtreeHashes: subtrees,
	}

	encoded := EncodeBlockAnnounce(a)
	expectedLen := BlockAnnounceMinPayload + 5*32
	if len(encoded) != expectedLen {
		t.Fatalf("encoded len = %d, want %d", len(encoded), expectedLen)
	}

	decoded, err := DecodeBlockAnnounce(encoded)
	if err != nil {
		t.Fatalf("DecodeBlockAnnounce: %v", err)
	}

	if decoded.Header != header {
		t.Error("Header mismatch")
	}
	if decoded.CoinbaseTxID != coinbaseTxID {
		t.Error("CoinbaseTxID mismatch")
	}
	if len(decoded.SubtreeHashes) != 5 {
		t.Fatalf("SubtreeHashes len = %d, want 5", len(decoded.SubtreeHashes))
	}
	for i, h := range decoded.SubtreeHashes {
		if h[0] != byte(i+1) {
			t.Errorf("SubtreeHash[%d][0] = 0x%02X, want 0x%02X", i, h[0], i+1)
		}
	}
}

func TestDecodeBlockAnnounce_ZeroSubtrees(t *testing.T) {
	a := &BlockAnnouncePayload{
		SubtreeHashes: nil,
	}
	encoded := EncodeBlockAnnounce(a)
	if len(encoded) != BlockAnnounceMinPayload {
		t.Fatalf("encoded len = %d, want %d", len(encoded), BlockAnnounceMinPayload)
	}

	decoded, err := DecodeBlockAnnounce(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.SubtreeHashes) != 0 {
		t.Errorf("SubtreeHashes len = %d, want 0", len(decoded.SubtreeHashes))
	}
}

func TestDecodeBlockAnnounce_TooShort(t *testing.T) {
	buf := make([]byte, BlockAnnounceMinPayload-1)
	_, err := DecodeBlockAnnounce(buf)
	if err == nil {
		t.Fatal("want error for too-short payload")
	}
}

func TestDecodeBlockAnnounce_TruncatedSubtrees(t *testing.T) {
	a := &BlockAnnouncePayload{
		SubtreeHashes: make([][32]byte, 3),
	}
	encoded := EncodeBlockAnnounce(a)

	// Truncate: remove last subtree hash.
	_, err := DecodeBlockAnnounce(encoded[:len(encoded)-1])
	if err == nil {
		t.Fatal("want error for truncated subtree hashes")
	}
}

func TestDecodeBlockAnnounce_LargeSubtreeCount(t *testing.T) {
	n := 1000
	subtrees := make([][32]byte, n)
	for i := range subtrees {
		subtrees[i][0] = byte(i & 0xFF)
		subtrees[i][1] = byte(i >> 8)
	}

	a := &BlockAnnouncePayload{
		SubtreeHashes: subtrees,
	}
	encoded := EncodeBlockAnnounce(a)

	decoded, err := DecodeBlockAnnounce(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.SubtreeHashes) != n {
		t.Fatalf("SubtreeHashes len = %d, want %d", len(decoded.SubtreeHashes), n)
	}
	for i, h := range decoded.SubtreeHashes {
		if h[0] != byte(i&0xFF) || h[1] != byte(i>>8) {
			t.Errorf("SubtreeHash[%d] mismatch", i)
			break
		}
	}
}

func TestEncodeBlockAnnounce_PayloadBytes(t *testing.T) {
	var header [80]byte
	for i := range header {
		header[i] = byte(i)
	}
	var coinbaseTxID [32]byte
	coinbaseTxID[31] = 0xFF

	a := &BlockAnnouncePayload{
		Header:        header,
		CoinbaseTxID:  coinbaseTxID,
		SubtreeHashes: make([][32]byte, 2),
	}
	a.SubtreeHashes[0][0] = 0xAA
	a.SubtreeHashes[1][0] = 0xBB

	encoded := EncodeBlockAnnounce(a)

	// Verify header bytes.
	if !bytes.Equal(encoded[0:80], header[:]) {
		t.Error("header bytes mismatch")
	}
	if !bytes.Equal(encoded[80:112], coinbaseTxID[:]) {
		t.Error("coinbaseTxID bytes mismatch")
	}
	// SubtreeCount at offset 112: should be 2.
	if encoded[112] != 0 || encoded[113] != 0 || encoded[114] != 0 || encoded[115] != 2 {
		t.Errorf("SubtreeCount bytes: %x", encoded[112:116])
	}
	// First subtree hash.
	if encoded[116] != 0xAA {
		t.Errorf("SubtreeHash[0][0] = 0x%02X, want 0xAA", encoded[116])
	}
	// Second subtree hash.
	if encoded[148] != 0xBB {
		t.Errorf("SubtreeHash[1][0] = 0x%02X, want 0xBB", encoded[148])
	}
}
