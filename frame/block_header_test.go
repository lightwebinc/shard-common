package frame_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/lightwebinc/shard-common/frame"
)

func makeBlockHeader80() []byte {
	hdr := make([]byte, frame.BlockHeaderSize)
	binary.LittleEndian.PutUint32(hdr[0:4], 0x20000000) // Version
	for i := 4; i < 36; i++ {                           // PrevBlockHash
		hdr[i] = byte(i)
	}
	for i := 36; i < 68; i++ { // MerkleRoot
		hdr[i] = byte(0xA0 + i)
	}
	binary.LittleEndian.PutUint32(hdr[68:72], 0x665B1A00) // Timestamp
	binary.LittleEndian.PutUint32(hdr[72:76], 0x1D00FFFF) // Bits
	binary.LittleEndian.PutUint32(hdr[76:80], 0x12345678) // Nonce
	return hdr
}

func TestEncodeDecodeBlockHeader_RoundTrip(t *testing.T) {
	hdr := makeBlockHeader80()
	var blockHash [32]byte
	for i := range blockHash {
		blockHash[i] = byte(0xF0 + i)
	}
	const hashKey uint64 = 0x00112233AABBCCDD
	const seqNum uint64 = 0x0000000000000001

	buf := make([]byte, frame.BlockHeaderFrameSize)
	n, err := frame.EncodeBlockHeader(blockHash, hashKey, seqNum, hdr, buf)
	if err != nil {
		t.Fatalf("EncodeBlockHeader: %v", err)
	}
	if n != frame.BlockHeaderFrameSize {
		t.Fatalf("wrote %d bytes, want %d", n, frame.BlockHeaderFrameSize)
	}

	// Verify wire-level offsets per BRC-135.
	if got := binary.BigEndian.Uint32(buf[0:4]); got != frame.MagicBSV {
		t.Errorf("magic = 0x%08X, want 0x%08X", got, frame.MagicBSV)
	}
	if got := binary.BigEndian.Uint16(buf[4:6]); got != frame.ProtoVer {
		t.Errorf("protover = 0x%04X, want 0x%04X", got, frame.ProtoVer)
	}
	if buf[6] != frame.FrameVerV7 {
		t.Errorf("FrameVer = 0x%02X, want 0x07", buf[6])
	}
	if buf[7] != 0 {
		t.Errorf("Reserved = 0x%02X, want 0x00", buf[7])
	}
	if !bytes.Equal(buf[8:40], blockHash[:]) {
		t.Errorf("BlockHash bytes mismatch")
	}
	if got := binary.BigEndian.Uint64(buf[40:48]); got != hashKey {
		t.Errorf("HashKey = 0x%016X, want 0x%016X", got, hashKey)
	}
	if got := binary.BigEndian.Uint64(buf[48:56]); got != seqNum {
		t.Errorf("SeqNum = 0x%016X, want 0x%016X", got, seqNum)
	}
	// LayoutPad32 (bytes 56–87) must be all zeros.
	for i := 56; i < 88; i++ {
		if buf[i] != 0 {
			t.Errorf("LayoutPad32 byte %d = 0x%02X, want 0x00", i, buf[i])
		}
	}
	if got := binary.BigEndian.Uint32(buf[88:92]); got != frame.BlockHeaderSize {
		t.Errorf("PayloadLen = %d, want %d", got, frame.BlockHeaderSize)
	}
	if !bytes.Equal(buf[92:frame.BlockHeaderFrameSize], hdr) {
		t.Errorf("Payload bytes mismatch")
	}

	// Round-trip decode.
	got, err := frame.DecodeBlockHeader(buf)
	if err != nil {
		t.Fatalf("DecodeBlockHeader: %v", err)
	}
	if got.Version != frame.FrameVerV7 {
		t.Errorf("Version = 0x%02X, want 0x07", got.Version)
	}
	if got.TxID != blockHash {
		t.Errorf("TxID (BlockHash) mismatch")
	}
	if got.HashKey != hashKey {
		t.Errorf("HashKey = 0x%016X, want 0x%016X", got.HashKey, hashKey)
	}
	if got.SeqNum != seqNum {
		t.Errorf("SeqNum = 0x%016X, want 0x%016X", got.SeqNum, seqNum)
	}
	if got.SubtreeID != ([32]byte{}) {
		t.Errorf("SubtreeID must be zeros")
	}
	if !bytes.Equal(got.Payload, hdr) {
		t.Errorf("Payload mismatch on decode")
	}
}

func TestEncodeBlockHeader_RejectsWrongPayloadSize(t *testing.T) {
	bad := make([]byte, 79)
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, err := frame.EncodeBlockHeader([32]byte{}, 0, 0, bad, buf)
	if !errors.Is(err, frame.ErrBadBlockHeaderLen) {
		t.Fatalf("err = %v, want ErrBadBlockHeaderLen", err)
	}
}

func TestEncodeBlockHeader_RejectsSmallBuffer(t *testing.T) {
	hdr := makeBlockHeader80()
	small := make([]byte, frame.BlockHeaderFrameSize-1)
	_, err := frame.EncodeBlockHeader([32]byte{}, 0, 0, hdr, small)
	if err == nil {
		t.Fatal("expected error for too-small buf")
	}
}

func TestDecodeBlockHeader_RejectsBadMagic(t *testing.T) {
	hdr := makeBlockHeader80()
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, _ = frame.EncodeBlockHeader([32]byte{}, 0, 1, hdr, buf)
	buf[0] = 0x00 // corrupt magic
	_, err := frame.DecodeBlockHeader(buf)
	if !errors.Is(err, frame.ErrBadMagic) {
		t.Fatalf("err = %v, want ErrBadMagic", err)
	}
}

func TestDecodeBlockHeader_RejectsWrongFrameVer(t *testing.T) {
	hdr := makeBlockHeader80()
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, _ = frame.EncodeBlockHeader([32]byte{}, 0, 1, hdr, buf)
	buf[6] = frame.FrameVerV2 // pretend it's a tx frame
	_, err := frame.DecodeBlockHeader(buf)
	if !errors.Is(err, frame.ErrBadVer) {
		t.Fatalf("err = %v, want ErrBadVer", err)
	}
}

func TestDecodeBlockHeader_RejectsBadPayloadLen(t *testing.T) {
	hdr := makeBlockHeader80()
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, _ = frame.EncodeBlockHeader([32]byte{}, 0, 1, hdr, buf)
	binary.BigEndian.PutUint32(buf[88:92], 79)
	_, err := frame.DecodeBlockHeader(buf)
	if !errors.Is(err, frame.ErrBadBlockHeaderLen) {
		t.Fatalf("err = %v, want ErrBadBlockHeaderLen", err)
	}
}

func TestDecodeBlockHeader_RejectsTruncated(t *testing.T) {
	hdr := makeBlockHeader80()
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, _ = frame.EncodeBlockHeader([32]byte{}, 0, 1, hdr, buf)
	_, err := frame.DecodeBlockHeader(buf[:frame.BlockHeaderFrameSize-1])
	if err == nil {
		t.Fatal("expected truncation error")
	}
}

func TestIsBlockHeaderFrame(t *testing.T) {
	hdr := makeBlockHeader80()
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, _ = frame.EncodeBlockHeader([32]byte{}, 0, 1, hdr, buf)

	if !frame.IsBlockHeaderFrame(buf) {
		t.Error("IsBlockHeaderFrame returned false for V7 frame")
	}

	// Wrong magic.
	bad := make([]byte, len(buf))
	copy(bad, buf)
	bad[0] = 0
	if frame.IsBlockHeaderFrame(bad) {
		t.Error("IsBlockHeaderFrame returned true for bad magic")
	}

	// Wrong version.
	bad2 := make([]byte, len(buf))
	copy(bad2, buf)
	bad2[6] = frame.FrameVerV2
	if frame.IsBlockHeaderFrame(bad2) {
		t.Error("IsBlockHeaderFrame returned true for non-V7")
	}

	// Too short.
	if frame.IsBlockHeaderFrame(buf[:8]) {
		t.Error("IsBlockHeaderFrame returned true for short buf")
	}
}

func TestDecode_RejectsV7WithGuidance(t *testing.T) {
	hdr := makeBlockHeader80()
	buf := make([]byte, frame.BlockHeaderFrameSize)
	_, _ = frame.EncodeBlockHeader([32]byte{}, 0, 1, hdr, buf)
	_, err := frame.Decode(buf)
	if !errors.Is(err, frame.ErrBadVer) {
		t.Fatalf("err = %v, want ErrBadVer (with DecodeBlockHeader guidance)", err)
	}
}
