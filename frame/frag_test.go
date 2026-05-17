package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// buildFragBuf constructs a minimal valid BRC-130 fragment datagram.
func buildFragBuf(txidByte byte, hashKey, seqNum uint64, origPayLen uint32, fragIndex, fragTotal uint16, fragData []byte) []byte {
	buf := make([]byte, HeaderSizeV3+len(fragData))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV3
	buf[7] = 0
	buf[8] = txidByte
	binary.BigEndian.PutUint64(buf[40:48], hashKey)
	binary.BigEndian.PutUint64(buf[48:56], seqNum)
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(fragData)))
	binary.BigEndian.PutUint32(buf[92:96], origPayLen)
	binary.BigEndian.PutUint16(buf[96:98], fragIndex)
	binary.BigEndian.PutUint16(buf[98:100], fragTotal)
	copy(buf[HeaderSizeV3:], fragData)
	return buf
}

func TestHeaderSizeV3(t *testing.T) {
	if HeaderSizeV3 != 104 {
		t.Errorf("HeaderSizeV3 = %d, want 104", HeaderSizeV3)
	}
}

func TestFrameVerV3(t *testing.T) {
	if FrameVerV3 != 0x03 {
		t.Errorf("FrameVerV3 = 0x%02X, want 0x03", FrameVerV3)
	}
}

// TestEncodeFragmentRoundTrip verifies that EncodeFragment followed by
// DecodeFragment produces identical field values.
func TestEncodeFragmentRoundTrip(t *testing.T) {
	var txID [32]byte
	txID[0] = 0xAB
	var subtreeID [32]byte
	for i := range subtreeID {
		subtreeID[i] = byte(i + 1)
	}
	fragData := []byte("fragment-payload-bytes")

	buf := make([]byte, HeaderSizeV3+len(fragData))
	n, err := EncodeFragment(buf, txID, subtreeID, 0xDEADBEEF12345678, 42, 9999, 3, 8, fragData)
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	if n != HeaderSizeV3+len(fragData) {
		t.Fatalf("EncodeFragment returned %d bytes, want %d", n, HeaderSizeV3+len(fragData))
	}

	ff, err := DecodeFragment(buf[:n])
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	if ff.TxID != txID {
		t.Errorf("TxID mismatch: got %x, want %x", ff.TxID, txID)
	}
	if ff.SubtreeID != subtreeID {
		t.Errorf("SubtreeID mismatch")
	}
	if ff.HashKey != 0xDEADBEEF12345678 {
		t.Errorf("HashKey = %x, want %x", ff.HashKey, uint64(0xDEADBEEF12345678))
	}
	if ff.SeqNum != 42 {
		t.Errorf("SeqNum = %d, want 42", ff.SeqNum)
	}
	if ff.OrigPayloadLen != 9999 {
		t.Errorf("OrigPayloadLen = %d, want 9999", ff.OrigPayloadLen)
	}
	if ff.FragIndex != 3 {
		t.Errorf("FragIndex = %d, want 3", ff.FragIndex)
	}
	if ff.FragTotal != 8 {
		t.Errorf("FragTotal = %d, want 8", ff.FragTotal)
	}
	if !bytes.Equal(ff.FragData, fragData) {
		t.Errorf("FragData mismatch: got %q, want %q", ff.FragData, fragData)
	}
}

// TestDecodeV3_HeaderSize verifies that exactly 104 bytes are required.
func TestDecodeV3_HeaderSize(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 2, nil)

	_, err := DecodeFragment(buf)
	if err != nil {
		t.Fatalf("valid 104-byte header: %v", err)
	}

	_, err = DecodeFragment(buf[:HeaderSizeV3-1])
	if err != ErrTooShort {
		t.Errorf("103-byte buf: want ErrTooShort, got %v", err)
	}
}

// TestDecodeV3_FieldOffsets verifies key field byte positions.
func TestDecodeV3_FieldOffsets(t *testing.T) {
	data := []byte{0xFF}
	buf := make([]byte, HeaderSizeV3+len(data))
	var txID [32]byte
	txID[0] = 0x11
	var subID [32]byte
	subID[0] = 0x22
	if _, err := EncodeFragment(buf, txID, subID, 0xAABBCCDDEEFF0011, 0x1122334455667788, 5000, 7, 10, data); err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}

	if buf[6] != FrameVerV3 {
		t.Errorf("buf[6] (FrameVer) = 0x%02X, want 0x03", buf[6])
	}
	if buf[8] != 0x11 {
		t.Errorf("buf[8] (TxID[0]) = 0x%02X, want 0x11", buf[8])
	}
	if binary.BigEndian.Uint64(buf[40:48]) != 0xAABBCCDDEEFF0011 {
		t.Errorf("buf[40:48] (HashKey) = %x", binary.BigEndian.Uint64(buf[40:48]))
	}
	if binary.BigEndian.Uint64(buf[48:56]) != 0x1122334455667788 {
		t.Errorf("buf[48:56] (SeqNum) = %x", binary.BigEndian.Uint64(buf[48:56]))
	}
	if buf[56] != 0x22 {
		t.Errorf("buf[56] (SubtreeID[0]) = 0x%02X, want 0x22", buf[56])
	}
	if binary.BigEndian.Uint32(buf[88:92]) != uint32(len(data)) {
		t.Errorf("buf[88:92] (PayloadLen) = %d, want 1", binary.BigEndian.Uint32(buf[88:92]))
	}
	if binary.BigEndian.Uint32(buf[92:96]) != 5000 {
		t.Errorf("buf[92:96] (OrigPayloadLen) = %d, want 5000", binary.BigEndian.Uint32(buf[92:96]))
	}
	if binary.BigEndian.Uint16(buf[96:98]) != 7 {
		t.Errorf("buf[96:98] (FragIndex) = %d, want 7", binary.BigEndian.Uint16(buf[96:98]))
	}
	if binary.BigEndian.Uint16(buf[98:100]) != 10 {
		t.Errorf("buf[98:100] (FragTotal) = %d, want 10", binary.BigEndian.Uint16(buf[98:100]))
	}
	if binary.BigEndian.Uint32(buf[100:104]) != 0 {
		t.Errorf("buf[100:104] (Reserved2) = %d, want 0", binary.BigEndian.Uint32(buf[100:104]))
	}
	if buf[HeaderSizeV3] != 0xFF {
		t.Errorf("buf[%d] (FragData[0]) = 0x%02X, want 0xFF", HeaderSizeV3, buf[HeaderSizeV3])
	}
}

// TestDecodeV3_BackwardCompat verifies that bytes 0–91 of a BRC-130 header
// are layout-compatible with BRC-124 (same field offsets for TxID, HashKey,
// SeqNum, SubtreeID, PayloadLen).
func TestDecodeV3_BackwardCompat(t *testing.T) {
	data := []byte("compat-test")
	var txID [32]byte
	txID[0] = 0xCC
	var subID [32]byte
	subID[0] = 0xDD

	v3buf := make([]byte, HeaderSizeV3+len(data))
	if _, err := EncodeFragment(v3buf, txID, subID, 0x1234567890ABCDEF, 77, 1000, 0, 1, data); err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}

	v2buf := make([]byte, HeaderSize+len(data))
	f := &Frame{
		TxID:      txID,
		HashKey:   0x1234567890ABCDEF,
		SeqNum:    77,
		SubtreeID: subID,
		Payload:   data,
	}
	if _, err := Encode(f, v2buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Bytes 0–87 must be identical (everything up to PayloadLen).
	for i := 0; i < 88; i++ {
		if i == 6 {
			continue // FrameVer differs by design
		}
		if v3buf[i] != v2buf[i] {
			t.Errorf("byte[%d]: BRC-130=%02X BRC-124=%02X", i, v3buf[i], v2buf[i])
		}
	}
	// PayloadLen field (bytes 88–91) encodes fragment data length in V3,
	// which equals len(data) in this single-fragment test.
	if binary.BigEndian.Uint32(v3buf[88:92]) != uint32(len(data)) {
		t.Errorf("V3 PayloadLen = %d, want %d", binary.BigEndian.Uint32(v3buf[88:92]), len(data))
	}
}

// TestDecodeV3_BadFrameVer verifies DecodeFragment rejects non-0x03 FrameVer.
func TestDecodeV3_BadFrameVer(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 1, nil)
	buf[6] = FrameVerV2 // flip to V2

	_, err := DecodeFragment(buf)
	if err == nil {
		t.Fatal("want error for FrameVer=0x02 in DecodeFragment, got nil")
	}
}

// TestDecodeV3_FragIndexBounds verifies that FragIndex >= FragTotal is rejected.
func TestDecodeV3_FragIndexBounds(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 5, 5, nil) // FragIndex=5, FragTotal=5 (equal → invalid)
	_, err := DecodeFragment(buf)
	if !errors.Is(err, ErrBadFrag) {
		t.Errorf("want ErrBadFrag for FragIndex==FragTotal, got %v", err)
	}

	buf = buildFragBuf(0x01, 1, 1, 100, 6, 5, nil) // FragIndex > FragTotal
	_, err = DecodeFragment(buf)
	if !errors.Is(err, ErrBadFrag) {
		t.Errorf("want ErrBadFrag for FragIndex>FragTotal, got %v", err)
	}
}

// TestDecodeV3_FragTotalZero verifies that FragTotal==0 is rejected.
func TestDecodeV3_FragTotalZero(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 0, nil) // FragTotal=0
	_, err := DecodeFragment(buf)
	if !errors.Is(err, ErrBadFrag) {
		t.Errorf("want ErrBadFrag for FragTotal=0, got %v", err)
	}
}

// TestDecodeV3_Truncated verifies io.ErrUnexpectedEOF on truncated fragment data.
func TestDecodeV3_Truncated(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 1, []byte("hello"))
	_, err := DecodeFragment(buf[:len(buf)-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

// TestDecodeV3_BadMagic verifies ErrBadMagic is returned for a bad magic.
func TestDecodeV3_BadMagic(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 1, []byte("data"))
	buf[0] = 0x00 // corrupt magic

	_, err := DecodeFragment(buf)
	if err == nil {
		t.Fatal("want error for bad magic, got nil")
	}
}

// TestDecodeV3_EmptyFragData verifies a zero-length fragment is accepted.
func TestDecodeV3_EmptyFragData(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 0, 0, 1, nil)
	ff, err := DecodeFragment(buf)
	if err != nil {
		t.Fatalf("DecodeFragment empty frag: %v", err)
	}
	if len(ff.FragData) != 0 {
		t.Errorf("FragData len = %d, want 0", len(ff.FragData))
	}
}

// TestIsFragment verifies IsFragment detection without full decode.
func TestIsFragment(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 1, []byte("x"))
	if !IsFragment(buf) {
		t.Error("want IsFragment=true for V3 frame")
	}

	v2buf := make([]byte, HeaderSize+1)
	binary.BigEndian.PutUint32(v2buf[0:4], MagicBSV)
	v2buf[6] = FrameVerV2
	if IsFragment(v2buf) {
		t.Error("want IsFragment=false for V2 frame")
	}

	if IsFragment([]byte{0x01, 0x02}) {
		t.Error("want IsFragment=false for short buffer")
	}
}

// TestDecodeRejectsV3 verifies that frame.Decode returns ErrBadVer for
// BRC-130 frames, directing callers to use DecodeFragment instead.
func TestDecodeRejectsV3(t *testing.T) {
	buf := buildFragBuf(0x01, 1, 1, 100, 0, 1, []byte("data"))
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error from Decode for V3 frame, got nil")
	}
}

// TestEncodeFragmentBufferTooSmall verifies error on undersized buffer.
func TestEncodeFragmentBufferTooSmall(t *testing.T) {
	var txID [32]byte
	var subID [32]byte
	_, err := EncodeFragment(make([]byte, 10), txID, subID, 0, 0, 0, 0, 1, []byte("data"))
	if err == nil {
		t.Fatal("want error for buffer too small, got nil")
	}
}
