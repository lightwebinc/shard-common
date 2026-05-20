package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// buildAnchorBuf constructs a minimal valid BRC-134 anchor transaction datagram.
func buildAnchorBuf(txidByte byte, payload []byte) []byte {
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV6
	buf[7] = 0x00 // Reserved
	buf[8] = txidByte
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)
	return buf
}

func TestFrameVerV6(t *testing.T) {
	if FrameVerV6 != 0x06 {
		t.Errorf("FrameVerV6 = 0x%02X, want 0x06", FrameVerV6)
	}
}

func TestDecodeAnchorRoundTrip(t *testing.T) {
	payload := []byte("raw-anchor-tx-payload")

	// Build manually since Encode always writes FrameVerV2.
	var txid [32]byte
	txid[0] = 0xAB
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV6
	buf[7] = 0x00
	copy(buf[8:40], txid[:])
	binary.BigEndian.PutUint64(buf[40:48], 0x1234567890ABCDEF)
	binary.BigEndian.PutUint64(buf[48:56], 42)
	// bytes 56–87: zeros (LayoutPad32)
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)

	f, err := DecodeAnchor(buf)
	if err != nil {
		t.Fatalf("DecodeAnchor: %v", err)
	}

	if f.Version != FrameVerV6 {
		t.Errorf("Version = 0x%02X, want 0x%02X", f.Version, FrameVerV6)
	}
	if f.TxID != txid {
		t.Errorf("TxID mismatch: got %x, want %x", f.TxID, txid)
	}
	if f.HashKey != 0x1234567890ABCDEF {
		t.Errorf("HashKey = %x, want 0x1234567890ABCDEF", f.HashKey)
	}
	if f.SeqNum != 42 {
		t.Errorf("SeqNum = %d, want 42", f.SeqNum)
	}
	if f.SubtreeID != ([32]byte{}) {
		t.Error("SubtreeID should be all zeros for anchor frames")
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", f.Payload, payload)
	}
}

func TestDecodeAnchor_FieldOffsets(t *testing.T) {
	payload := []byte{0xFF}

	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV6
	buf[7] = 0x00
	buf[8] = 0x11 // TxID[0]
	binary.BigEndian.PutUint64(buf[40:48], 0xAABBCCDDEEFF0011)
	binary.BigEndian.PutUint64(buf[48:56], 0x1122334455667788)
	binary.BigEndian.PutUint32(buf[88:92], 1)
	buf[HeaderSize] = 0xFF

	if buf[6] != FrameVerV6 {
		t.Errorf("buf[6] (FrameVer) = 0x%02X, want 0x%02X", buf[6], FrameVerV6)
	}
	if buf[7] != 0x00 {
		t.Errorf("buf[7] (Reserved) = 0x%02X, want 0x00", buf[7])
	}
	if buf[8] != 0x11 {
		t.Errorf("buf[8] (TxID[0]) = 0x%02X, want 0x11", buf[8])
	}
	if binary.BigEndian.Uint64(buf[40:48]) != 0xAABBCCDDEEFF0011 {
		t.Errorf("buf[40:48] (HashKey) mismatch")
	}
	if binary.BigEndian.Uint64(buf[48:56]) != 0x1122334455667788 {
		t.Errorf("buf[48:56] (SeqNum) mismatch")
	}
	if binary.BigEndian.Uint32(buf[88:92]) != 1 {
		t.Errorf("buf[88:92] (PayloadLen) = %d, want 1", binary.BigEndian.Uint32(buf[88:92]))
	}
	if buf[HeaderSize] != 0xFF {
		t.Errorf("buf[%d] (Payload[0]) = 0x%02X, want 0xFF", HeaderSize, buf[HeaderSize])
	}

	f, err := DecodeAnchor(buf)
	if err != nil {
		t.Fatalf("DecodeAnchor: %v", err)
	}
	if f.HashKey != 0xAABBCCDDEEFF0011 {
		t.Errorf("decoded HashKey mismatch")
	}
	if f.SeqNum != 0x1122334455667788 {
		t.Errorf("decoded SeqNum mismatch")
	}
}

func TestDecodeAnchor_LayoutPad32Zeros(t *testing.T) {
	buf := buildAnchorBuf(0x01, []byte("payload"))
	// Confirm bytes 56–87 are all zero (LayoutPad32).
	for i := 56; i < 88; i++ {
		if buf[i] != 0 {
			t.Errorf("buf[%d] = 0x%02X, want 0x00 (LayoutPad32)", i, buf[i])
		}
	}
	// DecodeAnchor copies them into SubtreeID; must decode as all-zeros.
	f, err := DecodeAnchor(buf)
	if err != nil {
		t.Fatalf("DecodeAnchor: %v", err)
	}
	if f.SubtreeID != ([32]byte{}) {
		t.Error("decoded SubtreeID must be all zeros for anchor frames")
	}
}

func TestDecodeAnchor_BadFrameVer(t *testing.T) {
	buf := buildAnchorBuf(0x01, nil)
	buf[6] = FrameVerV2
	_, err := DecodeAnchor(buf)
	if err == nil {
		t.Fatal("want error for FrameVer=0x02, got nil")
	}
	if !errors.Is(err, ErrBadVer) {
		t.Errorf("want ErrBadVer, got %v", err)
	}
}

func TestDecodeAnchor_BadMagic(t *testing.T) {
	buf := buildAnchorBuf(0x01, nil)
	buf[0] = 0x00
	_, err := DecodeAnchor(buf)
	if err == nil {
		t.Fatal("want error for bad magic, got nil")
	}
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("want ErrBadMagic, got %v", err)
	}
}

func TestDecodeAnchor_TooShort(t *testing.T) {
	buf := buildAnchorBuf(0x01, nil)
	_, err := DecodeAnchor(buf[:HeaderSize-1])
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort, got %v", err)
	}

	// Also test below HeaderSizeLegacy threshold.
	_, err = DecodeAnchor(buf[:HeaderSizeLegacy-1])
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort for buffer < HeaderSizeLegacy, got %v", err)
	}
}

func TestDecodeAnchor_Truncated(t *testing.T) {
	buf := buildAnchorBuf(0x01, []byte("hello"))
	_, err := DecodeAnchor(buf[:len(buf)-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestDecodeAnchor_EmptyPayload(t *testing.T) {
	buf := buildAnchorBuf(0x01, nil)
	f, err := DecodeAnchor(buf)
	if err != nil {
		t.Fatalf("DecodeAnchor empty payload: %v", err)
	}
	if len(f.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(f.Payload))
	}
}

func TestIsAnchorFrame(t *testing.T) {
	buf := buildAnchorBuf(0x01, []byte("x"))
	if !IsAnchorFrame(buf) {
		t.Error("want IsAnchorFrame=true for V6 frame")
	}

	v2buf := make([]byte, HeaderSize+1)
	binary.BigEndian.PutUint32(v2buf[0:4], MagicBSV)
	v2buf[6] = FrameVerV2
	if IsAnchorFrame(v2buf) {
		t.Error("want IsAnchorFrame=false for V2 frame")
	}

	v4buf := buildAnchorBuf(0x01, nil)
	v4buf[6] = FrameVerV4
	if IsAnchorFrame(v4buf) {
		t.Error("want IsAnchorFrame=false for V4 frame")
	}

	if IsAnchorFrame([]byte{0x01, 0x02}) {
		t.Error("want IsAnchorFrame=false for short buffer")
	}
}

func TestDecodeRejectsV6(t *testing.T) {
	buf := buildAnchorBuf(0x01, []byte("data"))
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error from Decode for V6 frame, got nil")
	}
	if !errors.Is(err, ErrBadVer) {
		t.Errorf("want ErrBadVer, got %v", err)
	}
}
