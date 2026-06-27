package frame

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func makeFrame(txidByte0 byte, payload []byte) *Frame {
	f := &Frame{Payload: payload}
	f.TxID[0] = txidByte0
	return f
}

// ── Constants ─────────────────────────────────────────────────────────────────

func TestHeaderSize(t *testing.T) {
	if HeaderSize != 92 {
		t.Errorf("HeaderSize = %d, want 92", HeaderSize)
	}
}

func TestHeaderSizeLegacy(t *testing.T) {
	if HeaderSizeLegacy != 44 {
		t.Errorf("HeaderSizeLegacy = %d, want 44", HeaderSizeLegacy)
	}
}

func TestFrameVerV1(t *testing.T) {
	if FrameVerV1 != 0x01 {
		t.Errorf("FrameVerV1 = 0x%02X, want 0x01", FrameVerV1)
	}
}

func TestFrameVerV2(t *testing.T) {
	if FrameVerV2 != 0x02 {
		t.Errorf("FrameVerV2 = 0x%02X, want 0x02", FrameVerV2)
	}
}

// ── Round-trip (all fields) ───────────────────────────────────────────────────

func TestRoundTrip(t *testing.T) {
	payload := []byte("fake-bsv-tx-payload")
	f := &Frame{
		Payload: payload,
		HashKey: 0x0102030405060708,
		SeqNum:  0xAABBCCDDEEFF0011,
	}
	f.TxID[0] = 0xAB
	for i := range f.SubtreeID {
		f.SubtreeID[i] = byte(i + 1)
	}

	buf := make([]byte, HeaderSize+len(payload))
	n, err := Encode(f, buf)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if n != HeaderSize+len(payload) {
		t.Fatalf("Encode returned %d bytes, want %d", n, HeaderSize+len(payload))
	}

	got, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.TxID != f.TxID {
		t.Errorf("TxID mismatch: got %x, want %x", got.TxID, f.TxID)
	}
	if got.HashKey != f.HashKey {
		t.Errorf("HashKey = %d, want %d", got.HashKey, f.HashKey)
	}
	if got.SeqNum != f.SeqNum {
		t.Errorf("SeqNum = %d, want %d", got.SeqNum, f.SeqNum)
	}
	if got.SubtreeID != f.SubtreeID {
		t.Errorf("SubtreeID mismatch")
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", got.Payload, payload)
	}
}

func TestRoundTripSeqFields(t *testing.T) {
	payload := []byte("tx-with-seq")
	f := &Frame{
		Payload: payload,
		HashKey: 0xDEADBEEFCAFEBABE,
		SeqNum:  0x0123456789ABCDEF,
	}
	f.TxID[0] = 0xCC

	buf := make([]byte, HeaderSize+len(payload))
	if _, err := Encode(f, buf); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(buf)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HashKey != f.HashKey {
		t.Errorf("HashKey mismatch: got %x, want %x", got.HashKey, f.HashKey)
	}
	if got.SeqNum != f.SeqNum {
		t.Errorf("SeqNum mismatch: got %x, want %x", got.SeqNum, f.SeqNum)
	}
}

// ── Field offsets ─────────────────────────────────────────────────────────────

func TestFieldOffsets(t *testing.T) {
	f := &Frame{
		HashKey: 0xAABBCCDDEEFF0011,
		SeqNum:  0x1122334455667788,
	}
	f.TxID[0] = 0x11
	for i := range f.SubtreeID {
		f.SubtreeID[i] = 0xCC
	}
	f.Payload = []byte{0xFF}

	buf := make([]byte, HeaderSize+5) // Extra space for payload checks
	if _, err := Encode(f, buf); err != nil {
		t.Fatal(err)
	}

	if buf[6] != FrameVerV2 {
		t.Errorf("buf[6] (FrameVer) = 0x%02X, want 0x%02X", buf[6], FrameVerV2)
	}
	if buf[7] != 0 {
		t.Errorf("buf[7] (Reserved) = 0x%02X, want 0x00", buf[7])
	}
	if buf[8] != 0x11 {
		t.Errorf("buf[8] (TxID[0]) = 0x%02X, want 0x11", buf[8])
	}
	if binary.BigEndian.Uint64(buf[40:48]) != 0xAABBCCDDEEFF0011 {
		t.Errorf("buf[40:48] (HashKey) = %x, want 0xAABBCCDDEEFF0011", binary.BigEndian.Uint64(buf[40:48]))
	}
	if binary.BigEndian.Uint64(buf[48:56]) != 0x1122334455667788 {
		t.Errorf("buf[48:56] (SeqNum) = %x, want 0x1122334455667788", binary.BigEndian.Uint64(buf[48:56]))
	}
	if buf[56] != 0xCC {
		t.Errorf("buf[56] (SubtreeID[0]) = 0x%02X, want 0xCC", buf[56])
	}
	payLen := binary.BigEndian.Uint32(buf[88:92])
	if payLen != 1 {
		t.Errorf("buf[88:92] (PayLen) = %d, want 1", payLen)
	}
	if buf[HeaderSize] != 0xFF {
		t.Errorf("buf[%d] (Payload[0]) = 0x%02X, want 0xFF", HeaderSize, buf[HeaderSize])
	}
}

// ── Empty payload ─────────────────────────────────────────────────────────────

func TestEmptyPayload(t *testing.T) {
	f := makeFrame(0x77, []byte{})
	buf := make([]byte, HeaderSize+8) // Extra space for copy operation
	n, err := Encode(f, buf)
	if err != nil {
		t.Fatalf("Encode empty payload: %v", err)
	}
	if n != HeaderSize {
		t.Errorf("n = %d, want %d", n, HeaderSize)
	}
	got, err := Decode(buf[:n])
	if err != nil {
		t.Fatalf("Decode empty payload: %v", err)
	}
	if len(got.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(got.Payload))
	}
}

// ── BRC-12 frame decode ───────────────────────────────────────────────────────────

// buildV1Frame assembles a minimal valid BRC-12 (legacy) datagram.
func buildV1Frame(txidByte byte, payload []byte) []byte {
	buf := make([]byte, HeaderSizeLegacy+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV1
	// buf[7] = 0x00 (reserved)
	buf[8] = txidByte
	binary.BigEndian.PutUint32(buf[40:44], uint32(len(payload)))
	copy(buf[44:], payload)
	return buf
}

func TestDecodeV1Basic(t *testing.T) {
	payload := []byte("v1-tx-payload")
	raw := buildV1Frame(0xAB, payload)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode v1: %v", err)
	}
	if f.Version != FrameVerV1 {
		t.Errorf("Version = 0x%02X, want 0x%02X", f.Version, FrameVerV1)
	}
	if f.TxID[0] != 0xAB {
		t.Errorf("TxID[0] = 0x%02X, want 0xAB", f.TxID[0])
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", f.Payload, payload)
	}
}

func TestDecodeV1ZeroedV2Fields(t *testing.T) {
	raw := buildV1Frame(0x01, nil)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode v1: %v", err)
	}
	if f.HashKey != 0 {
		t.Errorf("HashKey = %d, want 0", f.HashKey)
	}
	if f.SeqNum != 0 {
		t.Errorf("SeqNum = %d, want 0", f.SeqNum)
	}
	if f.SubtreeID != ([32]byte{}) {
		t.Error("SubtreeID should be all zeros for BRC-12")
	}
}

func TestDecodeV1EmptyPayload(t *testing.T) {
	raw := buildV1Frame(0x77, nil)
	f, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode BRC-12 empty payload: %v", err)
	}
	if len(f.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(f.Payload))
	}
}

func TestDecodeV1Truncated(t *testing.T) {
	raw := buildV1Frame(0x01, []byte("hello"))
	_, err := Decode(raw[:len(raw)-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

// ── Error paths ───────────────────────────────────────────────────────────────

func TestDecodeErrTooShort(t *testing.T) {
	// Shorter than even the BRC-12 header
	_, err := Decode(make([]byte, HeaderSizeLegacy-1))
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort, got %v", err)
	}
}

func TestDecodeV2ErrTooShort(t *testing.T) {
	// Long enough for BRC-12 but not BRC-124
	buf := make([]byte, HeaderSizeLegacy)
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	buf[6] = FrameVerV2
	_, err := Decode(buf)
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort for BRC-124 with only %d bytes, got %v", HeaderSizeLegacy, err)
	}
}

func TestDecodeErrBadMagic(t *testing.T) {
	buf := make([]byte, HeaderSize)
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error for bad magic, got nil")
	}
}

func TestDecodeErrBadVer(t *testing.T) {
	buf := make([]byte, HeaderSize)
	buf[0], buf[1], buf[2], buf[3] = 0xE3, 0xE1, 0xF3, 0xE8
	buf[6] = 0xFF
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error for bad frame version, got nil")
	}
}

func TestDecodeErrTruncated(t *testing.T) {
	f := makeFrame(0x01, []byte("payload"))
	buf := make([]byte, HeaderSize+len(f.Payload)) // Payload starts at offset HeaderSize
	n, _ := Encode(f, buf)
	_, err := Decode(buf[:n-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestEncodeBufferTooSmall(t *testing.T) {
	f := makeFrame(0x01, []byte("payload"))
	_, err := Encode(f, make([]byte, 1))
	if err == nil {
		t.Fatal("want error for buffer too small, got nil")
	}
}
