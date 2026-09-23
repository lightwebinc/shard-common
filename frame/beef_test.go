package frame

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func buildBEEFBuf(t *testing.T, f *BEEFFrame) []byte {
	t.Helper()
	buf := make([]byte, HeaderSize+len(f.Payload))
	n, err := EncodeBEEF(f, buf)
	if err != nil {
		t.Fatalf("EncodeBEEF: %v", err)
	}
	if n != HeaderSize+len(f.Payload) {
		t.Fatalf("EncodeBEEF wrote %d bytes, want %d", n, HeaderSize+len(f.Payload))
	}
	return buf
}

func testBEEFFrame() *BEEFFrame {
	f := &BEEFFrame{
		HashKey: 0xDEADBEEFCAFEBABE,
		SeqNum:  42,
		// 0100BEEF marker + arbitrary body — the codec never parses BEEF
		// structure, only carries it verbatim.
		Payload: []byte{0x01, 0x00, 0xBE, 0xEF, 0xAA, 0xBB, 0xCC},
	}
	for i := range f.ContentID {
		f.ContentID[i] = byte(i)
	}
	for i := range f.TopicID {
		f.TopicID[i] = byte(0x80 + i)
	}
	return f
}

func TestFrameVerV9Constant(t *testing.T) {
	if FrameVerV9 != 0x09 {
		t.Fatalf("FrameVerV9 = 0x%02X, want 0x09", FrameVerV9)
	}
}

func TestBEEFRoundTrip(t *testing.T) {
	f := testBEEFFrame()
	buf := buildBEEFBuf(t, f)

	// Field offsets per BRC-148 Appendix A.
	if buf[6] != FrameVerV9 {
		t.Fatalf("version byte = 0x%02X, want 0x09", buf[6])
	}
	if buf[7] != 0 {
		t.Fatalf("reserved byte = 0x%02X, want 0x00", buf[7])
	}
	if got := binary.BigEndian.Uint32(buf[88:92]); got != uint32(len(f.Payload)) {
		t.Fatalf("payload length = %d, want %d", got, len(f.Payload))
	}

	d, err := DecodeBEEF(buf)
	if err != nil {
		t.Fatalf("DecodeBEEF: %v", err)
	}
	if d.ContentID != f.ContentID {
		t.Errorf("ContentID mismatch")
	}
	if d.TopicID != f.TopicID {
		t.Errorf("TopicID mismatch")
	}
	if d.HashKey != f.HashKey || d.SeqNum != f.SeqNum {
		t.Errorf("HashKey/SeqNum = %X/%d, want %X/%d", d.HashKey, d.SeqNum, f.HashKey, f.SeqNum)
	}
	if string(d.Payload) != string(f.Payload) {
		t.Errorf("payload not verbatim")
	}
}

func TestIsBEEFFrame(t *testing.T) {
	buf := buildBEEFBuf(t, testBEEFFrame())
	if !IsBEEFFrame(buf) {
		t.Fatal("IsBEEFFrame = false for valid frame")
	}

	badMagic := append([]byte(nil), buf...)
	badMagic[0] = 0x00
	if IsBEEFFrame(badMagic) {
		t.Error("IsBEEFFrame = true for bad magic")
	}

	badVer := append([]byte(nil), buf...)
	badVer[6] = FrameVerV2
	if IsBEEFFrame(badVer) {
		t.Error("IsBEEFFrame = true for FrameVerV2")
	}

	if IsBEEFFrame(buf[:HeaderSizeLegacy-1]) {
		t.Error("IsBEEFFrame = true for short buffer")
	}
}

func TestDecodeBEEF_Errors(t *testing.T) {
	buf := buildBEEFBuf(t, testBEEFFrame())

	if _, err := DecodeBEEF(buf[:10]); !errors.Is(err, ErrTooShort) {
		t.Errorf("short buffer: err = %v, want ErrTooShort", err)
	}

	badMagic := append([]byte(nil), buf...)
	badMagic[0] = 0x00
	if _, err := DecodeBEEF(badMagic); !errors.Is(err, ErrBadMagic) {
		t.Errorf("bad magic: err = %v, want ErrBadMagic", err)
	}

	badVer := append([]byte(nil), buf...)
	badVer[6] = FrameVerV4
	if _, err := DecodeBEEF(badVer); !errors.Is(err, ErrBadVer) {
		t.Errorf("wrong version: err = %v, want ErrBadVer", err)
	}

	truncated := append([]byte(nil), buf...)
	binary.BigEndian.PutUint32(truncated[88:92], uint32(len(buf))) // declares more than present
	if _, err := DecodeBEEF(truncated); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated payload: err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestDecodeBEEF_DeliverCount(t *testing.T) {
	// Legacy zero reads as one deliverable topic; a stamped count round-trips.
	buf := buildBEEFBuf(t, testBEEFFrame())
	bf, err := DecodeBEEF(buf)
	if err != nil {
		t.Fatalf("DecodeBEEF: %v", err)
	}
	if bf.DeliverCount != BEEFDeliverCountLegacy || bf.Deliverable() != 1 {
		t.Fatalf("legacy byte 7: DeliverCount=%d Deliverable=%d, want 0/1", bf.DeliverCount, bf.Deliverable())
	}

	f := testBEEFFrame()
	f.DeliverCount = 3
	buf = buildBEEFBuf(t, f)
	if buf[7] != 3 {
		t.Fatalf("byte 7 = %d, want 3", buf[7])
	}
	bf, err = DecodeBEEF(buf)
	if err != nil {
		t.Fatalf("DecodeBEEF: %v", err)
	}
	if bf.Deliverable() != 3 {
		t.Fatalf("Deliverable = %d, want 3", bf.Deliverable())
	}
}

func TestDecode_V9ReturnsErrBadVer(t *testing.T) {
	buf := buildBEEFBuf(t, testBEEFFrame())
	if _, err := Decode(buf); !errors.Is(err, ErrBadVer) {
		t.Fatalf("Decode(V9): err = %v, want ErrBadVer steering to DecodeBEEF", err)
	}
}
