package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// buildBlockBuf constructs a minimal valid BRC-131 block control datagram.
func buildBlockBuf(msgType byte, contentIDByte byte, payload []byte) []byte {
	buf := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV4
	buf[7] = msgType
	buf[8] = contentIDByte
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)
	return buf
}

func TestFrameVerV4(t *testing.T) {
	if FrameVerV4 != 0x04 {
		t.Errorf("FrameVerV4 = 0x%02X, want 0x04", FrameVerV4)
	}
}

func TestBlockMsgConstants(t *testing.T) {
	if BlockMsgAnnounce != 0x01 {
		t.Errorf("BlockMsgAnnounce = 0x%02X, want 0x01", BlockMsgAnnounce)
	}
	if BlockMsgCoinbase != 0x02 {
		t.Errorf("BlockMsgCoinbase = 0x%02X, want 0x02", BlockMsgCoinbase)
	}
}

func TestEncodeBlockRoundTrip_Announce(t *testing.T) {
	var contentID [32]byte
	contentID[0] = 0xAA
	payload := []byte("block-announce-payload")

	bf := &BlockFrame{
		MsgType:   BlockMsgAnnounce,
		ContentID: contentID,
		HashKey:   0x1234567890ABCDEF,
		SeqNum:    42,
		Payload:   payload,
	}

	buf := make([]byte, HeaderSize+len(payload))
	n, err := EncodeBlock(bf, buf)
	if err != nil {
		t.Fatalf("EncodeBlock: %v", err)
	}
	if n != HeaderSize+len(payload) {
		t.Fatalf("EncodeBlock returned %d bytes, want %d", n, HeaderSize+len(payload))
	}

	decoded, err := DecodeBlock(buf[:n])
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}

	if decoded.MsgType != BlockMsgAnnounce {
		t.Errorf("MsgType = 0x%02X, want 0x%02X", decoded.MsgType, BlockMsgAnnounce)
	}
	if decoded.ContentID != contentID {
		t.Errorf("ContentID mismatch")
	}
	if decoded.HashKey != 0x1234567890ABCDEF {
		t.Errorf("HashKey = %x, want %x", decoded.HashKey, uint64(0x1234567890ABCDEF))
	}
	if decoded.SeqNum != 42 {
		t.Errorf("SeqNum = %d, want 42", decoded.SeqNum)
	}
	if !bytes.Equal(decoded.Payload, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestEncodeBlockRoundTrip_Coinbase(t *testing.T) {
	var contentID [32]byte
	contentID[0] = 0xBB
	payload := []byte("raw-coinbase-tx-bytes")

	bf := &BlockFrame{
		MsgType:   BlockMsgCoinbase,
		ContentID: contentID,
		HashKey:   0xDEADBEEFCAFEBABE,
		SeqNum:    99,
		Payload:   payload,
	}

	buf := make([]byte, HeaderSize+len(payload))
	n, err := EncodeBlock(bf, buf)
	if err != nil {
		t.Fatalf("EncodeBlock: %v", err)
	}

	decoded, err := DecodeBlock(buf[:n])
	if err != nil {
		t.Fatalf("DecodeBlock: %v", err)
	}

	if decoded.MsgType != BlockMsgCoinbase {
		t.Errorf("MsgType = 0x%02X, want 0x%02X", decoded.MsgType, BlockMsgCoinbase)
	}
	if decoded.SeqNum != 99 {
		t.Errorf("SeqNum = %d, want 99", decoded.SeqNum)
	}
}

func TestDecodeBlock_Reserved32Zeros(t *testing.T) {
	payload := []byte("test")
	bf := &BlockFrame{
		MsgType: BlockMsgAnnounce,
		Payload: payload,
	}
	buf := make([]byte, HeaderSize+len(payload))
	if _, err := EncodeBlock(bf, buf); err != nil {
		t.Fatal(err)
	}
	// Verify bytes 56–87 are all zero (Reserved32).
	for i := 56; i < 88; i++ {
		if buf[i] != 0 {
			t.Errorf("buf[%d] = 0x%02X, want 0x00 (Reserved32)", i, buf[i])
		}
	}
}

func TestDecodeBlock_HeaderOffsets(t *testing.T) {
	var contentID [32]byte
	contentID[0] = 0x11
	payload := []byte{0xFF}

	bf := &BlockFrame{
		MsgType:   BlockMsgCoinbase,
		ContentID: contentID,
		HashKey:   0xAABBCCDDEEFF0011,
		SeqNum:    0x1122334455667788,
		Payload:   payload,
	}

	buf := make([]byte, HeaderSize+len(payload))
	if _, err := EncodeBlock(bf, buf); err != nil {
		t.Fatal(err)
	}

	// Check specific offsets.
	if buf[6] != FrameVerV4 {
		t.Errorf("buf[6] (FrameVer) = 0x%02X, want 0x04", buf[6])
	}
	if buf[7] != BlockMsgCoinbase {
		t.Errorf("buf[7] (BlockMsgType) = 0x%02X, want 0x02", buf[7])
	}
	if buf[8] != 0x11 {
		t.Errorf("buf[8] (ContentID[0]) = 0x%02X, want 0x11", buf[8])
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
}

func TestDecodeBlock_BadFrameVer(t *testing.T) {
	buf := buildBlockBuf(BlockMsgAnnounce, 0x01, nil)
	buf[6] = FrameVerV2
	_, err := DecodeBlock(buf)
	if err == nil {
		t.Fatal("want error for FrameVer=0x02, got nil")
	}
	if !errors.Is(err, ErrBadVer) {
		t.Errorf("want ErrBadVer, got %v", err)
	}
}

func TestDecodeBlock_BadMagic(t *testing.T) {
	buf := buildBlockBuf(BlockMsgAnnounce, 0x01, nil)
	buf[0] = 0x00
	_, err := DecodeBlock(buf)
	if err == nil {
		t.Fatal("want error for bad magic, got nil")
	}
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("want ErrBadMagic, got %v", err)
	}
}

func TestDecodeBlock_BadMsgType(t *testing.T) {
	buf := buildBlockBuf(0x00, 0x01, nil)
	_, err := DecodeBlock(buf)
	if err == nil {
		t.Fatal("want error for MsgType=0x00, got nil")
	}
	if !errors.Is(err, ErrBadBlockMsg) {
		t.Errorf("want ErrBadBlockMsg, got %v", err)
	}

	buf2 := buildBlockBuf(0xFF, 0x01, nil)
	_, err = DecodeBlock(buf2)
	if !errors.Is(err, ErrBadBlockMsg) {
		t.Errorf("want ErrBadBlockMsg for 0xFF, got %v", err)
	}
}

func TestDecodeBlock_TooShort(t *testing.T) {
	buf := buildBlockBuf(BlockMsgAnnounce, 0x01, nil)
	_, err := DecodeBlock(buf[:HeaderSize-1])
	if err != ErrTooShort {
		t.Errorf("want ErrTooShort, got %v", err)
	}
}

func TestDecodeBlock_Truncated(t *testing.T) {
	buf := buildBlockBuf(BlockMsgAnnounce, 0x01, []byte("hello"))
	_, err := DecodeBlock(buf[:len(buf)-1])
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestDecodeBlock_EmptyPayload(t *testing.T) {
	buf := buildBlockBuf(BlockMsgCoinbase, 0x01, nil)
	bf, err := DecodeBlock(buf)
	if err != nil {
		t.Fatalf("DecodeBlock empty payload: %v", err)
	}
	if len(bf.Payload) != 0 {
		t.Errorf("Payload len = %d, want 0", len(bf.Payload))
	}
}

func TestIsBlockFrame(t *testing.T) {
	buf := buildBlockBuf(BlockMsgAnnounce, 0x01, []byte("x"))
	if !IsBlockFrame(buf) {
		t.Error("want IsBlockFrame=true for V4 frame")
	}

	v2buf := make([]byte, HeaderSize+1)
	binary.BigEndian.PutUint32(v2buf[0:4], MagicBSV)
	v2buf[6] = FrameVerV2
	if IsBlockFrame(v2buf) {
		t.Error("want IsBlockFrame=false for V2 frame")
	}

	if IsBlockFrame([]byte{0x01, 0x02}) {
		t.Error("want IsBlockFrame=false for short buffer")
	}
}

func TestDecodeRejectsV4(t *testing.T) {
	buf := buildBlockBuf(BlockMsgAnnounce, 0x01, []byte("data"))
	_, err := Decode(buf)
	if err == nil {
		t.Fatal("want error from Decode for V4 frame, got nil")
	}
	if !errors.Is(err, ErrBadVer) {
		t.Errorf("want ErrBadVer, got %v", err)
	}
}

func TestEncodeBlock_BufferTooSmall(t *testing.T) {
	bf := &BlockFrame{
		MsgType: BlockMsgAnnounce,
		Payload: []byte("data"),
	}
	_, err := EncodeBlock(bf, make([]byte, 10))
	if err == nil {
		t.Fatal("want error for buffer too small, got nil")
	}
}

// TestEncodeFragmentOrigFrameVer_RoundTrip verifies that a non-zero
// OrigFrameVer survives encode/decode.
func TestEncodeFragmentOrigFrameVer_RoundTrip(t *testing.T) {
	var txID [32]byte
	txID[0] = 0xDD
	var subID [32]byte
	fragData := []byte("test-v4-frag")

	buf := make([]byte, HeaderSizeV3+len(fragData))
	n, err := EncodeFragment(buf, txID, subID, 100, 1, 5000, 0, 3, FrameVerV4, fragData)
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}

	ff, err := DecodeFragment(buf[:n])
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}

	if ff.OrigFrameVer != FrameVerV4 {
		t.Errorf("OrigFrameVer = 0x%02X, want 0x%02X", ff.OrigFrameVer, FrameVerV4)
	}

	// Verify padding bytes are zero.
	if buf[101] != 0 || buf[102] != 0 || buf[103] != 0 {
		t.Errorf("Reserved2 padding bytes not zero")
	}
}

// TestEncodeFragmentOrigFrameVer_Zero_DefaultV2 verifies that OrigFrameVer=0
// is correctly stored and read back as 0 (caller maps 0 → FrameVerV2).
func TestEncodeFragmentOrigFrameVer_Zero_DefaultV2(t *testing.T) {
	var txID, subID [32]byte
	fragData := []byte("default")

	buf := make([]byte, HeaderSizeV3+len(fragData))
	if _, err := EncodeFragment(buf, txID, subID, 1, 1, 100, 0, 1, 0, fragData); err != nil {
		t.Fatal(err)
	}

	ff, err := DecodeFragment(buf)
	if err != nil {
		t.Fatal(err)
	}
	if ff.OrigFrameVer != 0 {
		t.Errorf("OrigFrameVer = 0x%02X, want 0x00", ff.OrigFrameVer)
	}
}
