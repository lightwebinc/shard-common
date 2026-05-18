// BRC-131 block control frame encode/decode.
//
// A FrameVer 0x04 frame uses the same 92-byte header layout as BRC-124 but
// carries block control payloads (BlockAnnounce or CoinbaseTx) on the
// CtrlGroupControl multicast channel (FF0E::B:FFFE).

package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// BlockFrame is the parsed in-memory representation of a BRC-131 block control
// datagram (FrameVer 0x04, 92-byte header).
//
// Payload is a zero-copy slice pointing into the buffer passed to
// [DecodeBlock]; the buffer must remain valid for the lifetime of the
// BlockFrame.
type BlockFrame struct {
	MsgType   byte     // BlockMsgAnnounce or BlockMsgCoinbase
	ContentID [32]byte // BlockHash (announce) or CoinbaseTxID (coinbase)
	HashKey   uint64   // Proxy-stamped; XXH64(sender ∥ 0xFFFE ∥ zeros)
	SeqNum    uint64   // Proxy-stamped; monotonic per sender
	Payload   []byte   // Message-specific payload
}

// DecodeBlock parses a raw BRC-131 block control datagram into a BlockFrame.
//
// The returned BlockFrame.Payload is a zero-copy slice into buf. The caller
// must not modify or reuse buf while the BlockFrame is in scope.
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer],
// [ErrBadBlockMsg], or [io.ErrUnexpectedEOF] if the datagram is truncated
// relative to the declared payload length.
func DecodeBlock(buf []byte) (*BlockFrame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV4 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x04", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}

	msgType := buf[7]
	if msgType != BlockMsgAnnounce && msgType != BlockMsgCoinbase {
		return nil, fmt.Errorf("%w: got 0x%02X", ErrBadBlockMsg, msgType)
	}

	payLen := int(binary.BigEndian.Uint32(buf[88:92]))
	if len(buf)-HeaderSize < payLen {
		return nil, io.ErrUnexpectedEOF
	}

	bf := &BlockFrame{
		MsgType: msgType,
		HashKey: binary.BigEndian.Uint64(buf[40:48]),
		SeqNum:  binary.BigEndian.Uint64(buf[48:56]),
		Payload: buf[HeaderSize : HeaderSize+payLen],
	}
	copy(bf.ContentID[:], buf[8:40])
	return bf, nil
}

// EncodeBlock serialises a BRC-131 block control frame into buf and returns
// the number of bytes written.
// buf must be at least HeaderSize + len(f.Payload) bytes long.
func EncodeBlock(f *BlockFrame, buf []byte) (int, error) {
	total := HeaderSize + len(f.Payload)
	if len(buf) < total {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV4
	buf[7] = f.MsgType
	copy(buf[8:40], f.ContentID[:])
	binary.BigEndian.PutUint64(buf[40:48], f.HashKey)
	binary.BigEndian.PutUint64(buf[48:56], f.SeqNum)
	// Reserved32 at offset 56–87: all zeros (single flow per sender)
	for i := 56; i < 88; i++ {
		buf[i] = 0
	}
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(f.Payload)))
	copy(buf[92:], f.Payload)

	return total, nil
}

// IsBlockFrame reports whether buf begins with a valid BRC-131 block control
// header (magic + FrameVer == 0x04) without performing a full decode.
// It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsBlockFrame(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV4
}
