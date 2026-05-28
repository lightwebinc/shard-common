// BRC-132 subtree data frame encode/decode.
//
// A FrameVer 0x05 frame uses the same 92-byte header layout as BRC-124 but
// carries subtree data payloads (transaction hashes or full nodes) on the
// GroupSubtreeAnnounce multicast channel (FF0X::B:FFFB).

package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// SubtreeDataFrame is the parsed in-memory representation of a BRC-132 subtree
// data datagram (FrameVer 0x05, 92-byte header).
//
// Payload is a zero-copy slice pointing into the buffer passed to
// [DecodeSubtreeData]; the buffer must remain valid for the lifetime of the
// SubtreeDataFrame.
type SubtreeDataFrame struct {
	MsgType   byte     // SubtreeMsgHashesOnly or SubtreeMsgFullNodes
	SubtreeID [32]byte // SHA-256 Merkle root hash (content identifier)
	HashKey   uint64   // Proxy-stamped; XXH64(sender ∥ 0xFFFB ∥ subtreeID)
	SeqNum    uint64   // Proxy-stamped; monotonic per (sender, subtree) flow
	Payload   []byte   // Subtree data payload
}

// DecodeSubtreeData parses a raw BRC-132 subtree data datagram into a
// SubtreeDataFrame.
//
// The returned SubtreeDataFrame.Payload is a zero-copy slice into buf. The
// caller must not modify or reuse buf while the SubtreeDataFrame is in scope.
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer],
// [ErrBadSubtreeMsg], or [io.ErrUnexpectedEOF] if the datagram is truncated
// relative to the declared payload length.
func DecodeSubtreeData(buf []byte) (*SubtreeDataFrame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV5 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x05", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}

	msgType := buf[7]
	if msgType != SubtreeMsgHashesOnly && msgType != SubtreeMsgFullNodes {
		return nil, fmt.Errorf("%w: got 0x%02X", ErrBadSubtreeMsg, msgType)
	}

	payLen := int(binary.BigEndian.Uint32(buf[88:92]))
	if len(buf)-HeaderSize < payLen {
		return nil, io.ErrUnexpectedEOF
	}

	sf := &SubtreeDataFrame{
		MsgType: msgType,
		HashKey: binary.BigEndian.Uint64(buf[40:48]),
		SeqNum:  binary.BigEndian.Uint64(buf[48:56]),
		Payload: buf[HeaderSize : HeaderSize+payLen],
	}
	copy(sf.SubtreeID[:], buf[8:40])
	return sf, nil
}

// EncodeSubtreeData serialises a BRC-132 subtree data frame into buf and
// returns the number of bytes written.
// buf must be at least HeaderSize + len(f.Payload) bytes long.
func EncodeSubtreeData(f *SubtreeDataFrame, buf []byte) (int, error) {
	total := HeaderSize + len(f.Payload)
	if len(buf) < total {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV5
	buf[7] = f.MsgType
	copy(buf[8:40], f.SubtreeID[:])
	binary.BigEndian.PutUint64(buf[40:48], f.HashKey)
	binary.BigEndian.PutUint64(buf[48:56], f.SeqNum)
	// LayoutPad32 at offset 56–87: all zeros.
	for i := 56; i < 88; i++ {
		buf[i] = 0
	}
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(f.Payload)))
	copy(buf[92:], f.Payload)

	return total, nil
}

// IsSubtreeDataFrame reports whether buf begins with a valid BRC-132 subtree
// data header (magic + FrameVer == 0x05) without performing a full decode.
// It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsSubtreeDataFrame(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV5
}
