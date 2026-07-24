// BRC-148 BEEF object frame encode/decode.
//
// A FrameVer 0x09 frame uses the same 92-byte header layout as BRC-124 but
// carries a BEEF-family transaction object (BRC-62 / BRC-95 / BRC-96)
// verbatim on the BEEF object plane's domain-tagged shard groups
// (IDX 0x1000 + shardIndex(TopicID)). ContentID (SHA-256d of the payload)
// occupies the TxID slot; TopicID (SHA-256 of the overlay topic name)
// occupies the SubtreeID slot. The BEEF encoding version is not duplicated
// in the header — it is the payload's first four bytes.

package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// BEEFFrame is the parsed in-memory representation of a BRC-148 BEEF object
// datagram (FrameVer 0x09, 92-byte header).
//
// Payload is a zero-copy slice pointing into the buffer passed to
// [DecodeBEEF]; the buffer must remain valid for the lifetime of the
// BEEFFrame.
type BEEFFrame struct {
	ContentID [32]byte // SHA-256d(payload) — object identity; keys BRC-130 reassembly
	HashKey   uint64   // Stamped at ingress; XXH64(sender ∥ domain-tagged groupIdx ∥ zeros); 0 = unset
	SeqNum    uint64   // Stamped at ingress; monotonic per (sender, group) flow; 0 = unset
	TopicID   [32]byte // SHA-256(UTF-8 topic name) — delivery-selectivity key
	Payload   []byte   // BEEF object verbatim (leading marker identifies the encoding)
}

// DecodeBEEF parses a raw BRC-148 BEEF object datagram into a BEEFFrame.
//
// The returned BEEFFrame.Payload is a zero-copy slice into buf. The caller
// must not modify or reuse buf while the BEEFFrame is in scope.
//
// The reserved byte at offset 7 is ignored on receive (it is reserved for
// future plane-level message types and MUST be zero on send).
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer], or
// [io.ErrUnexpectedEOF] if the datagram is truncated relative to the
// declared payload length.
func DecodeBEEF(buf []byte) (*BEEFFrame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV9 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x09", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}

	payLen := int(binary.BigEndian.Uint32(buf[88:92]))
	if len(buf)-HeaderSize < payLen {
		return nil, io.ErrUnexpectedEOF
	}

	bf := &BEEFFrame{
		HashKey: binary.BigEndian.Uint64(buf[40:48]),
		SeqNum:  binary.BigEndian.Uint64(buf[48:56]),
		Payload: buf[HeaderSize : HeaderSize+payLen],
	}
	copy(bf.ContentID[:], buf[8:40])
	copy(bf.TopicID[:], buf[56:88])
	return bf, nil
}

// EncodeBEEF serialises a BRC-148 BEEF object frame into buf and returns the
// number of bytes written.
// buf must be at least HeaderSize + len(f.Payload) bytes long.
func EncodeBEEF(f *BEEFFrame, buf []byte) (int, error) {
	total := HeaderSize + len(f.Payload)
	if len(buf) < total {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV9
	buf[7] = 0
	copy(buf[8:40], f.ContentID[:])
	binary.BigEndian.PutUint64(buf[40:48], f.HashKey)
	binary.BigEndian.PutUint64(buf[48:56], f.SeqNum)
	copy(buf[56:88], f.TopicID[:])
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(f.Payload)))
	copy(buf[92:], f.Payload)

	return total, nil
}

// IsBEEFFrame reports whether buf begins with a valid BRC-148 BEEF object
// header (magic + FrameVer == 0x09) without performing a full decode.
// It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsBEEFFrame(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV9
}
