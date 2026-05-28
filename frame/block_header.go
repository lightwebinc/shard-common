// BRC-135 block header frame encode/decode.
//
// A FrameVer 0x07 frame carries a single raw 80-byte BSV block header on the
// emitter's egress channel (typically GroupBlockHeader = 0xFFFA). It is
// derived from a BRC-131 BlockAnnounce by extracting the first 80 bytes of
// the announce payload and re-wrapping them in a 172-byte frame
// (92-byte BRC-124-compatible header + 80-byte payload).
//
// The emitter stamps HashKey and SeqNum using its own identity:
//
//	HashKey = XXH64(emitterIPv6 ∥ 0xFFFE [BE uint32] ∥ zeros[32])
//	SeqNum  = monotonic per-emitter counter, starting at 1
//
// BRC-135 frames are NOT retransmitted via BRC-126 on the primary fabric;
// loss recovery is by re-emission from upstream BRC-131 or application-level
// header sync.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// BlockHeaderFrameSize is the fixed total size of a BRC-135 datagram
	// (HeaderSize + BlockHeaderSize = 92 + 80 = 172 bytes).
	BlockHeaderFrameSize = HeaderSize + BlockHeaderSize
)

// ErrBadBlockHeaderLen is returned when a BRC-135 datagram declares a
// PayloadLen other than [BlockHeaderSize] (80).
var ErrBadBlockHeaderLen = errors.New("frame: BRC-135 PayloadLen must equal BlockHeaderSize (80)")

// EncodeBlockHeader serialises a BRC-135 block header frame into buf and
// returns the number of bytes written (always [BlockHeaderFrameSize]).
//
//   - blockHash: SHA256d of the 80-byte header in internal byte order
//     (identical to the ContentID field of the source BRC-131 BlockAnnounce).
//   - hashKey: stable per-emitter flow identifier. Callers typically derive
//     it once via seqhash.Hash(emitterIPv6, 0xFFFE, zeroSubtreeID) and reuse
//     it for the lifetime of the emitter process.
//   - seqNum: monotonic per-emitter counter, starting at 1.
//   - header80: the raw 80-byte BSV block header; must be exactly
//     [BlockHeaderSize] bytes.
//   - buf: destination buffer; must be at least [BlockHeaderFrameSize] bytes.
//
// Returns an error if buf is too small or header80 is not 80 bytes.
func EncodeBlockHeader(blockHash [32]byte, hashKey, seqNum uint64, header80 []byte, buf []byte) (int, error) {
	if len(header80) != BlockHeaderSize {
		return 0, fmt.Errorf("%w: got %d bytes", ErrBadBlockHeaderLen, len(header80))
	}
	if len(buf) < BlockHeaderFrameSize {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), BlockHeaderFrameSize)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV7
	buf[7] = 0 // Reserved
	copy(buf[8:40], blockHash[:])
	binary.BigEndian.PutUint64(buf[40:48], hashKey)
	binary.BigEndian.PutUint64(buf[48:56], seqNum)
	// LayoutPad32 at offsets 56–87: zero-fill for layout symmetry with BRC-124.
	for i := 56; i < 88; i++ {
		buf[i] = 0
	}
	binary.BigEndian.PutUint32(buf[88:92], uint32(BlockHeaderSize))
	copy(buf[92:BlockHeaderFrameSize], header80)

	return BlockHeaderFrameSize, nil
}

// DecodeBlockHeader parses a raw BRC-135 block header datagram into a Frame
// with Version=FrameVerV7. TxID carries the 32-byte BlockHash; Payload is a
// zero-copy slice into buf for the 80-byte block header.
//
// The caller must not modify or reuse buf while the returned Frame is in scope.
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer],
// [ErrBadBlockHeaderLen], or [io.ErrUnexpectedEOF] if the datagram is shorter
// than [BlockHeaderFrameSize].
func DecodeBlockHeader(buf []byte) (*Frame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV7 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x07", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}
	payLen := int(binary.BigEndian.Uint32(buf[88:92]))
	if payLen != BlockHeaderSize {
		return nil, fmt.Errorf("%w: got %d", ErrBadBlockHeaderLen, payLen)
	}
	if len(buf) < BlockHeaderFrameSize {
		return nil, io.ErrUnexpectedEOF
	}
	f := &Frame{Version: FrameVerV7}
	copy(f.TxID[:], buf[8:40]) // BlockHash carried in the TxID slot
	f.HashKey = binary.BigEndian.Uint64(buf[40:48])
	f.SeqNum = binary.BigEndian.Uint64(buf[48:56])
	// SubtreeID remains zero (LayoutPad32 in the spec).
	f.Payload = buf[HeaderSize:BlockHeaderFrameSize]
	return f, nil
}

// IsBlockHeaderFrame reports whether buf begins with a valid BRC-135 block
// header frame (magic + FrameVer == 0x07) without performing a full decode.
// It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsBlockHeaderFrame(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV7
}
