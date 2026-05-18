// BRC-130 fragment frame encode/decode.

package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// FragFrame is the parsed in-memory representation of a BRC-130 fragment
// datagram (FrameVer 0x03, 104-byte header).
//
// FragData is a zero-copy slice pointing into the buffer passed to
// [DecodeFragment]; the buffer must remain valid for the lifetime of the
// FragFrame.
type FragFrame struct {
	TxID           [32]byte // Identical across all fragments of one frame
	HashKey        uint64   // Stable per-flow identifier (same as parent flow); 0 = unstamped
	SeqNum         uint64   // Per-fragment monotonic counter; 0 = unstamped
	SubtreeID      [32]byte // Inherited from the original frame
	OrigPayloadLen uint32   // Total unfragmented payload size in bytes
	FragIndex      uint16   // 0-based index of this fragment
	FragTotal      uint16   // Total number of fragments in this frame
	OrigFrameVer   byte     // Original FrameVer before fragmentation (0 = default to FrameVerV2)
	MsgType        byte     // Frame-type-specific MsgType from byte 7 (e.g. BlockMsgAnnounce, SubtreeMsgHashesOnly)
	FragData       []byte   // Raw fragment bytes (zero-copy slice into decode buffer)
}

// DecodeFragment parses a raw BRC-130 fragment datagram into a FragFrame.
//
// The returned FragFrame.FragData is a zero-copy slice into buf. The caller
// must not modify or reuse buf while the FragFrame is in scope.
//
// Possible errors: [ErrTooShort], [ErrBadMagic], [ErrBadVer],
// [ErrBadFrag], or [io.ErrUnexpectedEOF] if the datagram is truncated
// relative to the declared fragment data length.
func DecodeFragment(buf []byte) (*FragFrame, error) {
	if len(buf) < HeaderSizeLegacy {
		return nil, ErrTooShort
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != MagicBSV {
		return nil, fmt.Errorf("%w: got 0x%08X", ErrBadMagic, magic)
	}
	if buf[6] != FrameVerV3 {
		return nil, fmt.Errorf("%w: got 0x%02X, want 0x03", ErrBadVer, buf[6])
	}
	if len(buf) < HeaderSizeV3 {
		return nil, ErrTooShort
	}

	fragDataLen := int(binary.BigEndian.Uint32(buf[88:92]))
	if len(buf)-HeaderSizeV3 < fragDataLen {
		return nil, io.ErrUnexpectedEOF
	}

	fragIndex := binary.BigEndian.Uint16(buf[96:98])
	fragTotal := binary.BigEndian.Uint16(buf[98:100])

	if fragTotal == 0 || fragIndex >= fragTotal {
		return nil, fmt.Errorf("%w: FragIndex=%d FragTotal=%d", ErrBadFrag, fragIndex, fragTotal)
	}

	ff := &FragFrame{
		HashKey:        binary.BigEndian.Uint64(buf[40:48]),
		SeqNum:         binary.BigEndian.Uint64(buf[48:56]),
		OrigPayloadLen: binary.BigEndian.Uint32(buf[92:96]),
		FragIndex:      fragIndex,
		FragTotal:      fragTotal,
		OrigFrameVer:   buf[100],
		MsgType:        buf[7],
		FragData:       buf[HeaderSizeV3 : HeaderSizeV3+fragDataLen],
	}
	copy(ff.TxID[:], buf[8:40])
	copy(ff.SubtreeID[:], buf[56:88])
	return ff, nil
}

// EncodeFragment serialises a BRC-130 fragment datagram into buf and returns
// the number of bytes written.
//
// hashKey and seqNum are the proxy-stamped values for this fragment. fragData
// is the slice of the original payload belonging to this fragment.
// buf must be at least [HeaderSizeV3] + len(fragData) bytes.
func EncodeFragment(
	buf []byte,
	txID [32]byte,
	subtreeID [32]byte,
	hashKey uint64,
	seqNum uint64,
	origPayloadLen uint32,
	fragIndex uint16,
	fragTotal uint16,
	origFrameVer byte,
	fragData []byte,
) (int, error) {
	total := HeaderSizeV3 + len(fragData)
	if len(buf) < total {
		return 0, fmt.Errorf("frame: buffer too small (%d bytes, need %d)", len(buf), total)
	}

	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = FrameVerV3
	buf[7] = 0
	copy(buf[8:40], txID[:])
	binary.BigEndian.PutUint64(buf[40:48], hashKey)
	binary.BigEndian.PutUint64(buf[48:56], seqNum)
	copy(buf[56:88], subtreeID[:])
	binary.BigEndian.PutUint32(buf[88:92], uint32(len(fragData)))
	binary.BigEndian.PutUint32(buf[92:96], origPayloadLen)
	binary.BigEndian.PutUint16(buf[96:98], fragIndex)
	binary.BigEndian.PutUint16(buf[98:100], fragTotal)
	buf[100] = origFrameVer
	buf[101] = 0
	buf[102] = 0
	buf[103] = 0
	copy(buf[HeaderSizeV3:], fragData)

	return total, nil
}

// IsFragment reports whether buf begins with a valid BRC-130 fragment header
// (magic + FrameVer == 0x03) without performing a full decode.
// It returns false for any buffer shorter than [HeaderSizeLegacy].
func IsFragment(buf []byte) bool {
	if len(buf) < HeaderSizeLegacy {
		return false
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return false
	}
	return buf[6] == FrameVerV3
}
