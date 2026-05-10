package frame

import (
	"encoding/binary"
	"errors"
)

// ErrSubtreeAnnounceTooShort is returned by [DecodeSubtreeAnnounce] when the
// buffer is shorter than [SubtreeAnnounceSize].
var ErrSubtreeAnnounceTooShort = errors.New("subtree_announce: datagram shorter than 64 bytes")

// SubtreeAnnounce is the in-memory representation of a BRC-127 SubtreeAnnounce
// datagram. It maps a single SubtreeID to a GroupID with a TTL.
type SubtreeAnnounce struct {
	SubtreeID [32]byte // SHA-256 subtree root hash (from BRC-124 frame header)
	GroupID   [16]byte // 128-bit group identifier, big-endian
	Epoch     uint32   // Unix timestamp (seconds) when this announcement was created
	TTL       uint16   // Validity in seconds; 0 = use listener default
}

// EncodeSubtreeAnnounce serialises a into buf, which must be at least
// [SubtreeAnnounceSize] bytes long. It returns the number of bytes written
// (always [SubtreeAnnounceSize] on success).
func EncodeSubtreeAnnounce(a *SubtreeAnnounce, buf []byte) (int, error) {
	if len(buf) < SubtreeAnnounceSize {
		return 0, errors.New("subtree_announce: buffer too small")
	}
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = MsgTypeSubtreeAnnounce
	buf[7] = 0x00 // Flags reserved
	copy(buf[8:40], a.SubtreeID[:])
	copy(buf[40:56], a.GroupID[:])
	binary.BigEndian.PutUint32(buf[56:60], a.Epoch)
	binary.BigEndian.PutUint16(buf[60:62], a.TTL)
	buf[62] = 0x00 // Reserved
	buf[63] = 0x00 // Reserved
	return SubtreeAnnounceSize, nil
}

// DecodeSubtreeAnnounce parses a 64-byte SubtreeAnnounce datagram from buf.
// Returns [ErrBadMagic] if the magic bytes are wrong, [ErrSubtreeAnnounceTooShort]
// if the buffer is too short, or an error if the MsgType is not
// [MsgTypeSubtreeAnnounce].
func DecodeSubtreeAnnounce(buf []byte) (*SubtreeAnnounce, error) {
	if len(buf) < SubtreeAnnounceSize {
		return nil, ErrSubtreeAnnounceTooShort
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return nil, ErrBadMagic
	}
	if buf[6] != MsgTypeSubtreeAnnounce {
		return nil, errors.New("subtree_announce: unexpected MsgType")
	}
	a := &SubtreeAnnounce{
		Epoch: binary.BigEndian.Uint32(buf[56:60]),
		TTL:   binary.BigEndian.Uint16(buf[60:62]),
	}
	copy(a.SubtreeID[:], buf[8:40])
	copy(a.GroupID[:], buf[40:56])
	return a, nil
}
