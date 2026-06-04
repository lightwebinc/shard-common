package frame

import (
	"encoding/binary"
	"errors"
)

// ErrSubtreeGroupAnnounceTooShort is returned by [DecodeSubtreeGroupAnnounce] when the
// buffer is shorter than [SubtreeGroupAnnounceSize].
var ErrSubtreeGroupAnnounceTooShort = errors.New("subtree_group_announce: datagram shorter than 64 bytes")

// SubtreeGroupAnnounce is the in-memory representation of a BRC-127 SubtreeGroupAnnounce
// datagram. It maps a single SubtreeID to a GroupID with a TTL.
type SubtreeGroupAnnounce struct {
	SubtreeID [32]byte // SHA-256 subtree root hash (from BRC-124/BRC-128 frame header)
	GroupID   [16]byte // 128-bit group identifier, big-endian
	Epoch     uint32   // Unix timestamp (seconds) when this announcement was created
	TTL       uint16   // Validity in seconds; 0 = use listener default
}

// EncodeSubtreeGroupAnnounce serialises a into buf, which must be at least
// [SubtreeGroupAnnounceSize] bytes long. It returns the number of bytes written
// (always [SubtreeGroupAnnounceSize] on success).
func EncodeSubtreeGroupAnnounce(a *SubtreeGroupAnnounce, buf []byte) (int, error) {
	if len(buf) < SubtreeGroupAnnounceSize {
		return 0, errors.New("subtree_group_announce: buffer too small")
	}
	binary.BigEndian.PutUint32(buf[0:4], MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], ProtoVer)
	buf[6] = MsgTypeSubtreeGroupAnnounce
	buf[7] = 0x00 // Flags reserved
	copy(buf[8:40], a.SubtreeID[:])
	copy(buf[40:56], a.GroupID[:])
	binary.BigEndian.PutUint32(buf[56:60], a.Epoch)
	binary.BigEndian.PutUint16(buf[60:62], a.TTL)
	buf[62] = 0x00 // Reserved
	buf[63] = 0x00 // Reserved
	return SubtreeGroupAnnounceSize, nil
}

// DecodeSubtreeGroupAnnounce parses a 64-byte SubtreeGroupAnnounce datagram from buf.
// Returns [ErrBadMagic] if the magic bytes are wrong, [ErrSubtreeGroupAnnounceTooShort]
// if the buffer is too short, or an error if the MsgType is not
// [MsgTypeSubtreeGroupAnnounce].
func DecodeSubtreeGroupAnnounce(buf []byte) (*SubtreeGroupAnnounce, error) {
	if len(buf) < SubtreeGroupAnnounceSize {
		return nil, ErrSubtreeGroupAnnounceTooShort
	}
	if binary.BigEndian.Uint32(buf[0:4]) != MagicBSV {
		return nil, ErrBadMagic
	}
	if buf[6] != MsgTypeSubtreeGroupAnnounce {
		return nil, errors.New("subtree_group_announce: unexpected MsgType")
	}
	a := &SubtreeGroupAnnounce{
		Epoch: binary.BigEndian.Uint32(buf[56:60]),
		TTL:   binary.BigEndian.Uint16(buf[60:62]),
	}
	copy(a.SubtreeID[:], buf[8:40])
	copy(a.GroupID[:], buf[40:56])
	return a, nil
}
