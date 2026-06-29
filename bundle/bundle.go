// Package bundle implements BRC-142, the coalescing ("bundle") frame format:
// many small BSV transactions of one (group, subtree) flow packed into a single
// datagram, the inverse of BRC-130 fragmentation. It provides the wire codec
// ([Encode]/[Decode]), the coalescer that packs frames into bundles
// ([Coalescer]), the decoalescer that splits a bundle back into individual
// frames ([Decoalesce]), and the relay re-bucketer ([Rebucketer]).
//
// # Wire format (FrameVer 0x08)
//
// All multi-byte integers are big-endian. The header is 66 bytes.
//
//	Offset  Size  Field         Notes
//	------  ----  -----         -----
//	     0     4  Network magic 0xE3E1F3E8
//	     4     2  Protocol ver  0x02BF
//	     6     1  Frame version 0x08 (BRC-142 bundle)
//	     7     1  Flags         bit0 = per-member TxIDs present (all-or-none)
//	     8    32  SubtreeID     the single subtree shared by all members
//	    40     8  HashKey       XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID); flow id
//	    48     8  SeqNum        monotonic per (sender, group, subtree) bundle flow
//	    56     2  GroupIdx      shard group the bundle was built for
//	    58     1  ShardBits     shard-bit width GroupIdx was computed at (1..12)
//	    59     1  Reserved      0x00
//	    60     2  TxCount       member count (uint16)
//	    62     4  PayloadLen    total member-section length (uint32); bounds the parse
//	    66     *  Members       [ TxLen u16 | (TxID 32B if flag) | tx bytes ] × TxCount
//
// The per-member length prefix is a fixed uint16 (a member is ≤ one datagram, so
// 16 bits suffices and a fixed width keeps the parse branch-free). EF members
// self-identify via the BRC-30/BRC-128 marker, so no per-member type flag is
// needed.
package bundle

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lightwebinc/shard-common/frame"
)

// Wire constants.
const (
	// FrameVerBundle is the BRC-142 bundle frame version (frame byte 6).
	FrameVerBundle = frame.FrameVerV8

	// HeaderSize is the fixed bundle header size in bytes; members begin here.
	HeaderSize = 66

	// FlagTxIDsPresent (Flags bit 0) indicates each member is preceded by its
	// 32-byte TxID. The flag is all-or-none across a bundle.
	FlagTxIDsPresent uint8 = 1 << 0

	// MaxMembers is the uint16 TxCount ceiling.
	MaxMembers = 1<<16 - 1

	// MaxMemberTxLen is the largest member transaction length the uint16 length
	// prefix can express (a length ceiling, not a member count — cf. MaxMembers).
	MaxMemberTxLen = 1<<16 - 1

	memberLenSize  = 2
	memberTxIDSize = 32
)

// Sentinel errors returned by [Decode] and [Bundle.Encode].
var (
	// ErrTooShort is returned when the datagram is shorter than the 66-byte header.
	ErrTooShort = errors.New("bundle: datagram shorter than header")
	// ErrBadMagic is returned when the first four bytes do not match the BSV magic.
	ErrBadMagic = errors.New("bundle: invalid BSV magic")
	// ErrBadVer is returned when the frame version byte is not FrameVerBundle.
	ErrBadVer = errors.New("bundle: not a bundle frame version")
	// ErrTruncated is returned when the member section is shorter than declared.
	ErrTruncated = errors.New("bundle: member section truncated")
	// ErrTooMany is returned when the member count exceeds the uint16 ceiling.
	ErrTooMany = errors.New("bundle: member count exceeds uint16")
	// ErrMemberBig is returned when a member transaction exceeds the uint16 length.
	ErrMemberBig = errors.New("bundle: member tx length exceeds uint16")
	// ErrCountMismatch is returned when the TxCount members do not consume the
	// declared PayloadLen exactly (TxCount and PayloadLen disagree).
	ErrCountMismatch = errors.New("bundle: member section not consumed exactly")
)

// Member is one transaction inside a bundle. Tx is the serialised BSV
// transaction (BRC-12 raw or BRC-30 Extended Format — EF self-identifies via its
// marker). TxID is valid only when the bundle has [FlagTxIDsPresent] set.
type Member struct {
	TxID [32]byte
	Tx   []byte
}

// Bundle is the parsed in-memory representation of a BRC-142 coalescing frame.
type Bundle struct {
	Flags     uint8
	SubtreeID [32]byte
	HashKey   uint64
	SeqNum    uint64
	GroupIdx  uint16
	ShardBits uint8
	Members   []Member
}

// TxIDsPresent reports whether members carry their 32-byte TxID on the wire.
func (b *Bundle) TxIDsPresent() bool { return b.Flags&FlagTxIDsPresent != 0 }

// memberSectionLen returns the encoded size of the member section in bytes.
func (b *Bundle) memberSectionLen() int {
	per := memberLenSize
	if b.TxIDsPresent() {
		per += memberTxIDSize
	}
	n := per * len(b.Members)
	for i := range b.Members {
		n += len(b.Members[i].Tx)
	}
	return n
}

// MemberOverhead returns the per-member wire overhead (length prefix, plus the
// 32-byte TxID when carried). Callers use it to budget a bundle against the MTU.
func MemberOverhead(carryTxID bool) int {
	if carryTxID {
		return memberLenSize + memberTxIDSize
	}
	return memberLenSize
}

// Encode serialises the bundle into a freshly allocated datagram.
func (b *Bundle) Encode() ([]byte, error) {
	if len(b.Members) > MaxMembers {
		return nil, fmt.Errorf("%w: %d", ErrTooMany, len(b.Members))
	}
	withTxID := b.TxIDsPresent()
	payLen := b.memberSectionLen()

	buf := make([]byte, HeaderSize+payLen)
	binary.BigEndian.PutUint32(buf[0:4], frame.MagicBSV)
	binary.BigEndian.PutUint16(buf[4:6], frame.ProtoVer)
	buf[6] = FrameVerBundle
	buf[7] = b.Flags
	copy(buf[8:40], b.SubtreeID[:])
	binary.BigEndian.PutUint64(buf[40:48], b.HashKey)
	binary.BigEndian.PutUint64(buf[48:56], b.SeqNum)
	binary.BigEndian.PutUint16(buf[56:58], b.GroupIdx)
	buf[58] = b.ShardBits
	buf[59] = 0 // reserved
	binary.BigEndian.PutUint16(buf[60:62], uint16(len(b.Members)))
	binary.BigEndian.PutUint32(buf[62:66], uint32(payLen))

	off := HeaderSize
	for i := range b.Members {
		m := &b.Members[i]
		if len(m.Tx) > MaxMemberTxLen {
			return nil, fmt.Errorf("%w: %d", ErrMemberBig, len(m.Tx))
		}
		binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(m.Tx)))
		off += memberLenSize
		if withTxID {
			copy(buf[off:off+memberTxIDSize], m.TxID[:])
			off += memberTxIDSize
		}
		copy(buf[off:off+len(m.Tx)], m.Tx)
		off += len(m.Tx)
	}
	return buf, nil
}

// Decode parses a bundle datagram. Member.Tx slices alias buf (zero-copy); the
// caller must keep buf valid for the lifetime of the returned Bundle.
func Decode(buf []byte) (*Bundle, error) {
	if len(buf) < HeaderSize {
		return nil, ErrTooShort
	}
	if m := binary.BigEndian.Uint32(buf[0:4]); m != frame.MagicBSV {
		return nil, fmt.Errorf("%w: 0x%08X", ErrBadMagic, m)
	}
	if buf[6] != FrameVerBundle {
		return nil, fmt.Errorf("%w: 0x%02X", ErrBadVer, buf[6])
	}

	b := &Bundle{Flags: buf[7]}
	copy(b.SubtreeID[:], buf[8:40])
	b.HashKey = binary.BigEndian.Uint64(buf[40:48])
	b.SeqNum = binary.BigEndian.Uint64(buf[48:56])
	b.GroupIdx = binary.BigEndian.Uint16(buf[56:58])
	b.ShardBits = buf[58]
	count := int(binary.BigEndian.Uint16(buf[60:62]))
	payLen := int(binary.BigEndian.Uint32(buf[62:66]))
	if len(buf)-HeaderSize < payLen {
		return nil, ErrTruncated
	}

	withTxID := b.TxIDsPresent()
	b.Members = make([]Member, 0, count)
	off := HeaderSize
	end := HeaderSize + payLen
	for i := 0; i < count; i++ {
		if off+memberLenSize > end {
			return nil, ErrTruncated
		}
		txLen := int(binary.BigEndian.Uint16(buf[off : off+2]))
		off += memberLenSize
		var m Member
		if withTxID {
			if off+memberTxIDSize > end {
				return nil, ErrTruncated
			}
			copy(m.TxID[:], buf[off:off+memberTxIDSize])
			off += memberTxIDSize
		}
		if off+txLen > end {
			return nil, ErrTruncated
		}
		m.Tx = buf[off : off+txLen]
		off += txLen
		b.Members = append(b.Members, m)
	}
	// The TxCount members must consume the declared PayloadLen exactly; leftover
	// bytes mean TxCount and PayloadLen disagree (a malformed or misaligned
	// bundle), which is rejected rather than silently ignored.
	if off != end {
		return nil, ErrCountMismatch
	}
	return b, nil
}
