// BRC-148 BEEF object plane codecs: marker/identity helpers, the submission
// record (up-direction, ClassBEEF lane grammar), the delivery record
// (down-direction), and the single-frame multicast wrap.
//
// Unlike the other classes, a ClassBEEF lane does not carry bare objects —
// BEEF bytes are not length-walkable without a full structural parse, which
// the fabric never performs. The lane object is therefore the *submission
// record*, an explicit length-carrying envelope:
//
//	u16  tag         0xBEEF BE (record discriminator on shared ports)
//	u8   recordVer   0x01
//	u8   topicCount  1..15
//	topicCount × { u8 nameLen 1..64 ∥ UTF-8 topic name }
//	u32  objectLen   BE, ≥ 1
//	objectLen bytes  BEEF object (leading marker identifies the encoding)
//
// One record submits one object to one or more topics; the ingress expands it
// into one FrameVer 0x09 frame per topic. The record's leading tag makes it
// grammar-distinct from a framed datagram (magic 0xE3…) and a bare
// transaction (version byte[1] is 0x00) on the shared open port.

package objfmt

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/lightwebinc/shard-common/frame"
)

// BEEF payload version words (uint32 LE of the object's first four bytes).
const (
	// BEEFMarkerV1 is the BRC-62 BEEF version word ("0100BEEF").
	BEEFMarkerV1 uint32 = 4022206465 // 0xEFBE0001
	// BEEFMarkerV2 is the BRC-96 BEEF V2 version word ("0200BEEF").
	BEEFMarkerV2 uint32 = 4022206466 // 0xEFBE0002
	// AtomicBEEFMarker is the BRC-95 Atomic BEEF 4-byte prefix (01 01 01 01),
	// read as uint32 LE like the BEEF version words.
	AtomicBEEFMarker uint32 = 0x01010101
	// beefMarkerHi is the fixed high half of the BEEF-family version-word
	// range: values 0xEFBE0001–0xEFBEFFFF keep the "BEEF" marker (BRC-62).
	beefMarkerHi uint32 = 0xEFBE0000
)

// Submission record wire constants.
const (
	// BEEFRecordTag is the record's leading discriminator (wire bytes BE EF).
	BEEFRecordTag uint16 = 0xBEEF
	// BEEFRecordVer is the submission-record format version.
	BEEFRecordVer byte = 0x01
	// BEEFMaxTopics bounds the topics of one submission.
	BEEFMaxTopics = 15
	// BEEFMaxTopicLen bounds one UTF-8 topic name in bytes.
	BEEFMaxTopicLen = 64
	// beefRecordMin is tag + ver + topicCount.
	beefRecordMin = 4
	// BEEFDeliveryHeaderSize is the delivery record's fixed prefix:
	// 32-byte TopicID + 4-byte BE object length.
	BEEFDeliveryHeaderSize = 36
)

// BEEFVersionWord returns the object's version word — the uint32 LE of its
// first four bytes (the version-filter input). ok is false when the object
// is shorter than four bytes.
func BEEFVersionWord(obj []byte) (word uint32, ok bool) {
	if len(obj) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(obj[0:4]), true
}

// IsBEEFObject reports whether obj leads with a recognised BEEF-family
// marker: a BEEF version word in the BRC-62 marker range (0xEFBE0001–
// 0xEFBEFFFF, covering BEEF and BEEF V2) or the BRC-95 Atomic BEEF prefix.
// It is a fixed-offset sanity gate only — no structure is parsed.
func IsBEEFObject(obj []byte) bool {
	w, ok := BEEFVersionWord(obj)
	if !ok {
		return false
	}
	if w == AtomicBEEFMarker {
		return true
	}
	return w&0xFFFF0000 == beefMarkerHi && w&0xFFFF != 0
}

// TopicID returns SHA-256 of the UTF-8 topic name — the BRC-148 topic
// identifier and BEEF-plane shard key.
func TopicID(name string) [32]byte { return sha256.Sum256([]byte(name)) }

// ContentID returns SHA-256d (double SHA-256) of the complete object bytes —
// the BRC-148 object identity.
func ContentID(obj []byte) [32]byte {
	h := sha256.Sum256(obj)
	return sha256.Sum256(h[:])
}

// BEEFRecord is a parsed submission record: one BEEF object named to one or
// more overlay topics (the BRC-22 submit shape).
type BEEFRecord struct {
	Topics []string
	Object []byte // zero-copy slice into the decode buffer
}

// BEEFRecordSize returns the total byte length of the submission record at
// the start of buf. It is the ClassBEEF stream delimiter: the record's
// explicit lengths make it cheap to walk, restoring the single-class-lane
// self-delimiting invariant that bare BEEF bytes cannot provide.
//
// Returns [ErrShort] when buf is a valid but incomplete prefix and
// [ErrMalformed] when buf cannot be a valid record.
func BEEFRecordSize(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, ErrShort
	}
	if binary.BigEndian.Uint16(buf[0:2]) != BEEFRecordTag {
		return 0, fmt.Errorf("%w: bad record tag 0x%04X", ErrMalformed, binary.BigEndian.Uint16(buf[0:2]))
	}
	if len(buf) < beefRecordMin {
		return 0, ErrShort
	}
	if buf[2] != BEEFRecordVer {
		return 0, fmt.Errorf("%w: record version 0x%02X", ErrMalformed, buf[2])
	}
	count := int(buf[3])
	if count < 1 || count > BEEFMaxTopics {
		return 0, fmt.Errorf("%w: topic count %d outside [1, %d]", ErrMalformed, count, BEEFMaxTopics)
	}

	off := beefRecordMin
	for i := 0; i < count; i++ {
		if len(buf) < off+1 {
			return 0, ErrShort
		}
		nameLen := int(buf[off])
		if nameLen < 1 || nameLen > BEEFMaxTopicLen {
			return 0, fmt.Errorf("%w: topic length %d outside [1, %d]", ErrMalformed, nameLen, BEEFMaxTopicLen)
		}
		off += 1 + nameLen
		if len(buf) < off {
			return 0, ErrShort
		}
	}

	if len(buf) < off+4 {
		return 0, ErrShort
	}
	objLen := binary.BigEndian.Uint32(buf[off : off+4])
	if objLen == 0 {
		return 0, fmt.Errorf("%w: zero object length", ErrMalformed)
	}
	if uint64(objLen) > uint64(math.MaxInt-off-4) {
		return 0, fmt.Errorf("%w: object length %d overflows", ErrMalformed, objLen)
	}
	total := off + 4 + int(objLen)
	if len(buf) < total {
		return 0, ErrShort
	}
	return total, nil
}

// DecodeBEEFRecord parses the submission record at the start of buf,
// returning the record and the number of bytes consumed. Record.Object is a
// zero-copy slice into buf. Like the rest of objfmt it is byte-only: the
// object's leading marker is NOT validated here — callers gate admission
// with [IsBEEFObject].
func DecodeBEEFRecord(buf []byte) (*BEEFRecord, int, error) {
	n, err := BEEFRecordSize(buf)
	if err != nil {
		return nil, 0, err
	}
	count := int(buf[3])
	rec := &BEEFRecord{Topics: make([]string, 0, count)}
	off := beefRecordMin
	for i := 0; i < count; i++ {
		nameLen := int(buf[off])
		rec.Topics = append(rec.Topics, string(buf[off+1:off+1+nameLen]))
		off += 1 + nameLen
	}
	objLen := int(binary.BigEndian.Uint32(buf[off : off+4]))
	rec.Object = buf[off+4 : off+4+objLen]
	return rec, n, nil
}

// EncodeBEEFRecord serialises a submission record. Topics must number
// 1..[BEEFMaxTopics], each valid UTF-8 of 1..[BEEFMaxTopicLen] bytes; the
// object must be non-empty.
func EncodeBEEFRecord(topics []string, object []byte) ([]byte, error) {
	if len(topics) < 1 || len(topics) > BEEFMaxTopics {
		return nil, fmt.Errorf("%w: topic count %d outside [1, %d]", ErrMalformed, len(topics), BEEFMaxTopics)
	}
	if len(object) == 0 {
		return nil, fmt.Errorf("%w: empty object", ErrMalformed)
	}
	size := beefRecordMin
	for _, t := range topics {
		if len(t) < 1 || len(t) > BEEFMaxTopicLen || !utf8.ValidString(t) {
			return nil, fmt.Errorf("%w: invalid topic %q", ErrMalformed, t)
		}
		size += 1 + len(t)
	}
	size += 4 + len(object)

	out := make([]byte, 0, size)
	out = binary.BigEndian.AppendUint16(out, BEEFRecordTag)
	out = append(out, BEEFRecordVer, byte(len(topics)))
	for _, t := range topics {
		out = append(out, byte(len(t)))
		out = append(out, t...)
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(object)))
	out = append(out, object...)
	return out, nil
}

// EncodeBEEFDelivery serialises the down-direction delivery record:
// TopicID ∥ u32 BE objectLen ∥ object. The edge knows the TopicID hash, not
// the name; overlay consumers map it back from their own elections.
func EncodeBEEFDelivery(topicID [32]byte, object []byte) []byte {
	out := make([]byte, 0, BEEFDeliveryHeaderSize+len(object))
	out = append(out, topicID[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(object)))
	return append(out, object...)
}

// BEEFDeliverySize returns the total length of the delivery record at the
// start of buf ([ErrShort]/[ErrMalformed] semantics as elsewhere).
func BEEFDeliverySize(buf []byte) (int, error) {
	if len(buf) < BEEFDeliveryHeaderSize {
		return 0, ErrShort
	}
	objLen := binary.BigEndian.Uint32(buf[32:36])
	if objLen == 0 {
		return 0, fmt.Errorf("%w: zero object length", ErrMalformed)
	}
	if uint64(objLen) > uint64(math.MaxInt-BEEFDeliveryHeaderSize) {
		return 0, fmt.Errorf("%w: object length %d overflows", ErrMalformed, objLen)
	}
	total := BEEFDeliveryHeaderSize + int(objLen)
	if len(buf) < total {
		return 0, ErrShort
	}
	return total, nil
}

// DecodeBEEFDelivery parses the delivery record at the start of buf,
// returning the TopicID, the object (zero-copy), and the bytes consumed.
func DecodeBEEFDelivery(buf []byte) (topicID [32]byte, object []byte, n int, err error) {
	n, err = BEEFDeliverySize(buf)
	if err != nil {
		return topicID, nil, 0, err
	}
	copy(topicID[:], buf[0:32])
	return topicID, buf[BEEFDeliveryHeaderSize:n], n, nil
}

// BEEFMulticastBytes wraps one BEEF object into a fully-encoded, unstamped
// FrameVer 0x09 multicast frame for one topic: ContentID is computed from
// the object bytes, TopicID is the caller's (already-hashed) topic. The
// ingress expands a multi-topic submission by calling this once per topic —
// which is why ClassBEEF is not registered in [MulticastBytes] (that seam is
// strictly 1:1).
func BEEFMulticastBytes(topicID [32]byte, obj []byte) ([]byte, error) {
	if len(obj) == 0 {
		return nil, fmt.Errorf("%w: empty object", ErrMalformed)
	}
	bf := &frame.BEEFFrame{
		ContentID: ContentID(obj),
		TopicID:   topicID,
		Payload:   obj,
	}
	buf := make([]byte, frame.HeaderSize+len(obj))
	n, err := frame.EncodeBEEF(bf, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// beefStrip extracts the verbatim BEEF object from a FrameVer 0x09 multicast
// frame (the [StripBytes] down-direction for ClassBEEF). The TopicID is
// dropped — a stripped lane consumer that needs it uses the delivery record
// ([EncodeBEEFDelivery]) instead.
func beefStrip(mcast []byte) ([]byte, error) {
	bf, err := frame.DecodeBEEF(mcast)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), bf.Payload...), nil
}
