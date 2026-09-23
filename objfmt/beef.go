// BRC-148/149 BEEF object plane codecs: marker/identity helpers (TopicID /
// ContentID, BRC-148), the BRC-149 submission record (up-direction, ClassBEEF
// lane grammar), the BRC-149 delivery record (down-direction), and the
// single-frame multicast wrap.
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
// One record submits one object under one or more topic names; the ingress
// emits it as ONE FrameVer 0x09 frame whose payload is the record verbatim,
// so every name reaches the subscriber, and whose DeliverCount says how many
// of the leading names are deliverable (one on the open path, up to the
// operator's cap on the authenticated path; the rest are labels). The
// record's leading tag makes it grammar-distinct from a framed datagram
// (magic 0xE3…), a bare transaction (version byte[1] is 0x00) on the shared
// open port, and a bare BEEF object (leading 0x01) as a frame payload.

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
	// BEEFRecordMaxEnvelope is the largest submission-record envelope the
	// grammar allows around its object: tag, RecordVer, TopicCount, a full
	// topic list, and ObjectLen. An object bound applies to the object; a
	// payload carrying the record may exceed it by at most this much.
	BEEFRecordMaxEnvelope = beefRecordMin + BEEFMaxTopics*(1+BEEFMaxTopicLen) + 4
	// BEEFDeliveryHeaderSize is the delivery record's fixed prefix:
	// 32-byte TopicID + 4-byte BE payload length.
	BEEFDeliveryHeaderSize = 36
)

// SplitBEEFPayload resolves a frame payload to its object and topic names.
// A payload leading with the record tag is a submission record and must be
// exactly one; anything else is a bare object with no names (topics nil).
// The marker gate ([IsBEEFObject]) is the caller's, as everywhere in objfmt.
func SplitBEEFPayload(payload []byte) (object []byte, topics []string, err error) {
	if len(payload) >= 2 && binary.BigEndian.Uint16(payload[0:2]) == BEEFRecordTag {
		rec, n, err := DecodeBEEFRecord(payload)
		if err != nil {
			return nil, nil, err
		}
		if n != len(payload) {
			return nil, nil, fmt.Errorf("%w: %d trailing bytes after record", ErrMalformed, len(payload)-n)
		}
		return rec.Object, rec.Topics, nil
	}
	return payload, nil, nil
}

// BEEFDeliverableTopicIDs returns the TopicIDs a listener may match a frame
// on, in submission order: the header TopicID, then the record's next
// Deliverable()-1 names hashed. A bare-object payload, a legacy frame, or a
// count past the record's length all collapse to what the record and the
// header can support; the header TopicID is always first.
func BEEFDeliverableTopicIDs(bf *frame.BEEFFrame) [][32]byte {
	ids := [][32]byte{bf.TopicID}
	want := bf.Deliverable()
	if want <= 1 {
		return ids
	}
	_, topics, err := SplitBEEFPayload(bf.Payload)
	if err != nil || len(topics) < 2 {
		return ids
	}
	if want > len(topics) {
		want = len(topics)
	}
	for _, name := range topics[1:want] {
		ids = append(ids, TopicID(name))
	}
	return ids
}

// BEEFVersionWord returns the object's version word — the uint32 LE of its
// first four bytes (the version-filter input). ok is false when the object
// is shorter than four bytes.
func BEEFVersionWord(obj []byte) (word uint32, ok bool) {
	if len(obj) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(obj[0:4]), true
}

// IsBEEFObject reports whether obj leads with a marker from the BRC-149
// version-word table: [BEEFMarkerV1] (BRC-62), [BEEFMarkerV2] (BRC-96), or
// [AtomicBEEFMarker] (BRC-95). The table is closed — BRC-149 requires a
// record whose object does not lead with one of these markers to be
// rejected — so an unallocated word in the 0xEFBExxxx range is NOT a BEEF
// object. It is a fixed-offset sanity gate only: no structure is parsed.
func IsBEEFObject(obj []byte) bool {
	w, ok := BEEFVersionWord(obj)
	if !ok {
		return false
	}
	return w == BEEFMarkerV1 || w == BEEFMarkerV2 || w == AtomicBEEFMarker
}

// TopicID returns SHA-256 of the UTF-8 topic name — the BRC-148 topic
// identifier and BEEF-plane shard key.
func TopicID(name string) [32]byte { return sha256.Sum256([]byte(name)) }

// ContentID returns SHA-256d (double SHA-256) of the complete frame payload —
// the BRC-148 object identity. The payload is the submission record when the
// ingress carried one (so the same object under a different label set is a
// distinct submission) and the bare object otherwise.
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
// TopicID ∥ u32 BE payloadLen ∥ payload. TopicID is the identifier the
// consumer's election matched; the payload is the frame payload verbatim,
// so a consumer sees every name the publisher submitted when it was a
// record ([SplitBEEFPayload]) and maps the matched identifier back to one of
// them, or to its own election for a bare object.
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

// BEEFMulticastRecord wraps one submission record verbatim into a
// fully-encoded, unstamped FrameVer 0x09 frame: ContentID is SHA-256d of the
// record, TopicID is the record's first topic, and deliverCount is clamped
// to [1, TopicCount]. This is the ingress emit shape; there is one frame per
// record at any topic count.
func BEEFMulticastRecord(rec []byte, deliverCount int) ([]byte, error) {
	r, n, err := DecodeBEEFRecord(rec)
	if err != nil {
		return nil, err
	}
	if n != len(rec) {
		return nil, fmt.Errorf("%w: %d trailing bytes after record", ErrMalformed, len(rec)-n)
	}
	if deliverCount < 1 {
		deliverCount = 1
	}
	if deliverCount > len(r.Topics) {
		deliverCount = len(r.Topics)
	}
	bf := &frame.BEEFFrame{
		ContentID:    ContentID(rec),
		TopicID:      TopicID(r.Topics[0]),
		DeliverCount: uint8(deliverCount),
		Payload:      rec,
	}
	buf := make([]byte, frame.HeaderSize+len(rec))
	wn, err := frame.EncodeBEEF(bf, buf)
	if err != nil {
		return nil, err
	}
	return buf[:wn], nil
}

// BEEFMulticastBytes wraps one bare BEEF object into a fully-encoded,
// unstamped FrameVer 0x09 frame for one topic: ContentID is computed from
// the object bytes, TopicID is the caller's (already-hashed) topic. This is
// the bare-object payload form; the ingress emits [BEEFMulticastRecord] so
// names travel, and ClassBEEF is not registered in [MulticastBytes] because
// that seam takes no topic.
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

// beefStrip extracts the verbatim payload (record or bare object) from a
// FrameVer 0x09 multicast frame (the [StripBytes] down-direction for
// ClassBEEF). The TopicID is dropped — a stripped lane consumer that needs
// it uses the delivery record ([EncodeBEEFDelivery]) instead.
func beefStrip(mcast []byte) ([]byte, error) {
	bf, err := frame.DecodeBEEF(mcast)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), bf.Payload...), nil
}
