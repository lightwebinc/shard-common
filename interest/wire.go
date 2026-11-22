package interest

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/lightwebinc/shard-common/frame"
)

// TopicID identifies an overlay topic: SHA-256 of the UTF-8 topic name
// (BRC-149). Interest names whole topics only, and never a name.
type TopicID [32]byte

// Message types. They share the control-message preamble of BRC-126 and
// BRC-139: network magic, protocol version, then the type at offset 6. The
// values continue that registry (0x10 NACK family, 0x20 ADVERT, 0x30 subtree
// group announce, 0x40 shard manifest).
const (
	// MsgAnnounce carries delta records, downstream to upstream.
	MsgAnnounce byte = 0x50
	// MsgDigest carries the count and digest of the sender's set.
	MsgDigest byte = 0x51
	// MsgAck answers an ANNOUNCE or a DIGEST, upstream to downstream.
	MsgAck byte = 0x52
	// MsgResync is a poke from upstream: send a DIGEST now.
	MsgResync byte = 0x53
)

// Version is the wire version implemented by this package. Version 0 is a
// draft and is not frozen.
const Version byte = 0

// Sizes, in bytes.
const (
	// HeaderSize is the fixed header every message starts with.
	HeaderSize = 40
	// RecordFixedSize is a delta record without extensions.
	RecordFixedSize = 38
	// StatusSize is one record status in an ACK.
	StatusSize = 4
	// DigestBodySize follows the header of a DIGEST.
	DigestBodySize = 48
	// AckBodySize follows the header of an ACK whose result carries a body.
	AckBodySize = 60
	// TLVHeaderSize is the type and length that precede an extension value.
	TLVHeaderSize = 3
	// MaxDatagram is the largest message a sender may emit: the IPv6 minimum
	// MTU less the IPv6 and UDP headers, so no hop ever fragments it.
	MaxDatagram = 1232
	// MaxRecords is the most extension-free records one ANNOUNCE holds.
	MaxRecords = (MaxDatagram - HeaderSize) / RecordFixedSize
)

// LifetimeWithdraw in a record's lifetime withdraws the topic.
const LifetimeWithdraw uint32 = 0

// LifetimeDefault in a record's lifetime asks for the upstream's default.
const LifetimeDefault uint32 = 0xFFFFFFFF

// Header flags. Bits not listed are reserved: zero on send, ignored on
// receipt.
const (
	// FlagScopeWanted (ANNOUNCE, DIGEST) asks the upstream to include its
	// delivered scope in the answer.
	FlagScopeWanted byte = 1 << 0
	// FlagSync (ANNOUNCE) marks a datagram that is part of a full replay.
	// Informational.
	FlagSync byte = 1 << 1
	// FlagProbe (DIGEST) marks a digest sent only to be answered: the
	// upstream compares nothing, refreshes nothing and removes nothing. A
	// sender uses it to ask for the scope while it has no set to vouch for.
	FlagProbe byte = 1 << 1
	// FlagNoticesTruncated (ACK) says more notices exist than fitted.
	FlagNoticesTruncated byte = 1 << 0
)

// Result is the outcome of a whole message, carried in the ACK header.
type Result byte

// Results. Only [ResultOK] means the message was applied. An ACK carries a
// body for every result except [ResultToken] and [ResultVersion], which are
// header-only so that an answer to an unproven source is never larger than
// the request.
const (
	// ResultOK: applied.
	ResultOK Result = 0
	// ResultToken: not applied. The token in this ACK is the one to echo;
	// the upstream holds nothing it trusts for this sender, so replay.
	ResultToken Result = 1
	// ResultStale: not applied. The sequence number was not above the last
	// one applied, which the body reports.
	ResultStale Result = 2
	// ResultMismatch: a DIGEST did not match the set held. Replay.
	ResultMismatch Result = 3
	// ResultBusy: not applied. Try again later.
	ResultBusy Result = 4
	// ResultVersion: not applied. The header's version is the one the
	// upstream implements.
	ResultVersion Result = 5
	// ResultHopLimit: not applied. The message crossed more relays than the
	// upstream allows, which usually means relays are configured in a loop.
	ResultHopLimit Result = 6
)

// HasBody reports whether an ACK with this result carries the ACK body.
func (r Result) HasBody() bool { return r != ResultToken && r != ResultVersion }

func (r Result) String() string {
	switch r {
	case ResultOK:
		return "ok"
	case ResultToken:
		return "token"
	case ResultStale:
		return "stale"
	case ResultMismatch:
		return "mismatch"
	case ResultBusy:
		return "busy"
	case ResultVersion:
		return "version"
	case ResultHopLimit:
		return "hop_limit"
	}
	return fmt.Sprintf("result_%d", byte(r))
}

// Status is the outcome of one record. Zero is plain acceptance. Values
// below 0x80 are refusals: the upstream does not hold the topic. Values from
// 0x80 are notes: the upstream holds the topic, with a caveat.
type Status byte

// Statuses.
const (
	// StatusOK: held, and served as far as this hop knows.
	StatusOK Status = 0x00

	// StatusNotServed: refused. The topic's group is not among the groups
	// this path delivers, so no stream exists behind the interest.
	StatusNotServed Status = 0x01
	// StatusOutsideBound: refused. The account's bound does not allow it.
	StatusOutsideBound Status = 0x02
	// StatusOverCap: refused. A cap on live topics is reached.
	StatusOverCap Status = 0x03
	// StatusRateLimited: refused for now. Try again later.
	StatusRateLimited Status = 0x04
	// StatusUnsupported: refused. The record carries a critical extension
	// this hop does not understand.
	StatusUnsupported Status = 0x05
	// StatusBadAddress: refused. The delivery address does not parse, or is
	// not one this hop may deliver to for this sender.
	StatusBadAddress Status = 0x06

	// StatusAddressNotHonored: held. The delivery address is ignored and
	// delivery is as provisioned.
	StatusAddressNotHonored Status = 0x80
	// StatusUnserved: held at this relay, but no upstream path delivers the
	// topic's group.
	StatusUnserved Status = 0x81
	// StatusUpstreamRefused: held at this relay, but refused upstream.
	StatusUpstreamRefused Status = 0x82

	// StatusPending is never sent. A sender uses it for a topic whose
	// outcome it does not yet know.
	StatusPending Status = 0x7F
)

// Refused reports whether the upstream does not hold the topic.
func (s Status) Refused() bool { return s != StatusOK && s < 0x80 && s != StatusPending }

// Held reports whether the upstream holds the topic.
func (s Status) Held() bool { return s == StatusOK || s >= 0x80 }

// Served reports whether a stream can be expected for the topic.
func (s Status) Served() bool { return s == StatusOK || s == StatusAddressNotHonored }

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusNotServed:
		return "not_served"
	case StatusOutsideBound:
		return "outside_bound"
	case StatusOverCap:
		return "over_cap"
	case StatusRateLimited:
		return "rate_limited"
	case StatusUnsupported:
		return "unsupported"
	case StatusBadAddress:
		return "bad_address"
	case StatusAddressNotHonored:
		return "address_not_honored"
	case StatusUnserved:
		return "unserved"
	case StatusUpstreamRefused:
		return "upstream_refused"
	case StatusPending:
		return "pending"
	}
	return fmt.Sprintf("status_%#02x", byte(s))
}

// Extension types. An extension is a type, a 16-bit length and a value. It
// follows a record (inside the record's extension length) or the last record
// or status of a message. A type with [ExtCritical] set must be understood:
// a hop that does not know it refuses the record with [StatusUnsupported],
// as it does a record whose extensions do not parse. Any other unknown type
// is skipped. After the records of an ANNOUNCE, extensions apply to every
// record in it, and so does a refusal they cause; a withdrawal is always
// applied.
const (
	// ExtDelivery is where the objects for a topic should arrive
	// ([Delivery]). On a record it applies to that record; after the records
	// of an ANNOUNCE it is the default for every record in the datagram.
	ExtDelivery byte = 0x01
	// ExtScope, in an ACK, is the upstream's delivered scope ([Scope]).
	ExtScope byte = 0x02
	// ExtNotice, in an ACK, is a list of topics with a status, for topics
	// whose status changed after they were acknowledged.
	ExtNotice byte = 0x03
	// ExtAssign, in an ACK, is where a topic will be found ([Assignment]).
	ExtAssign byte = 0x04

	// 0x05 (reach), 0x06 (terms) and 0x07 (signature) are reserved.

	// ExtCritical marks a type that must be understood.
	ExtCritical byte = 0x80
)

// NoticeSize is one entry of an [ExtNotice] value: a TopicID and a status.
const NoticeSize = 33

// Errors returned by the decoders.
var (
	// ErrShort: the datagram ends before the structure it declares.
	ErrShort = errors.New("interest: datagram too short")
	// ErrMagic: the datagram does not start with the network magic and
	// protocol version.
	ErrMagic = errors.New("interest: bad magic or protocol version")
	// ErrType: the message type is not the one the decoder expects, or is
	// not an interest message at all.
	ErrType = errors.New("interest: unexpected message type")
	// ErrMalformed: a length or count is inconsistent with the datagram.
	ErrMalformed = errors.New("interest: malformed message")
	// ErrTooLarge: the message is, or would be, longer than [MaxDatagram].
	ErrTooLarge = errors.New("interest: message exceeds the datagram limit")
)

// Header is the fixed 40-byte header of every message.
//
//	Offset  Size  Field
//	  0      4    NetworkMagic  0xE3E1F3E8
//	  4      2    ProtoVer      0x02BF
//	  6      1    MsgType       0x50 ANNOUNCE, 0x51 DIGEST, 0x52 ACK, 0x53 RESYNC
//	  7      1    Flags
//	  8      1    Version       wire version; 0 is the draft
//	  9      1    Hops          relays between the farthest announcer and the sender
//	 10      1    Result        ACK only
//	 11      1    reserved
//	 12      2    Count         records (ANNOUNCE) or statuses (ACK)
//	 14      2    reserved
//	 16      8    SenderID      the downstream party; echoed in ACK and RESYNC
//	 24      8    Token         echoed by the sender; issued in the ACK
//	 32      8    Seq           the sender's sequence number; echoed in the ACK
//
// All integers are big-endian, as in the rest of the control-message family.
type Header struct {
	Type     byte
	Flags    byte
	Version  byte
	Hops     byte
	Result   Result
	Count    uint16
	SenderID uint64
	Token    uint64
	Seq      uint64
}

// DecodeHeader reads the header of any interest message. It checks the
// datagram's size, the magic, the protocol version and that the type is an
// interest type, and nothing else: the version field is for the caller to
// judge, since the header layout is the same in every version. A datagram
// longer than [MaxDatagram] is not an interest message.
func DecodeHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderSize {
		return h, ErrShort
	}
	if len(b) > MaxDatagram {
		return h, ErrTooLarge
	}
	if binary.BigEndian.Uint32(b[0:4]) != frame.MagicBSV || binary.BigEndian.Uint16(b[4:6]) != frame.ProtoVer {
		return h, ErrMagic
	}
	h.Type = b[6]
	if h.Type < MsgAnnounce || h.Type > MsgResync {
		return h, ErrType
	}
	h.Flags = b[7]
	h.Version = b[8]
	h.Hops = b[9]
	h.Result = Result(b[10])
	h.Count = binary.BigEndian.Uint16(b[12:14])
	h.SenderID = binary.BigEndian.Uint64(b[16:24])
	h.Token = binary.BigEndian.Uint64(b[24:32])
	h.Seq = binary.BigEndian.Uint64(b[32:40])
	return h, nil
}

// appendHeader appends h. The caller sets Type and Count.
func appendHeader(dst []byte, h *Header) []byte {
	var b [HeaderSize]byte
	binary.BigEndian.PutUint32(b[0:4], frame.MagicBSV)
	binary.BigEndian.PutUint16(b[4:6], frame.ProtoVer)
	b[6] = h.Type
	b[7] = h.Flags
	b[8] = h.Version
	b[9] = h.Hops
	b[10] = byte(h.Result)
	binary.BigEndian.PutUint16(b[12:14], h.Count)
	binary.BigEndian.PutUint64(b[16:24], h.SenderID)
	binary.BigEndian.PutUint64(b[24:32], h.Token)
	binary.BigEndian.PutUint64(b[32:40], h.Seq)
	return append(dst, b[:]...)
}

// SeqNewer reports whether sequence number a is newer than b. Sequence
// numbers are compared in serial number arithmetic over 64 bits (RFC 1982):
// a is newer when it is ahead of b by less than half the number space. The
// space therefore has no end to run into, and a sender whose counter wraps,
// or is moved forward by a large step, carries on. Zero is never used as a
// sequence number.
func SeqNewer(a, b uint64) bool { return int64(a-b) > 0 }

// seqAfter returns the sequence number after s, skipping zero.
func seqAfter(s uint64) uint64 {
	if s++; s == 0 {
		s = 1
	}
	return s
}

// TLV is one extension.
type TLV struct {
	Type  byte
	Value []byte
}

// ParseTLVs splits an extension area into its extensions. The values alias
// b. An area that does not divide exactly is malformed.
func ParseTLVs(b []byte) ([]TLV, error) {
	var out []TLV
	for len(b) > 0 {
		if len(b) < TLVHeaderSize {
			return nil, fmt.Errorf("%w: truncated extension header", ErrMalformed)
		}
		n := int(binary.BigEndian.Uint16(b[1:3]))
		if len(b) < TLVHeaderSize+n {
			return nil, fmt.Errorf("%w: extension value runs past the datagram", ErrMalformed)
		}
		out = append(out, TLV{Type: b[0], Value: b[TLVHeaderSize : TLVHeaderSize+n]})
		b = b[TLVHeaderSize+n:]
	}
	return out, nil
}

// AppendTLV appends one extension.
func AppendTLV(dst []byte, typ byte, value []byte) []byte {
	dst = append(dst, typ, byte(len(value)>>8), byte(len(value)))
	return append(dst, value...)
}

// FindTLV returns the value of the first extension of the given type.
func FindTLV(tlvs []TLV, typ byte) ([]byte, bool) {
	for _, t := range tlvs {
		if t.Type == typ {
			return t.Value, true
		}
	}
	return nil, false
}

// Record is one delta: a topic with a lifetime in seconds.
//
//	Offset  Size  Field
//	  0      32   TopicID
//	 32       4   Lifetime  seconds; 0 withdraws; 0xFFFFFFFF asks for the default
//	 36       2   ExtLen    bytes of extensions that follow
//	 38       …   Extensions
type Record struct {
	Topic    TopicID
	Lifetime uint32
	// Ext is the record's raw extension area. After a decode it aliases the
	// datagram; parse it with [ParseTLVs].
	Ext []byte
}

func (r *Record) size() int { return RecordFixedSize + len(r.Ext) }

// Announce is an ANNOUNCE message: the header, Count records, then
// message-level extensions to the end of the datagram.
type Announce struct {
	Header
	Records []Record
	// Ext is the raw message-level extension area.
	Ext []byte
}

// Append encodes the message onto dst.
func (m *Announce) Append(dst []byte) ([]byte, error) {
	if len(m.Records) > 0xFFFF {
		return dst, ErrTooLarge
	}
	size := HeaderSize + len(m.Ext)
	for i := range m.Records {
		if len(m.Records[i].Ext) > 0xFFFF {
			return dst, ErrTooLarge
		}
		size += m.Records[i].size()
	}
	if size > MaxDatagram {
		return dst, ErrTooLarge
	}
	h := m.Header
	h.Type = MsgAnnounce
	h.Count = uint16(len(m.Records))
	h.Result = 0
	dst = appendHeader(dst, &h)
	for i := range m.Records {
		r := &m.Records[i]
		dst = append(dst, r.Topic[:]...)
		dst = binary.BigEndian.AppendUint32(dst, r.Lifetime)
		dst = binary.BigEndian.AppendUint16(dst, uint16(len(r.Ext)))
		dst = append(dst, r.Ext...)
	}
	return append(dst, m.Ext...), nil
}

// DecodeAnnounce decodes an ANNOUNCE. Extension areas alias b.
func DecodeAnnounce(b []byte) (*Announce, error) {
	h, err := DecodeHeader(b)
	if err != nil {
		return nil, err
	}
	if h.Type != MsgAnnounce {
		return nil, ErrType
	}
	m := &Announce{Header: h}
	p := b[HeaderSize:]
	if int(h.Count)*RecordFixedSize > len(p) {
		return nil, fmt.Errorf("%w: %d records do not fit in %d bytes", ErrMalformed, h.Count, len(p))
	}
	m.Records = make([]Record, h.Count)
	for i := range m.Records {
		if len(p) < RecordFixedSize {
			return nil, fmt.Errorf("%w: record %d truncated", ErrMalformed, i)
		}
		r := &m.Records[i]
		copy(r.Topic[:], p[0:32])
		r.Lifetime = binary.BigEndian.Uint32(p[32:36])
		n := int(binary.BigEndian.Uint16(p[36:38]))
		p = p[RecordFixedSize:]
		if n > len(p) {
			return nil, fmt.Errorf("%w: record %d extensions run past the datagram", ErrMalformed, i)
		}
		if n > 0 {
			r.Ext = p[:n]
			p = p[n:]
		}
	}
	if len(p) > 0 {
		m.Ext = p
	}
	return m, nil
}

// SetDigest is the digest of a set of topics: the bitwise XOR of their
// TopicIDs, all zero for the empty set. It is order-independent and updates
// in constant time. A TopicID is already the output of SHA-256, so the XOR
// of distinct ones does not collide by accident. It is compared together
// with the set's count, and it guards two cooperating ends against drift,
// not against an adversary.
type SetDigest [32]byte

// Toggle adds t to the digest if it was absent and removes it if present.
func (d *SetDigest) Toggle(t TopicID) {
	a := binary.NativeEndian.Uint64
	p := binary.NativeEndian.PutUint64
	p(d[0:8], a(d[0:8])^a(t[0:8]))
	p(d[8:16], a(d[8:16])^a(t[8:16]))
	p(d[16:24], a(d[16:24])^a(t[16:24]))
	p(d[24:32], a(d[24:32])^a(t[24:32]))
}

// Digest is a DIGEST message.
//
//	Offset  Size  Field
//	 40       8   Since      0: the digest covers the sender's whole set.
//	                         Otherwise: it covers the topics set by messages
//	                         with Seq >= Since, and on a match everything
//	                         older is removed (the sweep that ends a replay)
//	 48       4   SetCount
//	 52       4   reserved
//	 56      32   SetDigest
//	 88       …   Extensions
type Digest struct {
	Header
	Since     uint64
	SetCount  uint32
	SetDigest SetDigest
	Ext       []byte
}

// Append encodes the message onto dst.
func (m *Digest) Append(dst []byte) ([]byte, error) {
	if HeaderSize+DigestBodySize+len(m.Ext) > MaxDatagram {
		return dst, ErrTooLarge
	}
	h := m.Header
	h.Type = MsgDigest
	h.Count = 0
	h.Result = 0
	dst = appendHeader(dst, &h)
	dst = binary.BigEndian.AppendUint64(dst, m.Since)
	dst = binary.BigEndian.AppendUint32(dst, m.SetCount)
	dst = append(dst, 0, 0, 0, 0)
	dst = append(dst, m.SetDigest[:]...)
	return append(dst, m.Ext...), nil
}

// DecodeDigest decodes a DIGEST. The extension area aliases b.
func DecodeDigest(b []byte) (*Digest, error) {
	h, err := DecodeHeader(b)
	if err != nil {
		return nil, err
	}
	if h.Type != MsgDigest {
		return nil, ErrType
	}
	if len(b) < HeaderSize+DigestBodySize {
		return nil, ErrShort
	}
	m := &Digest{Header: h}
	p := b[HeaderSize:]
	m.Since = binary.BigEndian.Uint64(p[0:8])
	m.SetCount = binary.BigEndian.Uint32(p[8:12])
	copy(m.SetDigest[:], p[16:48])
	if len(p) > DigestBodySize {
		m.Ext = p[DigestBodySize:]
	}
	return m, nil
}

// RecordStatus is the status of one record of the ANNOUNCE an ACK answers,
// named by the record's position in that datagram. Records that were simply
// accepted are not listed.
//
//	Offset  Size  Field
//	  0       2   Index
//	  2       1   Status
//	  3       1   reserved
type RecordStatus struct {
	Index  uint16
	Status Status
}

// Ack is an ACK message. A body is present unless the result is
// [ResultToken] or [ResultVersion].
//
//	Offset  Size  Field
//	 40       8   LastSeq          highest Seq applied from this sender
//	 48       4   SetCount         topics held for this sender
//	 52       4   ScopeGen         changes when the delivered scope does; 0: none
//	 56      32   SetDigest        digest of the topics held for this sender
//	 88       4   LifetimeMin      seconds
//	 92       4   LifetimeDefault  seconds
//	 96       4   LifetimeMax      seconds
//	100       …   Count statuses, then extensions
type Ack struct {
	Header
	LastSeq         uint64
	SetCount        uint32
	ScopeGen        uint32
	SetDigest       SetDigest
	LifetimeMin     uint32
	LifetimeDefault uint32
	LifetimeMax     uint32
	Statuses        []RecordStatus
	Ext             []byte
}

// Append encodes the message onto dst.
func (m *Ack) Append(dst []byte) ([]byte, error) {
	h := m.Header
	h.Type = MsgAck
	if !h.Result.HasBody() {
		h.Count = 0
		return appendHeader(dst, &h), nil
	}
	if len(m.Statuses) > 0xFFFF || HeaderSize+AckBodySize+len(m.Statuses)*StatusSize+len(m.Ext) > MaxDatagram {
		return dst, ErrTooLarge
	}
	h.Count = uint16(len(m.Statuses))
	dst = appendHeader(dst, &h)
	dst = binary.BigEndian.AppendUint64(dst, m.LastSeq)
	dst = binary.BigEndian.AppendUint32(dst, m.SetCount)
	dst = binary.BigEndian.AppendUint32(dst, m.ScopeGen)
	dst = append(dst, m.SetDigest[:]...)
	dst = binary.BigEndian.AppendUint32(dst, m.LifetimeMin)
	dst = binary.BigEndian.AppendUint32(dst, m.LifetimeDefault)
	dst = binary.BigEndian.AppendUint32(dst, m.LifetimeMax)
	for _, s := range m.Statuses {
		dst = binary.BigEndian.AppendUint16(dst, s.Index)
		dst = append(dst, byte(s.Status), 0)
	}
	return append(dst, m.Ext...), nil
}

// DecodeAck decodes an ACK. The extension area aliases b.
func DecodeAck(b []byte) (*Ack, error) {
	h, err := DecodeHeader(b)
	if err != nil {
		return nil, err
	}
	if h.Type != MsgAck {
		return nil, ErrType
	}
	m := &Ack{Header: h}
	if !h.Result.HasBody() {
		return m, nil
	}
	p := b[HeaderSize:]
	if len(p) < AckBodySize {
		return nil, ErrShort
	}
	m.LastSeq = binary.BigEndian.Uint64(p[0:8])
	m.SetCount = binary.BigEndian.Uint32(p[8:12])
	m.ScopeGen = binary.BigEndian.Uint32(p[12:16])
	copy(m.SetDigest[:], p[16:48])
	m.LifetimeMin = binary.BigEndian.Uint32(p[48:52])
	m.LifetimeDefault = binary.BigEndian.Uint32(p[52:56])
	m.LifetimeMax = binary.BigEndian.Uint32(p[56:60])
	p = p[AckBodySize:]
	if int(h.Count)*StatusSize > len(p) {
		return nil, fmt.Errorf("%w: %d statuses do not fit in %d bytes", ErrMalformed, h.Count, len(p))
	}
	if h.Count > 0 {
		m.Statuses = make([]RecordStatus, h.Count)
		for i := range m.Statuses {
			m.Statuses[i] = RecordStatus{Index: binary.BigEndian.Uint16(p[0:2]), Status: Status(p[2])}
			p = p[StatusSize:]
		}
	}
	if len(p) > 0 {
		m.Ext = p
	}
	return m, nil
}

// Resync is a RESYNC message: the header alone. SenderID names the sender
// being poked; zero pokes every sender at the address.
type Resync struct {
	Header
}

// Append encodes the message onto dst.
func (m *Resync) Append(dst []byte) ([]byte, error) {
	h := m.Header
	h.Type = MsgResync
	h.Count = 0
	h.Result = 0
	return appendHeader(dst, &h), nil
}

// Notice is one entry of an [ExtNotice] value.
type Notice struct {
	Topic  TopicID
	Status Status
}

// AppendNotices appends an [ExtNotice] extension holding ns.
func AppendNotices(dst []byte, ns []Notice) []byte {
	n := len(ns) * NoticeSize
	dst = append(dst, ExtNotice, byte(n>>8), byte(n))
	for i := range ns {
		dst = append(dst, ns[i].Topic[:]...)
		dst = append(dst, byte(ns[i].Status))
	}
	return dst
}

// ParseNotices decodes the value of an [ExtNotice] extension.
func ParseNotices(v []byte) ([]Notice, error) {
	if len(v)%NoticeSize != 0 {
		return nil, fmt.Errorf("%w: notice list of %d bytes", ErrMalformed, len(v))
	}
	out := make([]Notice, len(v)/NoticeSize)
	for i := range out {
		copy(out[i].Topic[:], v[:32])
		out[i].Status = Status(v[32])
		v = v[NoticeSize:]
	}
	return out, nil
}
