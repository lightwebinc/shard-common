// Package objfmt implements the push (non-multicast) object frame codecs —
// the header-stripped wire forms used for unicast delivery to and submission
// from consumers reached by push (e.g. round-robin SDA delivery over a
// tunnel) rather than multicast announce/pull.
//
// # Model
//
// Each object class rides its own single-class lane, so frames are bare:
// there is no outer length prefix and no type tag. A body is self-delimiting
// by its own structure:
//
//   - ClassTx — a BSV transaction, BRC-12 (raw) or BRC-30 (EF); delimited by
//     walking the transaction structure (version, input/output vectors,
//     locktime). A BRC-12/30 stream is byte-for-byte the transactions.
//   - ClassSubtree — BRC-143 subtree push frame; delimited by NodeCount.
//   - ClassBlock — BRC-144 block push frame; delimited by its counts.
//   - ClassBEEFDelivery — BRC-149 delivery record; delimited by its own u32BE
//     object length.
//   - ClassBlockHeader — a bare 80-byte BSV block header; fixed size.
//
// Three classes wrap to a multicast frame: ClassTx to BRC-124/128,
// ClassSubtree to BRC-132, and ClassBlock to the fabric block frame (the
// BRC-144 body carried verbatim) — see [MulticastBytes]. ClassBEEF is admitted
// via the proxy's SubmitBEEF submission-record expansion, not [MulticastBytes].
//
// ClassBEEFDelivery and ClassBlockHeader are DELIVERY-SIDE ONLY: they are the
// down-direction forms an edge writes to a consumer, they have no up-direction
// inverse, and [MulticastBytes], [MulticastFrame] and [StripBytes] all
// correctly refuse them with [ErrClassNotRegistered]. Wiring either into an
// up-direction seam is a bug, not a missing codec.
//
// # Directions
//
// The same codec serves both directions so they cannot drift: the edge
// listener's frame-writer strips a multicast frame to the bare object for
// delivery (down), and the proxy's raw-object ingest decodes a submitted
// object and wraps it into the matching multicast frame for the forwarder
// (up) via [MulticastFrame].
//
// objfmt is byte-only: it packs, sizes, and unpacks bytes. It performs no
// object validation (no script checks, no merkle verification) — the edge
// moves bytes; the consumer validates.
package objfmt

import "errors"

// Class selects an object-class codec. It is an internal lane/dispatch
// selector — never an on-wire byte (lanes are single-class, frames are bare).
type Class uint8

const (
	// ClassTx is a BSV transaction: BRC-12 (raw) or BRC-30 (EF).
	ClassTx Class = iota + 1
	// ClassSubtree is a BRC-143 subtree push frame.
	ClassSubtree
	// ClassBlock is a BRC-144 block push frame.
	ClassBlock
	// ClassBEEF is a BRC-149 BEEF submission record (not a bare BEEF object —
	// BEEF bytes are not length-walkable, so the lane carries the explicit
	// length-carrying record; see beef.go).
	ClassBEEF
	// ClassBEEFDelivery is a BRC-149 BEEF *delivery* record: the down-direction
	// envelope an edge writes to an overlay consumer, TopicID ∥ u32BE objectLen
	// ∥ object (see EncodeBEEFDelivery). ClassBEEF is the up direction, which
	// names topics; this one carries the single TopicID that matched.
	ClassBEEFDelivery
	// ClassBlockHeader is a bare 80-byte BSV block header, the payload the
	// BRC-135 FrameVer 0x07 header frame carries. Delivery-side only.
	ClassBlockHeader
)

// String returns the LANE name for logs and metrics labels. It names the lane
// a class rides, not the class itself, which is why the two BEEF classes share
// one string: ClassBEEF (up) and ClassBEEFDelivery (down) are the two
// directions of the one "beef" lane, and the delivery plane's vocabulary is
// the lane's.
//
// These strings are not free to choose. Across the fleet the `lane` label and
// the `class` label must be the SAME string, because billing reconciliation
// rewrites one into the other and joins on it; a class whose string has no
// matching lane string drops out of that join silently, with no signal that it
// went unreconciled. "beef" and "header" are the live values in that shared
// vocabulary, so both new classes reuse them rather than inventing a name.
func (c Class) String() string {
	switch c {
	case ClassTx:
		return "tx"
	case ClassSubtree:
		return "subtree"
	case ClassBlock:
		return "block"
	case ClassBEEF, ClassBEEFDelivery:
		return "beef"
	case ClassBlockHeader:
		return "header"
	default:
		return "unknown"
	}
}

var (
	// ErrShort reports that the buffer ends before the object does: the
	// bytes seen so far are a valid prefix and the caller should supply
	// more. It is the streaming "not yet" signal, distinct from corruption.
	ErrShort = errors.New("objfmt: short buffer (need more bytes)")

	// ErrMalformed reports bytes that cannot be a valid object of the
	// class regardless of any suffix.
	ErrMalformed = errors.New("objfmt: malformed object")

	// ErrClassNotRegistered reports a class value with no registered codec for
	// the direction being asked. Every [Class] is registered for [Size]; the
	// delivery-only classes (ClassBEEFDelivery, ClassBlockHeader) and ClassBEEF
	// are not registered for the up-direction seams, so [MulticastBytes],
	// [MulticastFrame] and [StripBytes] return this for them by design.
	ErrClassNotRegistered = errors.New("objfmt: class not registered")

	// ErrObjectTooLarge reports an object exceeding the reader's configured
	// maximum. It bounds memory against absurd or hostile length fields.
	ErrObjectTooLarge = errors.New("objfmt: object exceeds maximum size")

	// ErrNotStrippable reports a well-formed multicast frame that carries no
	// full push object to strip for delivery — e.g. a BRC-131 block-control
	// frame that is a lossy native BlockAnnounce (or a coinbase) rather than a
	// verbatim BRC-144 body. The caller counts it as a non-deliverable class
	// drop, not corruption.
	ErrNotStrippable = errors.New("objfmt: frame carries no full push object")
)

// Size returns the total byte length of the first object of class c at the
// start of buf, walking the object's own structure.
//
// It returns [ErrShort] when buf is a valid but incomplete prefix,
// [ErrMalformed] when buf cannot be a valid object, and
// [ErrClassNotRegistered] for a class value with no registered codec.
func Size(c Class, buf []byte) (int, error) {
	switch c {
	case ClassTx:
		return TxSize(buf)
	case ClassSubtree:
		return SubtreeSize(buf)
	case ClassBlock:
		return BlockSize(buf)
	case ClassBEEF:
		return BEEFRecordSize(buf)
	case ClassBEEFDelivery:
		return BEEFDeliverySize(buf)
	case ClassBlockHeader:
		return BlockHeaderSize(buf)
	default:
		return 0, ErrClassNotRegistered
	}
}
