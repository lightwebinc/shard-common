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
//
// All three classes are registered: ClassTx wraps to BRC-124/128, ClassSubtree
// to BRC-132, and ClassBlock to the fabric block frame (the BRC-144 body
// carried verbatim) — see [MulticastBytes].
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
	// ClassSubtree is a BRC-143 subtree push frame. Not registered in v1.
	ClassSubtree
	// ClassBlock is a BRC-144 block push frame. Not registered in v1.
	ClassBlock
)

// String returns the lane name for logs and metrics labels.
func (c Class) String() string {
	switch c {
	case ClassTx:
		return "tx"
	case ClassSubtree:
		return "subtree"
	case ClassBlock:
		return "block"
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

	// ErrClassNotRegistered reports a class whose codec has not landed yet
	// (ClassSubtree and ClassBlock in v1).
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
// [ErrClassNotRegistered] for classes whose codec has not landed.
func Size(c Class, buf []byte) (int, error) {
	switch c {
	case ClassTx:
		return TxSize(buf)
	case ClassSubtree:
		return SubtreeSize(buf)
	case ClassBlock:
		return BlockSize(buf)
	default:
		return 0, ErrClassNotRegistered
	}
}
