package objfmt

import (
	"github.com/lightwebinc/shard-common/frame"
)

// MulticastFrame wraps a pushed ClassTx object into a BRC-124/128 [frame.Frame]
// (FrameVer 0x02; an EF payload is carried as-is per BRC-128). The returned
// frame is unstamped (zero HashKey/SeqNum) — the proxy stamps authoritatively
// from the observed source. It is the single-tx convenience form; ClassSubtree
// and ClassBlock have no [frame.Frame] representation (they wrap to BRC-132 /
// the fabric block frame) and return [ErrClassNotRegistered] here — use
// [MulticastBytes] for those.
func MulticastFrame(c Class, obj []byte) (*frame.Frame, error) {
	switch c {
	case ClassTx:
		n, err := TxSize(obj)
		if err != nil {
			return nil, err
		}
		id, err := TxID(obj[:n])
		if err != nil {
			return nil, err
		}
		return &frame.Frame{
			Version: frame.FrameVerV2,
			TxID:    id,
			Payload: obj[:n],
		}, nil
	default:
		return nil, ErrClassNotRegistered
	}
}

// MulticastBytes wraps a pushed object of class c into its fully-encoded
// multicast frame, ready to hand to the forwarder's frame-version dispatch
// (raw[6] routes it to the correct Process* path). It is the general
// up-direction seam the proxy ingest uses for every class:
//
//   - ClassTx      → BRC-124/128 (FrameVer 0x02)
//   - ClassSubtree → BRC-132 subtree data, hashes-only (FrameVer 0x05), the
//     in-band merkle root as SubtreeID
//   - ClassBlock   → BRC-131 block control (FrameVer 0x04) carrying the whole
//     BRC-144 body verbatim as payload (fabric-internal; the delivery edge
//     unwraps a byte-identical BRC-144 — no lossy BlockAnnounce projection)
//
// The frame is unstamped; the proxy stamps HashKey/SeqNum from the observed
// source. Returns [ErrShort]/[ErrMalformed] for a bad object, or
// [ErrClassNotRegistered] for an unknown class.
func MulticastBytes(c Class, obj []byte) ([]byte, error) {
	switch c {
	case ClassTx:
		f, err := MulticastFrame(ClassTx, obj)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, frame.HeaderSize+len(f.Payload))
		n, err := frame.Encode(f, buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	case ClassSubtree:
		return subtreeMulticast(obj)
	case ClassBlock:
		return blockMulticast(obj)
	default:
		return nil, ErrClassNotRegistered
	}
}
