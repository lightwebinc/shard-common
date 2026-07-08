package objfmt

import (
	"encoding/binary"

	"github.com/lightwebinc/shard-common/frame"
)

// StripBytes is the down-direction inverse of [MulticastBytes]: it turns a
// fully-encoded multicast frame of class c into the bare push-object bytes
// delivered on that class's single-class lane. The two directions live in this
// one package so they cannot drift — for every registered class,
// StripBytes(c, MulticastBytes(c, obj)) reproduces obj.
//
//   - ClassTx      → the BRC-12 raw / BRC-30 EF transaction payload of the
//     BRC-124/128 frame.
//   - ClassSubtree → BRC-143 (32B root ∥ u64 NodeCount ∥ N×32 hashes), rebuilt
//     from the BRC-132 frame's SubtreeID (the in-band merkle root) and its node
//     hashes. Fee/size are dropped (BRC-143 omits them — Teranode recomputes),
//     so it is well-defined for both hashes-only and full-node BRC-132 frames.
//   - ClassBlock   → the verbatim BRC-144 body carried in the BRC-131 frame.
//     A BRC-131 whose payload is not a whole BRC-144 (a lossy native
//     BlockAnnounce, or a coinbase) returns [ErrNotStrippable].
//
// The returned buffer is freshly allocated and independent of mcast.
func StripBytes(c Class, mcast []byte) ([]byte, error) {
	switch c {
	case ClassTx:
		f, err := frame.Decode(mcast)
		if err != nil {
			return nil, err
		}
		return append([]byte(nil), f.Payload...), nil
	case ClassSubtree:
		return subtreeStrip(mcast)
	case ClassBlock:
		return blockStrip(mcast)
	default:
		return nil, ErrClassNotRegistered
	}
}

// subtreeStrip rebuilds a BRC-143 subtree push frame from a BRC-132 subtree
// data multicast frame: the frame SubtreeID is the in-band merkle root and the
// node TxHashes become the hash list. It is the inverse of [subtreeMulticast].
func subtreeStrip(mcast []byte) ([]byte, error) {
	sf, err := frame.DecodeSubtreeData(mcast)
	if err != nil {
		return nil, err
	}
	p, err := frame.DecodeSubtreeDataPayload(sf.Payload, sf.MsgType)
	if err != nil {
		return nil, err
	}
	out := make([]byte, SubtreeHeaderSize+len(p.Nodes)*subtreeNodeSize)
	copy(out[0:32], sf.SubtreeID[:])
	binary.BigEndian.PutUint64(out[32:SubtreeHeaderSize], uint64(len(p.Nodes)))
	for i := range p.Nodes {
		off := SubtreeHeaderSize + i*subtreeNodeSize
		copy(out[off:off+subtreeNodeSize], p.Nodes[i].TxHash[:])
	}
	return out, nil
}

// blockStrip extracts the verbatim BRC-144 body carried in a BRC-131 block
// control frame. Only a frame carrying a whole BRC-144 body (as produced by
// [blockMulticast]) is deliverable; a lossy native BlockAnnounce or a coinbase
// frame carries no full block and returns [ErrNotStrippable].
func blockStrip(mcast []byte) ([]byte, error) {
	bf, err := frame.DecodeBlock(mcast)
	if err != nil {
		return nil, err
	}
	n, err := BlockSize(bf.Payload)
	if err != nil || n != len(bf.Payload) {
		return nil, ErrNotStrippable
	}
	return append([]byte(nil), bf.Payload...), nil
}
