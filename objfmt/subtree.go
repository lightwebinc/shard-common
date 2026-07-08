package objfmt

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/lightwebinc/shard-common/frame"
)

// SubtreeHeaderSize is the fixed BRC-143 subtree push-frame header:
// 32-byte SubtreeMerkleRoot + 8-byte uint64 NodeCount.
const SubtreeHeaderSize = 40

// subtreeNodeSize is one node hash on the wire (internal byte order).
const subtreeNodeSize = 32

// SubtreeSize returns the total serialized length of the BRC-143 subtree push
// frame at the start of buf: the 40-byte header plus NodeCount × 32 hash bytes.
// NodeCount delimits the body, so this is the ClassSubtree stream delimiter.
//
// Returns [ErrShort] when buf is a valid but incomplete prefix and
// [ErrMalformed] when NodeCount overflows the addressable range.
func SubtreeSize(buf []byte) (int, error) {
	if len(buf) < SubtreeHeaderSize {
		return 0, ErrShort
	}
	n := binary.BigEndian.Uint64(buf[32:40])
	if n > uint64((math.MaxInt-SubtreeHeaderSize)/subtreeNodeSize) {
		return 0, fmt.Errorf("%w: node count %d overflows", ErrMalformed, n)
	}
	total := SubtreeHeaderSize + int(n)*subtreeNodeSize
	if len(buf) < total {
		return 0, ErrShort
	}
	return total, nil
}

// subtreeMulticast wraps a BRC-143 subtree push frame into a BRC-132 subtree
// data multicast frame (FrameVer 0x05, hashes-only). The in-band merkle root
// becomes the frame SubtreeID (it rode the multicast header as SubtreeID and
// was lost on strip); the node hashes become hashes-only nodes with fee/size
// zeroed (the receiver recomputes them). The frame is unstamped — the proxy
// stamps HashKey/SeqNum from the observed source.
func subtreeMulticast(obj []byte) ([]byte, error) {
	n, err := SubtreeSize(obj)
	if err != nil {
		return nil, err
	}
	obj = obj[:n]

	var root [32]byte
	copy(root[:], obj[0:32])
	count := binary.BigEndian.Uint64(obj[32:40])

	nodes := make([]frame.SubtreeNode, count)
	for i := uint64(0); i < count; i++ {
		off := SubtreeHeaderSize + int(i)*subtreeNodeSize
		copy(nodes[i].TxHash[:], obj[off:off+subtreeNodeSize])
	}

	payload, err := frame.EncodeSubtreeDataPayload(
		&frame.SubtreeDataPayload{Nodes: nodes}, frame.SubtreeMsgHashesOnly)
	if err != nil {
		return nil, err
	}

	sf := &frame.SubtreeDataFrame{
		MsgType:   frame.SubtreeMsgHashesOnly,
		SubtreeID: root,
		Payload:   payload,
	}
	buf := make([]byte, frame.HeaderSize+len(payload))
	wn, err := frame.EncodeSubtreeData(sf, buf)
	if err != nil {
		return nil, err
	}
	return buf[:wn], nil
}
