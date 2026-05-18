// BRC-132 subtree data payload encode/decode.

package frame

import (
	"encoding/binary"
	"fmt"
)

const (
	// SubtreeDataPayloadHeaderSize is the fixed-size metadata prefix common to
	// both hashes-only and full-node subtree data payloads:
	// TotalFees (8B) + TotalSizeBytes (8B) + NodeCount (8B) = 24 bytes.
	SubtreeDataPayloadHeaderSize = 24

	// SubtreeNodeHashSize is the size of one node in a hashes-only payload.
	SubtreeNodeHashSize = 32

	// SubtreeNodeFullSize is the size of one node in a full-node payload:
	// TxHash (32B) + Fee (8B) + Size (8B) = 48 bytes.
	SubtreeNodeFullSize = 48
)

// SubtreeNode is one entry in a full-node subtree data payload.
type SubtreeNode struct {
	TxHash [32]byte // SHA256d transaction ID
	Fee    uint64   // Transaction fee in satoshis
	Size   uint64   // Serialised transaction size in bytes
}

// SubtreeDataPayload is the parsed in-memory representation of a BRC-132
// subtree data payload (both hashes-only and full-node formats).
//
// For hashes-only frames (SubtreeMsgHashesOnly), Nodes carries TxHash with
// Fee and Size zeroed.
// For full-node frames (SubtreeMsgFullNodes), Nodes carries all three fields.
type SubtreeDataPayload struct {
	TotalFees      uint64        // Aggregate fee sum for this subtree (satoshis)
	TotalSizeBytes uint64        // Aggregate serialised byte count for this subtree
	Nodes          []SubtreeNode // Transaction nodes (NodeCount entries)
	ConflictHashes [][32]byte    // Conflict set: transaction hashes only
}

// DecodeSubtreeDataPayload parses a subtree data payload according to msgType.
// msgType must be [SubtreeMsgHashesOnly] or [SubtreeMsgFullNodes].
func DecodeSubtreeDataPayload(payload []byte, msgType byte) (*SubtreeDataPayload, error) {
	if len(payload) < SubtreeDataPayloadHeaderSize {
		return nil, fmt.Errorf("frame: subtree data payload too short (%d bytes, need >= %d)", len(payload), SubtreeDataPayloadHeaderSize)
	}

	totalFees := binary.BigEndian.Uint64(payload[0:8])
	totalSize := binary.BigEndian.Uint64(payload[8:16])
	nodeCount := binary.BigEndian.Uint64(payload[16:24])

	var nodeStride int
	switch msgType {
	case SubtreeMsgHashesOnly:
		nodeStride = SubtreeNodeHashSize
	case SubtreeMsgFullNodes:
		nodeStride = SubtreeNodeFullSize
	default:
		return nil, fmt.Errorf("frame: unknown subtree MsgType 0x%02X", msgType)
	}

	nodesEnd := SubtreeDataPayloadHeaderSize + int(nodeCount)*nodeStride
	if len(payload) < nodesEnd+8 {
		return nil, fmt.Errorf("frame: subtree data payload too short for %d nodes (%d bytes, need >= %d)", nodeCount, len(payload), nodesEnd+8)
	}

	nodes := make([]SubtreeNode, nodeCount)
	for i := uint64(0); i < nodeCount; i++ {
		off := SubtreeDataPayloadHeaderSize + int(i)*nodeStride
		copy(nodes[i].TxHash[:], payload[off:off+32])
		if msgType == SubtreeMsgFullNodes {
			nodes[i].Fee = binary.BigEndian.Uint64(payload[off+32 : off+40])
			nodes[i].Size = binary.BigEndian.Uint64(payload[off+40 : off+48])
		}
	}

	conflictCount := binary.BigEndian.Uint64(payload[nodesEnd : nodesEnd+8])
	conflictsEnd := nodesEnd + 8 + int(conflictCount)*32
	if len(payload) < conflictsEnd {
		return nil, fmt.Errorf("frame: subtree data payload too short for %d conflicts (%d bytes, need %d)", conflictCount, len(payload), conflictsEnd)
	}

	conflicts := make([][32]byte, conflictCount)
	for i := uint64(0); i < conflictCount; i++ {
		off := nodesEnd + 8 + int(i)*32
		copy(conflicts[i][:], payload[off:off+32])
	}

	return &SubtreeDataPayload{
		TotalFees:      totalFees,
		TotalSizeBytes: totalSize,
		Nodes:          nodes,
		ConflictHashes: conflicts,
	}, nil
}

// EncodeSubtreeDataPayload serialises a SubtreeDataPayload into a byte slice
// according to msgType.
// msgType must be [SubtreeMsgHashesOnly] or [SubtreeMsgFullNodes].
func EncodeSubtreeDataPayload(p *SubtreeDataPayload, msgType byte) ([]byte, error) {
	var nodeStride int
	switch msgType {
	case SubtreeMsgHashesOnly:
		nodeStride = SubtreeNodeHashSize
	case SubtreeMsgFullNodes:
		nodeStride = SubtreeNodeFullSize
	default:
		return nil, fmt.Errorf("frame: unknown subtree MsgType 0x%02X", msgType)
	}

	size := SubtreeDataPayloadHeaderSize +
		len(p.Nodes)*nodeStride +
		8 + // ConflictCount
		len(p.ConflictHashes)*32

	buf := make([]byte, size)
	binary.BigEndian.PutUint64(buf[0:8], p.TotalFees)
	binary.BigEndian.PutUint64(buf[8:16], p.TotalSizeBytes)
	binary.BigEndian.PutUint64(buf[16:24], uint64(len(p.Nodes)))

	for i, node := range p.Nodes {
		off := SubtreeDataPayloadHeaderSize + i*nodeStride
		copy(buf[off:off+32], node.TxHash[:])
		if msgType == SubtreeMsgFullNodes {
			binary.BigEndian.PutUint64(buf[off+32:off+40], node.Fee)
			binary.BigEndian.PutUint64(buf[off+40:off+48], node.Size)
		}
	}

	conflictOff := SubtreeDataPayloadHeaderSize + len(p.Nodes)*nodeStride
	binary.BigEndian.PutUint64(buf[conflictOff:conflictOff+8], uint64(len(p.ConflictHashes)))
	for i, h := range p.ConflictHashes {
		off := conflictOff + 8 + i*32
		copy(buf[off:off+32], h[:])
	}

	return buf, nil
}
