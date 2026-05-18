// BRC-131 block announce payload encode/decode.

package frame

import (
	"encoding/binary"
	"fmt"
)

const (
	// BlockHeaderSize is the fixed size of a BSV block header in bytes.
	BlockHeaderSize = 80

	// BlockAnnounceMinPayload is the minimum payload size for a BlockAnnounce
	// frame: 80B block header + 32B coinbase TxID + 4B subtree count.
	BlockAnnounceMinPayload = BlockHeaderSize + 32 + 4
)

// BlockAnnouncePayload is the parsed payload of a BlockAnnounce frame
// (BlockMsgType 0x01).
type BlockAnnouncePayload struct {
	Header        [80]byte   // Standard 80-byte BSV block header
	CoinbaseTxID  [32]byte   // SHA256d of the coinbase transaction
	SubtreeHashes [][32]byte // Ordered subtree root hashes
}

// DecodeBlockAnnounce parses a BlockAnnounce payload.
//
// Possible errors: payload too short, subtree count mismatch.
func DecodeBlockAnnounce(payload []byte) (*BlockAnnouncePayload, error) {
	if len(payload) < BlockAnnounceMinPayload {
		return nil, fmt.Errorf("frame: block announce payload too short (%d bytes, need >= %d)", len(payload), BlockAnnounceMinPayload)
	}

	subtreeCount := binary.BigEndian.Uint32(payload[112:116])
	expectedLen := BlockAnnounceMinPayload + int(subtreeCount)*32
	if len(payload) < expectedLen {
		return nil, fmt.Errorf("frame: block announce payload too short for %d subtrees (%d bytes, need %d)", subtreeCount, len(payload), expectedLen)
	}

	a := &BlockAnnouncePayload{}
	copy(a.Header[:], payload[0:80])
	copy(a.CoinbaseTxID[:], payload[80:112])

	if subtreeCount > 0 {
		a.SubtreeHashes = make([][32]byte, subtreeCount)
		for i := uint32(0); i < subtreeCount; i++ {
			off := 116 + int(i)*32
			copy(a.SubtreeHashes[i][:], payload[off:off+32])
		}
	}

	return a, nil
}

// EncodeBlockAnnounce serialises a BlockAnnouncePayload into a byte slice.
func EncodeBlockAnnounce(a *BlockAnnouncePayload) []byte {
	size := BlockAnnounceMinPayload + len(a.SubtreeHashes)*32
	buf := make([]byte, size)

	copy(buf[0:80], a.Header[:])
	copy(buf[80:112], a.CoinbaseTxID[:])
	binary.BigEndian.PutUint32(buf[112:116], uint32(len(a.SubtreeHashes)))

	for i, h := range a.SubtreeHashes {
		off := 116 + i*32
		copy(buf[off:off+32], h[:])
	}

	return buf
}
