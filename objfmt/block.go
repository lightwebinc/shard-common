package objfmt

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/lightwebinc/shard-common/frame"
)

// BlockPrefixSize is the fixed BRC-144 block push-frame prefix through
// SubtreeCount: 80-byte header + 8 TransactionCount + 8 SizeInBytes +
// 8 SubtreeCount (all uint64 BE).
const BlockPrefixSize = 104

// blockRootSize is one subtree root hash on the wire.
const blockRootSize = 32

// BlockSize returns the total serialized length of the BRC-144 block push
// frame at the start of buf, walking its counts: the 104-byte prefix +
// SubtreeCount × 32 roots + the inline coinbase (self-delimiting by tx
// structure) + 8 Height + 8 CoinbaseBUMPLen + CoinbaseBUMP.
//
// Returns [ErrShort] on an incomplete prefix and [ErrMalformed] when a count
// overflows the addressable range or the inline coinbase is malformed.
func BlockSize(buf []byte) (int, error) {
	if len(buf) < BlockPrefixSize {
		return 0, ErrShort
	}
	m := binary.BigEndian.Uint64(buf[96:104])
	if m > uint64((math.MaxInt-BlockPrefixSize)/blockRootSize) {
		return 0, fmt.Errorf("%w: subtree count %d overflows", ErrMalformed, m)
	}
	off := BlockPrefixSize + int(m)*blockRootSize
	if len(buf) < off {
		return 0, ErrShort
	}

	// Inline coinbase — self-delimiting by transaction structure (no length
	// prefix, as in the native block body). ErrShort/ErrMalformed propagate.
	cb, err := TxSize(buf[off:])
	if err != nil {
		return 0, err
	}
	off += cb

	// Height (8) + CoinbaseBUMPLen (8).
	if len(buf) < off+16 {
		return 0, ErrShort
	}
	l := binary.BigEndian.Uint64(buf[off+8 : off+16])
	off += 16
	if l > uint64(math.MaxInt-off) {
		return 0, fmt.Errorf("%w: coinbase BUMP length %d overflows", ErrMalformed, l)
	}
	end := off + int(l)
	if len(buf) < end {
		return 0, ErrShort
	}
	return end, nil
}

// blockMulticast wraps a BRC-144 block push frame into the fabric block frame.
// Per the design direction (multicast is fabric-internal; no consumer
// terminates on the fabric frame) the whole BRC-144 body is carried VERBATIM as
// the payload of a BRC-131 block-control frame — not projected into a lossy
// BlockAnnounce — so the delivery edge unwraps a byte-identical BRC-144 with no
// height/BUMP loss and no correlation step. ContentID is the block hash
// (SHA256d of the 80-byte header); the frame is unstamped (proxy stamps).
func blockMulticast(obj []byte) ([]byte, error) {
	n, err := BlockSize(obj)
	if err != nil {
		return nil, err
	}
	body := obj[:n]

	first := sha256.Sum256(body[:frame.BlockHeaderSize])
	blockHash := sha256.Sum256(first[:])

	bf := &frame.BlockFrame{
		MsgType:   frame.BlockMsgAnnounce,
		ContentID: blockHash,
		Payload:   body,
	}
	buf := make([]byte, frame.HeaderSize+len(body))
	wn, err := frame.EncodeBlock(bf, buf)
	if err != nil {
		return nil, err
	}
	return buf[:wn], nil
}
