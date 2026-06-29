package bundle

import (
	"crypto/sha256"

	"github.com/lightwebinc/shard-common/frame"
	"github.com/lightwebinc/shard-common/seqhash"
	"github.com/lightwebinc/shard-common/shard"
)

// flowKey identifies a bundle flow: one (sender, group, subtree). A bundle is
// scoped to a single flow, which gives it one HashKey and one monotonic SeqNum.
type flowKey struct {
	sender  [16]byte
	group   uint16
	subtree [32]byte
}

// Coalescer packs same-(sender, group, subtree) transactions into bundles,
// assigning a monotonic bundle SeqNum per flow. It is not safe for concurrent
// use; give each worker its own Coalescer.
type Coalescer struct {
	eng       *shard.Engine
	maxBytes  int  // max bundle datagram size (e.g. 1500 or 9000)
	maxCount  int  // max members per bundle (clamped to the uint16 ceiling)
	carryTxID bool // emit per-member TxIDs vs recompute on receipt
	seq       map[flowKey]uint64
}

// NewCoalescer constructs a Coalescer. maxBytes caps the encoded datagram size;
// maxCount caps members per bundle (clamped to [MaxMembers]); carryTxID chooses
// whether member TxIDs ride on the wire.
func NewCoalescer(eng *shard.Engine, maxBytes, maxCount int, carryTxID bool) *Coalescer {
	if maxCount <= 0 || maxCount > MaxMembers {
		maxCount = MaxMembers
	}
	return &Coalescer{
		eng:       eng,
		maxBytes:  maxBytes,
		maxCount:  maxCount,
		carryTxID: carryTxID,
		seq:       make(map[flowKey]uint64),
	}
}

// Coalesce buckets frames observed from sender by (group, subtree) and returns
// packed bundles. Frames within a bucket are packed in arrival order; a new
// bundle starts when adding a member would exceed maxBytes or maxCount. A member
// larger than the size budget is emitted alone (callers keep members ≤ MTU by
// construction; oversized transactions use BRC-130, not a bundle). Bundle order
// follows first-seen bucket order. The flow HashKey/SeqNum are stamped per
// (sender, group, subtree).
func (c *Coalescer) Coalesce(sender [16]byte, frames []*frame.Frame) []*Bundle {
	type bucket struct {
		key  flowKey
		mems []Member
	}
	idx := make(map[flowKey]int)
	var buckets []*bucket
	for _, f := range frames {
		k := flowKey{sender: sender, group: uint16(c.eng.GroupIndex(&f.TxID)), subtree: f.SubtreeID}
		bi, ok := idx[k]
		if !ok {
			bi = len(buckets)
			idx[k] = bi
			buckets = append(buckets, &bucket{key: k})
		}
		buckets[bi].mems = append(buckets[bi].mems, Member{TxID: f.TxID, Tx: f.Payload})
	}

	overhead := MemberOverhead(c.carryTxID)

	var out []*Bundle
	for _, bk := range buckets {
		for i := 0; i < len(bk.mems); {
			b := &Bundle{
				GroupIdx:  bk.key.group,
				SubtreeID: bk.key.subtree,
				ShardBits: uint8(c.eng.ShardBits()),
				HashKey:   seqhash.Hash(bk.key.sender, uint32(bk.key.group), bk.key.subtree),
			}
			if c.carryTxID {
				b.Flags |= FlagTxIDsPresent
			}
			size := HeaderSize
			for i < len(bk.mems) && len(b.Members) < c.maxCount {
				add := overhead + len(bk.mems[i].Tx)
				if len(b.Members) > 0 && size+add > c.maxBytes {
					break
				}
				b.Members = append(b.Members, bk.mems[i])
				size += add
				i++
			}
			c.seq[bk.key]++
			b.SeqNum = c.seq[bk.key]
			out = append(out, b)
		}
	}
	return out
}

// Decoalesce expands a bundle into individual BRC-124/128 (FrameVer 0x02) frames
// for the per-consumer egress (edge-decoalesce). Each frame inherits the bundle's
// flow HashKey and SubtreeID; SeqNum is left 0 — the egress side re-stamps per-tx
// SeqNums on its own flow (the bundle SeqNum is frame-bound and does not survive
// the split). TxIDs come from the bundle when present, else are recomputed
// ([TxID]). The returned frames are FrameVer 0x02; a caller delivering to a
// consumer that expects the transaction's base BRC-12/BRC-30 format re-wraps
// accordingly.
//
// Note: a recomputed TxID is the double-SHA256 of the member bytes, which is the
// canonical id only for a BRC-12 raw transaction. An Extended Format member's
// canonical id is the hash of its de-extended base transaction, so EF members
// should be carried with [FlagTxIDsPresent] set (see BRC-142 §Member Format).
func Decoalesce(b *Bundle) []*frame.Frame {
	out := make([]*frame.Frame, 0, len(b.Members))
	withTxID := b.TxIDsPresent()
	for i := range b.Members {
		m := &b.Members[i]
		f := &frame.Frame{
			Version:   frame.FrameVerV2,
			HashKey:   b.HashKey,
			SubtreeID: b.SubtreeID,
			Payload:   m.Tx,
		}
		if withTxID {
			f.TxID = m.TxID
		} else {
			f.TxID = TxID(m.Tx)
		}
		out = append(out, f)
	}
	return out
}

// Rebucketer re-splits bundles to a different (finer) shardBits — the relay
// operation for a cross-domain or reshard generation mismatch (BRC-142
// §Re-bucketing). It is decoalesce + re-coalesce at the new shardBits: each
// member is routed to its correct child group (recomputed from its TxID),
// SubtreeID is preserved, and HashKey/SeqNum are re-stamped on the new flows.
type Rebucketer struct {
	c *Coalescer
}

// NewRebucketer builds a Rebucketer that emits bundles at newEng's shardBits.
// maxBytes/maxCount/carryTxID govern the re-packed bundles.
func NewRebucketer(newEng *shard.Engine, maxBytes, maxCount int, carryTxID bool) *Rebucketer {
	return &Rebucketer{c: NewCoalescer(newEng, maxBytes, maxCount, carryTxID)}
}

// Rebucket splits b and re-coalesces it at the target shardBits under sender (the
// re-emitting node's source identity, which determines the new flow HashKeys).
func (rb *Rebucketer) Rebucket(sender [16]byte, b *Bundle) []*Bundle {
	return rb.c.Coalesce(sender, Decoalesce(b))
}

// TxID computes the BSV transaction id: double-SHA256 over the raw serialised
// transaction, in internal (non-display) byte order — matching frame.Frame.TxID.
func TxID(tx []byte) [32]byte {
	h := sha256.Sum256(tx)
	return sha256.Sum256(h[:])
}
