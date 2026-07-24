// BRC-148 domain-partitioned object planes.
//
// BRC-148 partitions the 16-bit shard-index space into object planes selected
// by the high nibble (the domain): 0x0 = transaction plane (unchanged
// BRC-129), 0x1 = BEEF object plane, 0x2–0xE reserved, 0xF forbidden (the
// control plane occupies 0xF800–0xFFFF). Each plane derives its shard index
// with the unmodified BRC-129 top-bits rule applied to the plane's own
// 32-byte shard key (TxID for domain 0x0, TopicID for the BEEF plane) at the
// plane's own shard-bit width, then adds the plane base:
//
//	planeBase(domain) = domain << 12
//	IDX               = planeBase + ((key[0:4] as uint32 BE) >> (32 - bits))

package shard

import (
	"errors"
	"fmt"
)

// BRC-148 domain selectors.
const (
	// DomainTx is the transaction plane (BRC-124/BRC-128; unchanged BRC-129
	// behaviour, shard key = TxID, shard_bits ≤ 12).
	DomainTx uint8 = 0x0

	// DomainBEEF is the BEEF object plane (BRC-148; shard key = TopicID).
	DomainBEEF uint8 = 0x1

	// DomainMax is the highest assignable plane domain. 0xF is forbidden —
	// its slot overlaps the BRC-129 control plane (0xF800–0xFFFF).
	DomainMax uint8 = 0x0E

	// ControlBase is the first index of the BRC-129 control plane. No plane's
	// reserved range may reach it: planeBase + 2^shardBits ≤ ControlBase.
	ControlBase uint16 = 0xF800
)

// ErrBadPlane is returned by [NewPlane] for a (domain, shardBits) pair that
// violates the BRC-148 constraints.
var ErrBadPlane = errors.New("shard: invalid plane parameters")

// PlaneBase returns a plane's base index (domain << 12): 0x0000, 0x1000, ….
// The result is meaningful only for domain ≤ [DomainMax].
func PlaneBase(domain uint8) uint16 { return uint16(domain) << 12 }

// PlaneOf returns the domain selector encoded in an index's high nibble.
// Indices at or above [ControlBase] belong to the control plane, not to any
// object plane; callers gate on that separately when it matters.
func PlaneOf(idx uint16) uint8 { return uint8(idx >> 12) }

// SlotSpan returns the number of contiguous 0x1000 slots a plane with the
// given shard-bit width reserves: ceil(2^bits / 4096), minimum 1.
func SlotSpan(shardBits uint) uint8 {
	if shardBits <= 12 {
		return 1
	}
	return uint8(1) << (shardBits - 12)
}

// ValidatePlane checks the BRC-148 constraints for a (domain, shardBits)
// pair: domain ≤ 0x0E; shardBits in [1, 15]; the plane's reserved range must
// not reach the control plane (planeBase + 2^shardBits ≤ 0xF800); and domain
// 0x0 retains the BRC-129 cap shardBits ≤ 12.
func ValidatePlane(domain uint8, shardBits uint) error {
	if domain > DomainMax {
		return fmt.Errorf("%w: domain 0x%X (0xF overlaps the control plane)", ErrBadPlane, domain)
	}
	if shardBits < 1 || shardBits > 15 {
		return fmt.Errorf("%w: shardBits %d outside [1, 15]", ErrBadPlane, shardBits)
	}
	if domain == DomainTx && shardBits > 12 {
		return fmt.Errorf("%w: domain 0x0 caps shardBits at 12 (BRC-129)", ErrBadPlane)
	}
	if end := uint32(PlaneBase(domain)) + (uint32(1) << shardBits); end > uint32(ControlBase) {
		return fmt.Errorf("%w: planeBase 0x%04X + 2^%d reaches 0x%X (limit 0x%X)",
			ErrBadPlane, PlaneBase(domain), shardBits, end, ControlBase)
	}
	return nil
}

// PlaneEngine derives domain-tagged group indices for one object plane. It
// embeds an [Engine] configured with the plane's own shard-bit width;
// [PlaneEngine.GroupIndex] shadows the embedded derivation to add the plane
// base, and the inherited [Engine.Addr] accepts the banded index unchanged.
//
// Like Engine, a PlaneEngine is immutable and safe for concurrent use.
type PlaneEngine struct {
	*Engine
	base uint16
}

// NewPlane creates a PlaneEngine for the given domain, validating the
// BRC-148 (domain, shardBits) constraints via [ValidatePlane].
func NewPlane(mcPrefix uint16, groupID uint16, shardBits uint, domain uint8) (*PlaneEngine, error) {
	if err := ValidatePlane(domain, shardBits); err != nil {
		return nil, err
	}
	return &PlaneEngine{Engine: New(mcPrefix, groupID, shardBits), base: PlaneBase(domain)}, nil
}

// GroupIndex returns the domain-tagged group index for a plane shard key
// (TopicID on the BEEF plane): planeBase + top-bits(key). The result feeds
// [Engine.Addr] and the HashKey derivation directly.
func (p *PlaneEngine) GroupIndex(key *[32]byte) uint32 {
	return uint32(p.base) + p.Engine.GroupIndex(key)
}

// Base returns the plane's base index (planeBase(domain)).
func (p *PlaneEngine) Base() uint16 { return p.base }

// Groups returns every domain-tagged group index of the plane, in ascending
// order: planeBase … planeBase + 2^shardBits − 1. Useful for building
// aggregator join sets and retry-endpoint band joins.
func (p *PlaneEngine) Groups() []uint16 {
	out := make([]uint16, p.NumGroups())
	for i := range out {
		out[i] = p.base + uint16(i)
	}
	return out
}
