package interest

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"slices"

	"github.com/lightwebinc/shard-common/shard"
)

// Scope flag bits.
const (
	scopeFlagAll    byte = 1 << 0
	scopeFlagBitmap byte = 1 << 1
)

// scopeFixedSize is the fixed part of a scope value.
const scopeFixedSize = 22

// MaxScopeValue is the largest scope value a receiver puts in an ACK. A
// scope that cannot be expressed within it is not advertised, and senders
// then learn what is not served from record statuses alone.
const MaxScopeValue = 1024

// Scope is the set of groups an upstream path delivers on one plane: the
// delivered scope. A topic whose group is outside it has no stream behind
// it on that path.
//
// The plane is named as in BRC-148 (a domain and its shard-bit width) and
// carries the plane's generation id as in BRC-139, so a sender can tell a
// re-shard from a change of membership. Groups are domain-tagged indices,
// the same numbers a shard manifest lists.
//
// The wire form of the value (an [ExtScope] extension in an ACK):
//
//	Offset  Size  Field
//	  0       1   Domain        plane selector; 0x1 is the object plane
//	  1       1   ShardBits     the plane's width
//	  2       1   Flags         bit 0: every group of the plane is delivered
//	                            bit 1: the groups are a bitmap, not a list
//	  3       1   reserved
//	  4      16   GenerationID
//	 20       2   N             groups in the list, or bytes in the bitmap
//	 22       …   list: N group indices, 16 bits each, ascending, unique
//	              bitmap: bit i (least significant first) is group base+i
//
// A Scope is immutable once built.
type Scope struct {
	domain     uint8
	shardBits  uint8
	all        bool
	generation [16]byte
	groups     []uint16 // domain-tagged, ascending, unique; nil when all
	bitmap     []uint64 // membership by plane-relative index; nil when all
	value      []byte   // wire form; nil when it exceeds MaxScopeValue
	gen        uint32
}

// NewScope builds the scope of a path that delivers the given groups of a
// plane. The groups are domain-tagged indices; order and duplicates do not
// matter. An empty list is a path that delivers nothing on the plane.
func NewScope(domain, shardBits uint8, generation [16]byte, groups []uint16) (*Scope, error) {
	if err := shard.ValidatePlane(domain, uint(shardBits)); err != nil {
		return nil, err
	}
	s := &Scope{domain: domain, shardBits: shardBits, generation: generation}
	base := shard.PlaneBase(domain)
	width := uint32(1) << shardBits
	s.groups = slices.Clone(groups)
	slices.Sort(s.groups)
	s.groups = slices.Compact(s.groups)
	if s.groups == nil {
		s.groups = []uint16{}
	}
	s.bitmap = make([]uint64, (width+63)/64)
	for _, g := range s.groups {
		if g < base || uint32(g-base) >= width {
			return nil, fmt.Errorf("interest: group %#04x is outside plane %#x at %d bits", g, domain, shardBits)
		}
		i := uint32(g - base)
		s.bitmap[i/64] |= 1 << (i % 64)
	}
	s.encode()
	return s, nil
}

// AllScope builds the scope of a path that delivers every group of a plane.
func AllScope(domain, shardBits uint8, generation [16]byte) (*Scope, error) {
	if err := shard.ValidatePlane(domain, uint(shardBits)); err != nil {
		return nil, err
	}
	s := &Scope{domain: domain, shardBits: shardBits, generation: generation, all: true}
	s.encode()
	return s, nil
}

// Domain returns the plane selector.
func (s *Scope) Domain() uint8 { return s.domain }

// ShardBits returns the plane's width.
func (s *Scope) ShardBits() uint8 { return s.shardBits }

// All reports whether every group of the plane is delivered.
func (s *Scope) All() bool { return s.all }

// Generation returns the plane's generation id.
func (s *Scope) Generation() [16]byte { return s.generation }

// Groups returns the delivered groups, ascending. Nil when [Scope.All].
func (s *Scope) Groups() []uint16 { return slices.Clone(s.groups) }

// Gen is a short value that changes whenever the scope does, and is never
// zero. An ACK carries it so a sender can tell that the scope it holds is
// out of date without receiving the whole scope each time.
func (s *Scope) Gen() uint32 { return s.gen }

// Value returns the wire form, or nil when the scope is too large to
// advertise. The result must not be modified.
func (s *Scope) Value() []byte { return s.value }

// GroupOf returns the domain-tagged group index of a topic on this scope's
// plane: the plane base plus the top ShardBits bits of the TopicID, the
// BRC-148 derivation.
func (s *Scope) GroupOf(t TopicID) uint16 { return GroupIndex(s.domain, s.shardBits, t) }

// Contains reports whether the path delivers the topic's group.
func (s *Scope) Contains(t TopicID) bool {
	if s.all {
		return true
	}
	i := binary.BigEndian.Uint32(t[0:4]) >> (32 - uint(s.shardBits))
	return s.bitmap[i/64]&(1<<(i%64)) != 0
}

// GroupIndex is the BRC-148 group derivation for a plane's 32-byte shard
// key: planeBase(domain) + (key[0:4] as a big-endian integer >> (32 - bits)).
// It agrees with [shard.PlaneEngine.GroupIndex].
func GroupIndex(domain, shardBits uint8, t TopicID) uint16 {
	return shard.PlaneBase(domain) + uint16(binary.BigEndian.Uint32(t[0:4])>>(32-uint(shardBits)))
}

var crc32c = crc32.MakeTable(crc32.Castagnoli)

func (s *Scope) encode() {
	v := make([]byte, scopeFixedSize, scopeFixedSize+2*len(s.groups))
	v[0] = s.domain
	v[1] = s.shardBits
	copy(v[4:20], s.generation[:])
	switch {
	case s.all:
		v[2] = scopeFlagAll
	default:
		bitmapBytes := (int(1)<<s.shardBits + 7) / 8
		if 2*len(s.groups) <= bitmapBytes {
			binary.BigEndian.PutUint16(v[20:22], uint16(len(s.groups)))
			for _, g := range s.groups {
				v = binary.BigEndian.AppendUint16(v, g)
			}
		} else {
			v[2] = scopeFlagBitmap
			binary.BigEndian.PutUint16(v[20:22], uint16(bitmapBytes))
			bm := make([]byte, bitmapBytes)
			base := shard.PlaneBase(s.domain)
			for _, g := range s.groups {
				i := int(g - base)
				bm[i/8] |= 1 << (i % 8)
			}
			v = append(v, bm...)
		}
	}
	// The generation value covers the whole scope, encodable or not, so a
	// scope too large to advertise still changes it when it changes.
	s.gen = crc32.Checksum(v, crc32c)
	if s.gen == 0 {
		s.gen = 1
	}
	if len(v) <= MaxScopeValue {
		s.value = v
	}
}

// ParseScope decodes the value of an [ExtScope] extension.
func ParseScope(v []byte) (*Scope, error) {
	if len(v) < scopeFixedSize {
		return nil, fmt.Errorf("%w: scope of %d bytes", ErrMalformed, len(v))
	}
	domain, bits, flags := v[0], v[1], v[2]
	var gen [16]byte
	copy(gen[:], v[4:20])
	n := int(binary.BigEndian.Uint16(v[20:22]))
	p := v[scopeFixedSize:]
	if err := shard.ValidatePlane(domain, uint(bits)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	switch {
	case flags&scopeFlagAll != 0:
		if n != 0 || len(p) != 0 {
			return nil, fmt.Errorf("%w: scope claims every group and lists some", ErrMalformed)
		}
		return AllScope(domain, bits, gen)
	case flags&scopeFlagBitmap != 0:
		if len(p) != n || n != (int(1)<<bits+7)/8 {
			return nil, fmt.Errorf("%w: scope bitmap of %d bytes for %d bits", ErrMalformed, len(p), bits)
		}
		base := shard.PlaneBase(domain)
		width := 1 << bits
		var groups []uint16
		for i := 0; i < width; i++ {
			if p[i/8]&(1<<(i%8)) != 0 {
				groups = append(groups, base+uint16(i))
			}
		}
		// Bits past the plane's width must be clear.
		for i := width; i < n*8; i++ {
			if p[i/8]&(1<<(i%8)) != 0 {
				return nil, fmt.Errorf("%w: scope bitmap sets a bit past the plane", ErrMalformed)
			}
		}
		return NewScope(domain, bits, gen, groups)
	default:
		if len(p) != 2*n {
			return nil, fmt.Errorf("%w: scope lists %d groups in %d bytes", ErrMalformed, n, len(p))
		}
		groups := make([]uint16, n)
		for i := range groups {
			groups[i] = binary.BigEndian.Uint16(p[2*i:])
			if i > 0 && groups[i] <= groups[i-1] {
				return nil, fmt.Errorf("%w: scope groups are not ascending and unique", ErrMalformed)
			}
		}
		s, err := NewScope(domain, bits, gen, groups)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		return s, nil
	}
}

// Equal reports whether two scopes describe the same plane, generation and
// groups. Two nil scopes are equal.
func (s *Scope) Equal(o *Scope) bool {
	if s == nil || o == nil {
		return s == o
	}
	return s.domain == o.domain && s.shardBits == o.shardBits && s.all == o.all &&
		s.generation == o.generation && slices.Equal(s.groups, o.groups)
}

// UnionScope returns the scope of a hop whose upstreams have the given
// scopes: what the hop as a whole can serve. It returns nil, meaning
// unknown, when any upstream's scope is unknown or when the upstreams
// disagree about the plane (its domain, width or generation), because a
// union of groups is only meaningful within one plane at one width.
func UnionScope(scopes []*Scope) *Scope {
	if len(scopes) == 0 {
		return nil
	}
	first := scopes[0]
	if first == nil {
		return nil
	}
	all := first.all
	var groups []uint16
	groups = append(groups, first.groups...)
	for _, s := range scopes[1:] {
		if s == nil || s.domain != first.domain || s.shardBits != first.shardBits || s.generation != first.generation {
			return nil
		}
		all = all || s.all
		groups = append(groups, s.groups...)
	}
	if all {
		u, _ := AllScope(first.domain, first.shardBits, first.generation)
		return u
	}
	u, _ := NewScope(first.domain, first.shardBits, first.generation, groups)
	return u
}
