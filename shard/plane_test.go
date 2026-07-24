package shard

import (
	"encoding/binary"
	"errors"
	"testing"
)

func keyWithPrefix(prefix uint32) [32]byte {
	var k [32]byte
	binary.BigEndian.PutUint32(k[0:4], prefix)
	return k
}

func TestPlaneConstants(t *testing.T) {
	if DomainTx != 0x0 || DomainBEEF != 0x1 || DomainMax != 0x0E {
		t.Fatalf("domain constants wrong: %X %X %X", DomainTx, DomainBEEF, DomainMax)
	}
	if PlaneBase(DomainBEEF) != 0x1000 {
		t.Fatalf("PlaneBase(BEEF) = 0x%04X, want 0x1000", PlaneBase(DomainBEEF))
	}
	if ControlBase != 0xF800 {
		t.Fatalf("ControlBase = 0x%04X, want 0xF800", ControlBase)
	}
}

func TestPlaneOf(t *testing.T) {
	cases := []struct {
		idx  uint16
		want uint8
	}{
		{0x0000, 0x0}, {0x0FFF, 0x0}, {0x1000, 0x1}, {0x1FFF, 0x1}, {0xE000, 0xE},
	}
	for _, c := range cases {
		if got := PlaneOf(c.idx); got != c.want {
			t.Errorf("PlaneOf(0x%04X) = 0x%X, want 0x%X", c.idx, got, c.want)
		}
	}
}

func TestSlotSpan(t *testing.T) {
	cases := []struct {
		bits uint
		want uint8
	}{
		{1, 1}, {12, 1}, {13, 2}, {14, 4}, {15, 8},
	}
	for _, c := range cases {
		if got := SlotSpan(c.bits); got != c.want {
			t.Errorf("SlotSpan(%d) = %d, want %d", c.bits, got, c.want)
		}
	}
}

func TestValidatePlane(t *testing.T) {
	cases := []struct {
		name   string
		domain uint8
		bits   uint
		ok     bool
	}{
		{"beef bits 12", DomainBEEF, 12, true},
		{"beef bits 1", DomainBEEF, 1, true},
		{"beef wide 15 fits runway", DomainBEEF, 15, true}, // 0x1000+0x8000=0x9000 ≤ 0xF800
		{"tx bits 12", DomainTx, 12, true},
		{"tx bits 13 violates BRC-129 cap", DomainTx, 13, false},
		{"domain 0xF forbidden", 0x0F, 4, false},
		{"bits 0 rejected", DomainBEEF, 0, false},
		{"bits 16 rejected", DomainBEEF, 16, false},
		{"top domain single slot ok", 0x0E, 12, true},        // 0xE000+0x1000=0xF000 ≤ 0xF800
		{"top domain wide reaches control", 0x0E, 13, false}, // 0xE000+0x2000 > 0xF800
	}
	for _, c := range cases {
		err := ValidatePlane(c.domain, c.bits)
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrBadPlane) {
			t.Errorf("%s: err = %v, want ErrBadPlane", c.name, err)
		}
	}
}

func TestPlaneEngineGroupIndex(t *testing.T) {
	p, err := NewPlane(0xFF05, DefaultGroupID, 12, DomainBEEF)
	if err != nil {
		t.Fatalf("NewPlane: %v", err)
	}

	// Top 12 bits of 0xABCDEF01 = 0xABC.
	key := keyWithPrefix(0xABCDEF01)
	if got := p.GroupIndex(&key); got != 0x1000+0xABC {
		t.Fatalf("GroupIndex = 0x%04X, want 0x1ABC", got)
	}

	// Domain 0 reduces exactly to the BRC-129 derivation.
	p0, err := NewPlane(0xFF05, DefaultGroupID, 12, DomainTx)
	if err != nil {
		t.Fatalf("NewPlane(tx): %v", err)
	}
	e := New(0xFF05, DefaultGroupID, 12)
	if p0.GroupIndex(&key) != e.GroupIndex(&key) {
		t.Fatal("domain-0 PlaneEngine diverges from Engine")
	}
}

func TestPlaneEngineConsistentHashSplit(t *testing.T) {
	key := keyWithPrefix(0xABCDEF01)
	parent, _ := NewPlane(0xFF05, DefaultGroupID, 8, DomainBEEF)
	child, _ := NewPlane(0xFF05, DefaultGroupID, 9, DomainBEEF)

	pIdx := parent.GroupIndex(&key) - uint32(parent.Base())
	cIdx := child.GroupIndex(&key) - uint32(child.Base())
	if cIdx != pIdx*2 && cIdx != pIdx*2+1 {
		t.Fatalf("widening split broken: parent 0x%X → child 0x%X", pIdx, cIdx)
	}
}

func TestPlaneEngineAddrAndGroups(t *testing.T) {
	p, err := NewPlane(0xFF3E, DefaultGroupID, 4, DomainBEEF)
	if err != nil {
		t.Fatalf("NewPlane: %v", err)
	}

	groups := p.Groups()
	if len(groups) != 16 || groups[0] != 0x1000 || groups[15] != 0x100F {
		t.Fatalf("Groups() = len %d [%04X..%04X], want 16 [1000..100F]",
			len(groups), groups[0], groups[len(groups)-1])
	}

	addr := p.Addr(uint32(groups[3]), 9001)
	ip := addr.IP
	if binary.BigEndian.Uint16(ip[0:2]) != 0xFF3E ||
		binary.BigEndian.Uint16(ip[12:14]) != DefaultGroupID ||
		binary.BigEndian.Uint16(ip[14:16]) != 0x1003 {
		t.Fatalf("Addr bytes wrong: %v", ip)
	}
}
