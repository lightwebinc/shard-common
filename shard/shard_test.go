package shard

import (
	"net"
	"testing"
)

func engine8() *Engine { return New(0xFF05, DefaultGroupID, 8) }

func TestGroupIndexTopBits(t *testing.T) {
	e := engine8()
	var txid [32]byte
	txid[0] = 0xAB // top 8 bits = 0xAB = 171
	if got := e.GroupIndex(&txid); got != 0xAB {
		t.Errorf("GroupIndex = 0x%X, want 0xAB", got)
	}
}

func TestGroupIndexZero(t *testing.T) {
	e := engine8()
	var txid [32]byte
	if got := e.GroupIndex(&txid); got != 0 {
		t.Errorf("GroupIndex = %d, want 0", got)
	}
}

func TestGroupIndexMaxBits(t *testing.T) {
	e := New(0xFF05, DefaultGroupID, 15)
	var txid [32]byte
	txid[0], txid[1] = 0xFF, 0xFE // top 15 bits = 0x7FFF
	if got := e.GroupIndex(&txid); got != 0x7FFF {
		t.Errorf("GroupIndex = 0x%X, want 0x7FFF", got)
	}
}

func TestNumGroups(t *testing.T) {
	cases := []struct {
		bits   uint
		groups uint32
	}{
		{1, 2},
		{8, 256},
		{12, 4096},
		{15, 32768},
	}
	for _, c := range cases {
		e := New(0xFF05, DefaultGroupID, c.bits)
		if got := e.NumGroups(); got != c.groups {
			t.Errorf("bits=%d: NumGroups=%d, want %d", c.bits, got, c.groups)
		}
	}
}

func TestAddrPrefix(t *testing.T) {
	e := engine8()
	addr := e.Addr(0, 9001)
	if addr.IP[0] != 0xFF || addr.IP[1] != 0x05 {
		t.Errorf("prefix bytes = %02X%02X, want FF05", addr.IP[0], addr.IP[1])
	}
}

func TestAddrGroupIndexPlacement(t *testing.T) {
	e := engine8()
	addr := e.Addr(0x2B3C, 9001)
	if addr.IP[14] != 0x2B || addr.IP[15] != 0x3C {
		t.Errorf("group bytes = %02X%02X, want 2B3C",
			addr.IP[14], addr.IP[15])
	}
}

func TestAddrGroupID(t *testing.T) {
	e := New(0xFF05, 0xCAFE, 8)
	addr := e.Addr(0, 9001)
	if addr.IP[12] != 0xCA || addr.IP[13] != 0xFE {
		t.Errorf("group-id bytes = %02X%02X, want CAFE", addr.IP[12], addr.IP[13])
	}
}

func TestAddrIANABoundaryZero(t *testing.T) {
	// Bytes [2:12] must be zero per IANA 96-bit boundary.
	e := New(0xFF05, DefaultGroupID, 8)
	addr := e.Addr(0xAB, 9001)
	for i := 2; i < 12; i++ {
		if addr.IP[i] != 0 {
			t.Errorf("byte %d = 0x%02X, want 0 (IANA 96-bit boundary)", i, addr.IP[i])
		}
	}
}

func TestAddrDefaultBitcoinAllocation(t *testing.T) {
	e := New(0xFF05, DefaultGroupID, 8)
	addr := e.Addr(0, 9001)
	want := net.ParseIP("FF05::B:0")
	if !addr.IP.Equal(want) {
		t.Errorf("got %v, want %v", addr.IP, want)
	}
}

func TestAddrIsMulticast(t *testing.T) {
	e := engine8()
	addr := e.Addr(1, 9001)
	if !addr.IP.IsMulticast() {
		t.Errorf("Addr returned non-multicast IP: %v", addr.IP)
	}
}

func TestAddrPort(t *testing.T) {
	e := engine8()
	addr := e.Addr(0, 1234)
	if addr.Port != 1234 {
		t.Errorf("Port = %d, want 1234", addr.Port)
	}
}

func TestConsistentHashing(t *testing.T) {
	// When shard bits increase from N to N+1, group g at width N maps to
	// either 2g or 2g+1 at width N+1.
	var txid [32]byte
	txid[0] = 0x80 // top bit set

	e4 := New(0xFF05, DefaultGroupID, 4)
	e5 := New(0xFF05, DefaultGroupID, 5)

	g4 := e4.GroupIndex(&txid)
	g5 := e5.GroupIndex(&txid)

	if g5 != g4*2 && g5 != g4*2+1 {
		t.Errorf("consistent hashing broken: bits=4 index=%d, bits=5 index=%d (want %d or %d)",
			g4, g5, g4*2, g4*2+1)
	}
}

func TestAddrIsIPv6(t *testing.T) {
	e := engine8()
	addr := e.Addr(1, 9001)
	if addr.IP.To4() != nil {
		t.Errorf("expected IPv6 address, got IPv4-mappable: %v", addr.IP)
	}
	if len(addr.IP) != net.IPv6len {
		t.Errorf("IP length = %d, want 16", len(addr.IP))
	}
}

func TestShardBitsAccessor(t *testing.T) {
	e := New(0xFF05, DefaultGroupID, 12)
	if e.ShardBits() != 12 {
		t.Errorf("ShardBits = %d, want 12", e.ShardBits())
	}
}

func TestGroupIDAccessor(t *testing.T) {
	e := New(0xFF05, 0x1234, 8)
	if e.GroupID() != 0x1234 {
		t.Errorf("GroupID = 0x%04X, want 0x1234", e.GroupID())
	}
}
