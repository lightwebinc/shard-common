package shard

import (
	"net"
	"testing"
)

func TestGroupAddr_defaultBitcoin(t *testing.T) {
	ip := GroupAddr(0xFF05, DefaultGroupID, GroupBeacon)
	want := net.ParseIP("FF05::B:FFFD")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestGroupAddr_customGroupID(t *testing.T) {
	ip := GroupAddr(0xFF05, 0xCAFE, GroupBeacon)
	// bytes [12:14] = CAFE, [14:16] = FFFD, [2:12] = zero
	if ip[12] != 0xCA || ip[13] != 0xFE {
		t.Errorf("group-id bytes = %02X%02X, want CAFE", ip[12], ip[13])
	}
	if ip[14] != 0xFF || ip[15] != 0xFD {
		t.Errorf("suffix = %02X%02X, want FFFD", ip[14], ip[15])
	}
	for i := 2; i < 12; i++ {
		if ip[i] != 0 {
			t.Errorf("byte %d = 0x%02X, want 0 (IANA boundary)", i, ip[i])
		}
	}
}

func TestGroupAddr_globalScope(t *testing.T) {
	ip := GroupAddr(0xFF0E, DefaultGroupID, GroupBeacon)
	want := net.ParseIP("FF0E::B:FFFD")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestGroupAddr_blockBroadcast(t *testing.T) {
	ip := GroupAddr(0xFF0E, DefaultGroupID, GroupBlockBroadcast)
	want := net.ParseIP("FF0E::B:FFFE")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestGroupAddr_subtreeAnnounce(t *testing.T) {
	ip := GroupAddr(0xFF05, DefaultGroupID, GroupSubtreeAnnounce)
	want := net.ParseIP("FF05::B:FFFB")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestGroupAddr_subtreeGroupAnnounce(t *testing.T) {
	ip := GroupAddr(0xFF05, DefaultGroupID, GroupSubtreeGroupAnnounce)
	want := net.ParseIP("FF05::B:FFFC")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestGroupAddrOrthogonal(t *testing.T) {
	// Assert that network-service group indices never collide with shard
	// indices for shardBits 1–12.
	for bits := uint(1); bits <= 12; bits++ {
		e := New(0xFF05, DefaultGroupID, bits)
		numGroups := uint16(e.NumGroups())
		if e.NumGroups() <= 0xFFFF && uint16(GroupSubtreeAnnounce) < numGroups {
			t.Errorf("shardBits=%d: GroupSubtreeAnnounce (0x%X) < NumGroups (0x%X)",
				bits, uint16(GroupSubtreeAnnounce), numGroups)
		}
		if e.NumGroups() <= 0xFFFF && uint16(GroupBeacon) < numGroups {
			t.Errorf("shardBits=%d: GroupBeacon (0x%X) < NumGroups (0x%X)",
				bits, uint16(GroupBeacon), numGroups)
		}
		if e.NumGroups() <= 0xFFFF && uint16(GroupBlockBroadcast) < numGroups {
			t.Errorf("shardBits=%d: GroupBlockBroadcast (0x%X) < NumGroups (0x%X)",
				bits, uint16(GroupBlockBroadcast), numGroups)
		}
	}
}

func TestGroupAddr_isMulticast(t *testing.T) {
	ip := GroupAddr(0xFF05, DefaultGroupID, GroupBeacon)
	if !ip.IsMulticast() {
		t.Errorf("expected multicast address, got %v", ip)
	}
}

func TestGroupAddr_isIPv6(t *testing.T) {
	ip := GroupAddr(0xFF05, DefaultGroupID, GroupBeacon)
	if ip.To4() != nil {
		t.Errorf("expected IPv6-only address, got IPv4-mappable: %v", ip)
	}
	if len(ip) != net.IPv6len {
		t.Errorf("IP length = %d, want 16", len(ip))
	}
}

func TestGroupIdxString(t *testing.T) {
	cases := []struct {
		idx  GroupIdx
		want string
	}{
		{GroupBlockHeader, "block_header"},
		{GroupSubtreeAnnounce, "subtree_announce"},
		{GroupSubtreeGroupAnnounce, "subtree_group_announce"},
		{GroupBeacon, "beacon"},
		{GroupBlockBroadcast, "block_broadcast"},
		{GroupCoinbaseFlow, "coinbase_flow"},
		{GroupAnchorFlow, "anchor_flow"},
		{GroupIdx(0x1234), "0x1234"},
	}
	for _, tc := range cases {
		if got := tc.idx.String(); got != tc.want {
			t.Errorf("GroupIdx(0x%04X).String() = %q, want %q", uint16(tc.idx), got, tc.want)
		}
	}
}
