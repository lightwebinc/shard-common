package shard

import (
	"net"
	"testing"
)

func TestControlGroupAddr_defaultBitcoin(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, DefaultGroupID, CtrlGroupBeacon)
	want := net.ParseIP("FF05::B:FFFD")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_customGroupID(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, 0xCAFE, CtrlGroupBeacon)
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

func TestControlGroupAddr_globalScope(t *testing.T) {
	ip := ControlGroupAddr(0xFF0E, DefaultGroupID, CtrlGroupBeacon)
	want := net.ParseIP("FF0E::B:FFFD")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_controlChannel(t *testing.T) {
	ip := ControlGroupAddr(0xFF0E, DefaultGroupID, CtrlGroupControl)
	want := net.ParseIP("FF0E::B:FFFE")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_subtreeAnnounce(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, DefaultGroupID, CtrlGroupSubtreeAnnounce)
	want := net.ParseIP("FF05::B:FFFB")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_subtreeGroupAnnounce(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, DefaultGroupID, CtrlGroupSubtreeGroupAnnounce)
	want := net.ParseIP("FF05::B:FFFC")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddrOrthogonal(t *testing.T) {
	// Assert that control indices never collide with shard indices
	// for shardBits 1–12.
	for bits := uint(1); bits <= 12; bits++ {
		e := New(0xFF05, DefaultGroupID, bits)
		numGroups := uint16(e.NumGroups())
		if e.NumGroups() <= 0xFFFF && CtrlGroupSubtreeAnnounce < numGroups {
			t.Errorf("shardBits=%d: CtrlGroupSubtreeAnnounce (0x%X) < NumGroups (0x%X)",
				bits, CtrlGroupSubtreeAnnounce, numGroups)
		}
		if e.NumGroups() <= 0xFFFF && CtrlGroupBeacon < numGroups {
			t.Errorf("shardBits=%d: CtrlGroupBeacon (0x%X) < NumGroups (0x%X)",
				bits, CtrlGroupBeacon, numGroups)
		}
		if e.NumGroups() <= 0xFFFF && CtrlGroupControl < numGroups {
			t.Errorf("shardBits=%d: CtrlGroupControl (0x%X) < NumGroups (0x%X)",
				bits, CtrlGroupControl, numGroups)
		}
	}
}

func TestControlGroupAddr_isMulticast(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, DefaultGroupID, CtrlGroupBeacon)
	if !ip.IsMulticast() {
		t.Errorf("expected multicast address, got %v", ip)
	}
}

func TestControlGroupAddr_isIPv6(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, DefaultGroupID, CtrlGroupBeacon)
	if ip.To4() != nil {
		t.Errorf("expected IPv6-only address, got IPv4-mappable: %v", ip)
	}
	if len(ip) != net.IPv6len {
		t.Errorf("IP length = %d, want 16", len(ip))
	}
}
