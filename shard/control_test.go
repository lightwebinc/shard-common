package shard

import (
	"net"
	"testing"
)

func TestControlGroupAddr_noMiddleBytes(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, [11]byte{}, CtrlGroupBeacon)
	want := net.ParseIP("FF05::FF:FFFD")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_withMiddleBytes(t *testing.T) {
	var middle [11]byte
	middle[0] = 0xDE
	middle[10] = 0xAD
	ip := ControlGroupAddr(0xFF05, middle, CtrlGroupBeacon)
	// Byte 2 = 0xDE, byte 12 = 0xAD, bytes 13-15 = FF:FF:FD
	if ip[2] != 0xDE {
		t.Errorf("ip[2] = 0x%02X, want 0xDE", ip[2])
	}
	if ip[12] != 0xAD {
		t.Errorf("ip[12] = 0x%02X, want 0xAD", ip[12])
	}
	if ip[13] != 0xFF || ip[14] != 0xFF || ip[15] != 0xFD {
		t.Errorf("suffix = %02X%02X%02X, want FFFFFD", ip[13], ip[14], ip[15])
	}
}

func TestControlGroupAddr_globalScope(t *testing.T) {
	ip := ControlGroupAddr(0xFF0E, [11]byte{}, CtrlGroupBeacon)
	want := net.ParseIP("FF0E::FF:FFFD")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_controlChannel(t *testing.T) {
	ip := ControlGroupAddr(0xFF0E, [11]byte{}, CtrlGroupControl)
	want := net.ParseIP("FF0E::FF:FFFE")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddr_subtreeAnnounce(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, [11]byte{}, CtrlGroupSubtreeAnnounce)
	want := net.ParseIP("FF05::FF:FFFC")
	if !ip.Equal(want) {
		t.Errorf("got %v, want %v", ip, want)
	}
}

func TestControlGroupAddrOrthogonal(t *testing.T) {
	// Assert that control indices never collide with shard indices
	// for shardBits 1–23.
	for bits := uint(1); bits <= 23; bits++ {
		e := New(0xFF05, [11]byte{}, bits)
		numGroups := e.NumGroups()
		if CtrlGroupSubtreeAnnounce < numGroups {
			t.Errorf("shardBits=%d: CtrlGroupSubtreeAnnounce (0x%X) < NumGroups (0x%X)",
				bits, CtrlGroupSubtreeAnnounce, numGroups)
		}
		if CtrlGroupBeacon < numGroups {
			t.Errorf("shardBits=%d: CtrlGroupBeacon (0x%X) < NumGroups (0x%X)",
				bits, CtrlGroupBeacon, numGroups)
		}
		if CtrlGroupControl < numGroups {
			t.Errorf("shardBits=%d: CtrlGroupControl (0x%X) < NumGroups (0x%X)",
				bits, CtrlGroupControl, numGroups)
		}
	}
}

func TestControlGroupAddr_isMulticast(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, [11]byte{}, CtrlGroupBeacon)
	if !ip.IsMulticast() {
		t.Errorf("expected multicast address, got %v", ip)
	}
}

func TestControlGroupAddr_isIPv6(t *testing.T) {
	ip := ControlGroupAddr(0xFF05, [11]byte{}, CtrlGroupBeacon)
	if ip.To4() != nil {
		t.Errorf("expected IPv6-only address, got IPv4-mappable: %v", ip)
	}
	if len(ip) != net.IPv6len {
		t.Errorf("IP length = %d, want 16", len(ip))
	}
}
