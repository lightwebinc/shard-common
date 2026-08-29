package netjoin

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPutSockaddrIn6Layout pins the per-OS sockaddr_in6 prefix. Linux reads a
// native-endian uint16 family at offset 0; the BSDs read sin6_len at byte 0
// and sin6_family at byte 1 and reject anything else with EINVAL.
func TestPutSockaddrIn6Layout(t *testing.T) {
	addr := netip.MustParseAddr("fd00:50:0:3::1")
	var buf [128]byte
	putSockaddrIn6(&buf, addr)

	switch runtime.GOOS {
	case "linux":
		if got := binary.NativeEndian.Uint16(buf[0:2]); got != unix.AF_INET6 {
			t.Fatalf("linux family: got %d want %d", got, unix.AF_INET6)
		}
	default:
		if buf[0] != 28 || buf[1] != unix.AF_INET6 {
			t.Fatalf("bsd len/family: got %d/%d want 28/%d", buf[0], buf[1], unix.AF_INET6)
		}
	}
	for i := 2; i < 8; i++ {
		if buf[i] != 0 {
			t.Fatalf("port/flowinfo byte %d not zero", i)
		}
	}
	a := addr.As16()
	if string(buf[8:24]) != string(a[:]) {
		t.Fatalf("sin6_addr mismatch")
	}
	for i := 24; i < 128; i++ {
		if buf[i] != 0 {
			t.Fatalf("trailing byte %d not zero", i)
		}
	}
	if got := binary.Size(groupSourceReq{}); got != 264 {
		t.Fatalf("group_source_req size %d, want 264", got)
	}
}
