//go:build linux

package netjoin

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/unix"
)

// putSockaddrIn6 writes a sockaddr_in6 into the 128-byte sockaddr_storage
// buffer. The IPv6 address goes in the sin6_addr field at offset 8; port,
// flowinfo, and scope_id are left zero.
//
// Linux sockaddr ABI: sa_family_t is an unsigned short at offset 0 in NATIVE
// byte order (the kernel reads it without htons). All Linux architectures we
// target (amd64, arm64) are little-endian.
func putSockaddrIn6(buf *[128]byte, addr netip.Addr) {
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	// port (2..4), flowinfo (4..8) zero.
	a := addr.As16()
	copy(buf[8:24], a[:])
	// scope_id (24..28) zero.
}
