//go:build freebsd || openbsd || netbsd || dragonfly || darwin

package netjoin

import (
	"net/netip"

	"golang.org/x/sys/unix"
)

// sockaddrIn6Len is sizeof(struct sockaddr_in6) on the BSDs: sin6_len(1) +
// sin6_family(1) + sin6_port(2) + sin6_flowinfo(4) + sin6_addr(16) +
// sin6_scope_id(4).
const sockaddrIn6Len = 28

// putSockaddrIn6 writes a sockaddr_in6 into the 128-byte sockaddr_storage
// buffer. The IPv6 address goes in the sin6_addr field at offset 8; port,
// flowinfo, and scope_id are left zero.
//
// BSD sockaddr ABI: byte 0 is sin6_len and byte 1 is sin6_family (both
// uint8). The kernel rejects MCAST_JOIN_SOURCE_GROUP with EINVAL unless
// ss_len == sizeof(sockaddr_in6) AND ss_family == AF_INET6, so the Linux
// layout (uint16 family at offset 0) fails every SSM join on these systems.
func putSockaddrIn6(buf *[128]byte, addr netip.Addr) {
	buf[0] = sockaddrIn6Len
	buf[1] = unix.AF_INET6
	// port (2..4), flowinfo (4..8) zero.
	a := addr.As16()
	copy(buf[8:24], a[:])
	// scope_id (24..28) zero.
}
