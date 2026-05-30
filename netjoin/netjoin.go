// Package netjoin provides socket-level helpers for joining IPv6 multicast
// groups, branching between ASM ([IPV6_JOIN_GROUP]) and SSM
// ([MCAST_JOIN_SOURCE_GROUP], RFC 3678) by the presence of a source list.
//
// The helpers operate directly on file descriptors so they compose with
// existing raw-socket call sites that bypass Go's runtime poller. A
// [Limiter] and a [Jitter] helper are provided for cold-start storm
// protection at scale (hundreds of listeners × hundreds of publishers).
//
// [IPV6_JOIN_GROUP]: https://man7.org/linux/man-pages/man7/ipv6.7.html
// [MCAST_JOIN_SOURCE_GROUP]: https://datatracker.ietf.org/doc/html/rfc3678#section-4.1.2
package netjoin

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Join joins an IPv6 multicast group on fd. When sources is empty the call
// is an ASM (*, G) join via [unix.IPV6_JOIN_GROUP]. When sources is
// non-empty the call issues one (S, G) join per source via
// [unix.MCAST_JOIN_SOURCE_GROUP].
//
// fd must be an IPv6 UDP socket already bound to the desired port.
// ifaceIdx is the outbound interface index ([net.Interface.Index]).
// group must be an IPv6 multicast address.
//
// The function does not rate-limit; callers running at scale should wrap
// each invocation with a shared [*Limiter.Acquire].
func Join(fd, ifaceIdx int, group netip.Addr, sources []netip.Addr) error {
	if !group.Is6() {
		return fmt.Errorf("netjoin: group %s is not IPv6", group)
	}
	if len(sources) == 0 {
		return joinASM(fd, ifaceIdx, group)
	}
	for _, src := range sources {
		if !src.Is6() {
			return fmt.Errorf("netjoin: source %s is not IPv6", src)
		}
		if err := joinSSM(fd, ifaceIdx, group, src); err != nil {
			return fmt.Errorf("netjoin: SSM join (S=%s, G=%s): %w", src, group, err)
		}
	}
	return nil
}

// Leave is the counterpart to [Join]: ASM leave via [unix.IPV6_LEAVE_GROUP]
// when sources is empty, otherwise one [unix.MCAST_LEAVE_SOURCE_GROUP] per
// source.
func Leave(fd, ifaceIdx int, group netip.Addr, sources []netip.Addr) error {
	if !group.Is6() {
		return fmt.Errorf("netjoin: group %s is not IPv6", group)
	}
	if len(sources) == 0 {
		return leaveASM(fd, ifaceIdx, group)
	}
	for _, src := range sources {
		if !src.Is6() {
			return fmt.Errorf("netjoin: source %s is not IPv6", src)
		}
		if err := leaveSSM(fd, ifaceIdx, group, src); err != nil {
			return fmt.Errorf("netjoin: SSM leave (S=%s, G=%s): %w", src, group, err)
		}
	}
	return nil
}

func joinASM(fd, ifaceIdx int, group netip.Addr) error {
	mreq := &unix.IPv6Mreq{Interface: uint32(ifaceIdx)}
	copy(mreq.Multiaddr[:], group.AsSlice())
	return unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
}

func leaveASM(fd, ifaceIdx int, group netip.Addr) error {
	mreq := &unix.IPv6Mreq{Interface: uint32(ifaceIdx)}
	copy(mreq.Multiaddr[:], group.AsSlice())
	return unix.SetsockoptIPv6Mreq(fd, unix.IPPROTO_IPV6, unix.IPV6_LEAVE_GROUP, mreq)
}

func joinSSM(fd, ifaceIdx int, group, source netip.Addr) error {
	return ssmSetsockopt(fd, ifaceIdx, group, source, unix.MCAST_JOIN_SOURCE_GROUP)
}

func leaveSSM(fd, ifaceIdx int, group, source netip.Addr) error {
	return ssmSetsockopt(fd, ifaceIdx, group, source, unix.MCAST_LEAVE_SOURCE_GROUP)
}

// groupSourceReq mirrors C's `struct group_source_req` from <netinet/in.h>.
// Layout on Linux (LP64): __u32 gsr_interface + 4 bytes alignment padding
// + struct sockaddr_storage gsr_group (128 B) + struct sockaddr_storage
// gsr_source (128 B). Total 264 bytes. The sockaddr_storage fields hold
// sockaddr_in6 values for IPv6 groups.
type groupSourceReq struct {
	Interface uint32
	_         [4]byte
	Group     [128]byte
	Source    [128]byte
}

func ssmSetsockopt(fd, ifaceIdx int, group, source netip.Addr, opt int) error {
	var gsr groupSourceReq
	gsr.Interface = uint32(ifaceIdx)
	putSockaddrIn6(&gsr.Group, group)
	putSockaddrIn6(&gsr.Source, source)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.IPPROTO_IPV6),
		uintptr(opt),
		uintptr(unsafe.Pointer(&gsr)),
		unsafe.Sizeof(gsr),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// putSockaddrIn6 writes a sockaddr_in6 into the 128-byte sockaddr_storage
// buffer. The IPv6 address goes in the sin6_addr field at offset 8; port,
// flowinfo, and scope_id are left zero.
//
// sin6_family is written in NATIVE byte order per the Linux sockaddr ABI
// (sa_family_t is an unsigned short interpreted by the kernel without
// htons). On all Linux architectures we target (amd64, arm64) this is
// little-endian.
func putSockaddrIn6(buf *[128]byte, addr netip.Addr) {
	binary.NativeEndian.PutUint16(buf[0:2], unix.AF_INET6)
	// port (2..4), flowinfo (4..8) zero.
	a := addr.As16()
	copy(buf[8:24], a[:])
	// scope_id (24..28) zero.
}

// Limiter is a token-bucket rate limiter intended to bound the per-listener
// join/leave rate so a cold-start storm cannot overrun the upstream MLDv2
// querier. Acquire one slot per setsockopt call:
//
//	lim := netjoin.NewLimiter(1000)        // 1000 joins/sec
//	defer lim.Stop()
//	for _, src := range sources {
//	    if err := lim.Acquire(ctx); err != nil { return err }
//	    if err := netjoin.Join(fd, ifIdx, grp, []netip.Addr{src}); err != nil { return err }
//	}
//
// A nil receiver is a no-op (Acquire returns nil immediately), so the
// limiter can be threaded through call sites without requiring callers to
// nil-check.
type Limiter struct {
	bucket chan struct{}
	ticker *time.Ticker
	stop   chan struct{}
}

// NewLimiter creates a token-bucket limiter that allows up to perSecond
// operations per second with a burst of perSecond. perSecond must be > 0;
// a value of 0 or negative returns nil (no rate limiting).
func NewLimiter(perSecond int) *Limiter {
	if perSecond <= 0 {
		return nil
	}
	l := &Limiter{
		bucket: make(chan struct{}, perSecond),
		ticker: time.NewTicker(time.Second / time.Duration(perSecond)),
		stop:   make(chan struct{}),
	}
	// Prefill burst so cold-start is paced from the first call.
	for i := 0; i < perSecond; i++ {
		l.bucket <- struct{}{}
	}
	go l.refill()
	return l
}

func (l *Limiter) refill() {
	for {
		select {
		case <-l.stop:
			return
		case <-l.ticker.C:
			select {
			case l.bucket <- struct{}{}:
			default:
			}
		}
	}
}

// Acquire blocks until a token is available or ctx is cancelled.
func (l *Limiter) Acquire(ctx context.Context) error {
	if l == nil {
		return nil
	}
	select {
	case <-l.bucket:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop releases the underlying ticker. Safe to call on a nil receiver.
func (l *Limiter) Stop() {
	if l == nil {
		return
	}
	close(l.stop)
	l.ticker.Stop()
}

// Jitter sleeps for a uniformly random duration in [0, max). When max is
// zero or negative, Jitter is a no-op. Intended to be called once at
// listener startup so a fleet of replicas does not issue MLDv2 reports in
// the same millisecond window.
func Jitter(ctx context.Context, max time.Duration) {
	if max <= 0 {
		return
	}
	d := time.Duration(rand.Int64N(int64(max)))
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
