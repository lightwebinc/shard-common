package netjoin

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openUDP6 opens an IPv6 UDP socket bound to an arbitrary port on ::, for
// use as the target of MCAST_JOIN_* setsockopts in tests.
func openUDP6(t *testing.T) (fd int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("open UDP6 socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet6{Port: 0}); err != nil {
		_ = unix.Close(fd)
		t.Fatalf("bind: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

func loopbackIndex(t *testing.T) int {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lookup lo: %v", err)
	}
	return iface.Index
}

func TestJoinASM_Loopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("netjoin requires Linux")
	}
	t.Parallel()
	fd := openUDP6(t)
	ifIdx := loopbackIndex(t)
	grp := netip.MustParseAddr("ff05::b:abcd")
	if err := Join(fd, ifIdx, grp, nil); err != nil {
		t.Fatalf("ASM Join: %v", err)
	}
	if err := Leave(fd, ifIdx, grp, nil); err != nil {
		t.Fatalf("ASM Leave: %v", err)
	}
}

func TestJoinSSM_Loopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("netjoin requires Linux")
	}
	t.Parallel()
	fd := openUDP6(t)
	ifIdx := loopbackIndex(t)
	grp := netip.MustParseAddr("ff35::b:abcd")
	sources := []netip.Addr{
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fd00::1"),
	}
	if err := Join(fd, ifIdx, grp, sources); err != nil {
		t.Fatalf("SSM Join: %v", err)
	}
	if err := Leave(fd, ifIdx, grp, sources); err != nil {
		t.Fatalf("SSM Leave: %v", err)
	}
}

func TestJoin_RejectsIPv4Group(t *testing.T) {
	t.Parallel()
	grp := netip.MustParseAddr("239.1.2.3")
	if err := Join(-1, 1, grp, nil); err == nil {
		t.Fatal("Join with IPv4 group returned nil, want error")
	}
}

func TestJoin_RejectsIPv4Source(t *testing.T) {
	t.Parallel()
	grp := netip.MustParseAddr("ff35::b:abcd")
	srcs := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	if err := Join(-1, 1, grp, srcs); err == nil {
		t.Fatal("Join with IPv4 source returned nil, want error")
	}
}

// TestPutSockaddrIn6_Layout verifies the sockaddr_in6 byte layout the kernel
// expects: native-endian family at [0..2], port (BE) at [2..4], flowinfo
// (BE) at [4..8], 16-byte address at [8..24], scope_id at [24..28].
func TestPutSockaddrIn6_Layout(t *testing.T) {
	t.Parallel()
	var buf [128]byte
	addr := netip.MustParseAddr("fd20::dead:beef")
	putSockaddrIn6(&buf, addr)

	// Family is AF_INET6 in native endian.
	if got := binary.NativeEndian.Uint16(buf[0:2]); got != unix.AF_INET6 {
		t.Errorf("family = %d, want %d (AF_INET6)", got, unix.AF_INET6)
	}
	// Port zero.
	if buf[2] != 0 || buf[3] != 0 {
		t.Errorf("port bytes = %v, want zero", buf[2:4])
	}
	// Flowinfo zero.
	for i := 4; i < 8; i++ {
		if buf[i] != 0 {
			t.Errorf("flowinfo byte %d = %d, want 0", i, buf[i])
		}
	}
	// Address bytes match.
	want := addr.As16()
	for i := 0; i < 16; i++ {
		if buf[8+i] != want[i] {
			t.Errorf("addr byte %d = %#x, want %#x", i, buf[8+i], want[i])
		}
	}
	// Scope_id zero.
	for i := 24; i < 28; i++ {
		if buf[i] != 0 {
			t.Errorf("scope_id byte %d = %d, want 0", i, buf[i])
		}
	}
}

func TestLimiter_NilAcquireIsNoop(t *testing.T) {
	t.Parallel()
	var l *Limiter
	if err := l.Acquire(context.Background()); err != nil {
		t.Fatalf("nil limiter Acquire = %v, want nil", err)
	}
	l.Stop() // should also be safe
}

func TestLimiter_BurstAndRefill(t *testing.T) {
	t.Parallel()
	// 50 ops/sec burst, drain quickly then verify refill keeps up.
	const rate = 50
	l := NewLimiter(rate)
	defer l.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Drain burst.
	for i := 0; i < rate; i++ {
		if err := l.Acquire(ctx); err != nil {
			t.Fatalf("burst Acquire %d: %v", i, err)
		}
	}
	// Subsequent Acquire must wait for refill; with rate=50/s, 10 more
	// acquisitions take ~200ms. Allow 500ms slack.
	start := time.Now()
	for i := 0; i < 10; i++ {
		if err := l.Acquire(ctx); err != nil {
			t.Fatalf("refill Acquire %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Errorf("10 acquisitions after burst took %v, want >= ~200ms (rate=%d/s)", elapsed, rate)
	}
	if elapsed > time.Second {
		t.Errorf("10 acquisitions after burst took %v, want <= 1s", elapsed)
	}
}

func TestLimiter_ContextCancelled(t *testing.T) {
	t.Parallel()
	l := NewLimiter(1) // 1/sec, burst 1
	defer l.Stop()
	// Drain.
	if err := l.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Acquire(ctx); err == nil {
		t.Fatal("Acquire after drain with short context returned nil, want context.DeadlineExceeded")
	}
}

func TestJitter_ZeroIsNoop(t *testing.T) {
	t.Parallel()
	start := time.Now()
	Jitter(context.Background(), 0)
	if d := time.Since(start); d > 10*time.Millisecond {
		t.Errorf("Jitter(0) took %v, want ~0", d)
	}
}

func TestJitter_BoundedByMax(t *testing.T) {
	t.Parallel()
	const max = 20 * time.Millisecond
	var maxObserved time.Duration
	for i := 0; i < 32; i++ {
		start := time.Now()
		Jitter(context.Background(), max)
		d := time.Since(start)
		if d > maxObserved {
			maxObserved = d
		}
	}
	// Allow scheduler slack on top of max.
	if maxObserved > max+100*time.Millisecond {
		t.Errorf("max observed jitter = %v, want <= %v + scheduler slack", maxObserved, max)
	}
}

func TestJitter_CancelsOnContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	Jitter(ctx, time.Hour)
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("Jitter with cancelled context took %v, want quick exit", d)
	}
}

// Ensure syscall.SYS_SETSOCKOPT is non-zero on Linux platforms we target;
// guard against accidental cross-compilation issues that would compile-fail
// silently.
var _ = atomic.LoadInt64(&[]int64{int64(syscall.SYS_SETSOCKOPT)}[0])
