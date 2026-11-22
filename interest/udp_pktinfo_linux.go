//go:build linux

package interest

import (
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

// pktConn reads the destination address of each datagram (IPV6_PKTINFO,
// IP_PKTINFO) and sends from a chosen local address. If the socket refuses
// the options it behaves as a plain socket: the kernel picks the source.
type pktConn struct {
	conn   *net.UDPConn
	v6     bool // an AF_INET6 socket, which may also carry IPv4 as mapped addresses
	enable bool
	oob    []byte
}

func newPktConn(conn *net.UDPConn) *pktConn {
	pc := &pktConn{conn: conn, oob: make([]byte, 128)}
	rc, err := conn.SyscallConn()
	if err != nil {
		return pc
	}
	_ = rc.Control(func(fd uintptr) {
		domain, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_DOMAIN)
		if err != nil {
			return
		}
		pc.v6 = domain == syscall.AF_INET6
		ok := true
		if pc.v6 {
			ok = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1) == nil
		}
		// IPv4, and on a dual-stack socket the IPv4 it carries.
		v4 := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1) == nil
		pc.enable = ok && (v4 || pc.v6)
	})
	return pc
}

// read returns the datagram, its source and the local address it was sent
// to (invalid when the socket does not say).
func (pc *pktConn) read(b []byte) (int, netip.AddrPort, netip.Addr, error) {
	if !pc.enable {
		n, src, err := pc.conn.ReadFromUDPAddrPort(b)
		return n, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.Addr{}, err
	}
	n, oobn, _, src, err := pc.conn.ReadMsgUDPAddrPort(b, pc.oob)
	if err != nil {
		return n, src, netip.Addr{}, err
	}
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	return n, src, pktDst(pc.oob[:oobn]), nil
}

func pktDst(oob []byte) netip.Addr {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == syscall.IPV6_PKTINFO && len(m.Data) >= 16:
			return netip.AddrFrom16([16]byte(m.Data[:16])).Unmap()
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= 12:
			// struct in_pktinfo: ifindex, spec_dst, addr (the header's destination).
			return netip.AddrFrom4([4]byte(m.Data[8:12]))
		}
	}
	return netip.Addr{}
}

// write sends b to dst from the local address from, when it is known and
// usable as a source; otherwise the kernel picks.
func (pc *pktConn) write(b []byte, dst netip.AddrPort, from netip.Addr) error {
	if !pc.enable || !from.IsValid() || from.IsMulticast() || from.IsUnspecified() {
		_, err := pc.conn.WriteToUDPAddrPort(b, dst)
		return err
	}
	var oob []byte
	switch {
	case from.Is6() && dst.Addr().Is6():
		var data [syscall.SizeofInet6Pktinfo]byte
		a := from.As16()
		copy(data[:16], a[:])
		oob = cmsg(syscall.IPPROTO_IPV6, syscall.IPV6_PKTINFO, data[:])
	case from.Is4() && dst.Addr().Is4():
		var data [syscall.SizeofInet4Pktinfo]byte
		a := from.As4()
		copy(data[4:8], a[:]) // spec_dst: the source to use
		oob = cmsg(syscall.IPPROTO_IP, syscall.IP_PKTINFO, data[:])
		if pc.v6 {
			dst = netip.AddrPortFrom(netip.AddrFrom16(dst.Addr().As16()), dst.Port())
		}
	default:
		_, err := pc.conn.WriteToUDPAddrPort(b, dst)
		return err
	}
	_, _, err := pc.conn.WriteMsgUDPAddrPort(b, oob, dst)
	return err
}

func cmsg(level, typ int, data []byte) []byte {
	b := make([]byte, syscall.CmsgSpace(len(data)))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = int32(level)
	h.Type = int32(typ)
	h.SetLen(syscall.CmsgLen(len(data)))
	copy(b[syscall.CmsgLen(0):], data)
	return b
}
