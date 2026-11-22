//go:build !linux

package interest

import (
	"net"
	"net/netip"
)

// pktConn is a plain socket here: the kernel picks each reply's source
// address. A receiver bound to a wildcard address on a host with several
// addresses can then answer from one its senders do not expect.
type pktConn struct{ conn *net.UDPConn }

func newPktConn(conn *net.UDPConn) *pktConn { return &pktConn{conn: conn} }

func (pc *pktConn) read(b []byte) (int, netip.AddrPort, netip.Addr, error) {
	n, src, err := pc.conn.ReadFromUDPAddrPort(b)
	return n, netip.AddrPortFrom(src.Addr().Unmap(), src.Port()), netip.Addr{}, err
}

func (pc *pktConn) write(b []byte, dst netip.AddrPort, _ netip.Addr) error {
	_, err := pc.conn.WriteToUDPAddrPort(b, dst)
	return err
}
