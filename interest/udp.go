package interest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultPort is the UDP port a receiver listens on. It is the same at
// every hop, because the wire is the same at every hop.
const DefaultPort = 8729

// readBuffer is larger than any valid datagram, so an oversized one is
// seen as oversized instead of being silently truncated to a valid length.
const readBuffer = 2048

// ServeOptions adjusts [ServeReceiver].
type ServeOptions struct {
	// Resync is called when a RESYNC arrives on the receiver's socket. A
	// relay's upstream may address the relay there instead of at the
	// socket it sends from; the relay passes it to [Client.Poke].
	Resync func(src netip.AddrPort)
	// Tick is how often expiry runs. It defaults to one second.
	Tick time.Duration
	// OnError is called with errors from the socket other than those that
	// end the loop. It may be nil.
	OnError func(error)
}

// ServeReceiver answers datagrams arriving on conn with r until ctx is
// done. It returns nil when ctx ends and the socket error otherwise. It
// does not close conn.
//
// An answer leaves from the address its datagram was sent to, and anything
// sent to a sender unasked leaves from the address that sender uses. A
// sender accepts answers only from the address it sends to, and a socket
// bound to a wildcard address on a host with several addresses would
// otherwise answer from whichever the kernel prefers for the reply.
func ServeReceiver(ctx context.Context, conn *net.UDPConn, r *Receiver, opts ServeOptions) error {
	if opts.Tick <= 0 {
		opts.Tick = time.Second
	}
	pc := newPktConn(conn)
	local := newLocalAddrs()
	done := make(chan struct{})
	defer func() {
		close(done)
		_ = conn.SetReadDeadline(time.Time{})
	}()
	go func() {
		t := time.NewTicker(opts.Tick)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				// Unblock the read below.
				_ = conn.SetReadDeadline(time.Now())
				return
			case now := <-t.C:
				for _, d := range r.Tick(now) {
					if err := pc.write(d.Data, d.Addr, local.get(d.Addr)); err != nil && opts.OnError != nil {
						opts.OnError(err)
					}
				}
				local.keepOnly(r.senderAddrs())
			}
		}
	}()
	buf := make([]byte, readBuffer)
	for {
		n, src, dst, err := pc.read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		pkt := buf[:n]
		if opts.Resync != nil {
			if h, err := DecodeHeader(pkt); err == nil && h.Type == MsgResync {
				opts.Resync(src)
				continue
			}
		}
		if resp := r.Handle(src, pkt, time.Now()); resp != nil {
			// Only a source the policy knows is answered, so only such a
			// source is remembered, and only while it is tracked.
			local.set(src, dst)
			if err := pc.write(resp, src, dst); err != nil && opts.OnError != nil {
				opts.OnError(err)
			}
		}
	}
}

// localAddrs remembers, per sender, the local address its datagrams
// arrive at.
type localAddrs struct {
	mu sync.Mutex
	m  map[netip.AddrPort]netip.Addr
}

func newLocalAddrs() *localAddrs { return &localAddrs{m: map[netip.AddrPort]netip.Addr{}} }

func (l *localAddrs) set(src netip.AddrPort, dst netip.Addr) {
	if !dst.IsValid() {
		return
	}
	l.mu.Lock()
	l.m[src] = dst
	l.mu.Unlock()
}

func (l *localAddrs) get(src netip.AddrPort) netip.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[src]
}

// keepOnly forgets every sender not in keep.
func (l *localAddrs) keepOnly(keep map[netip.AddrPort]struct{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.m {
		if _, ok := keep[k]; !ok {
			delete(l.m, k)
		}
	}
}

// RunOptions adjusts [RunClient].
type RunOptions struct {
	// WithdrawOnExit sends each upstream one datagram that withdraws
	// everything when ctx ends, so delivery stops at once instead of when
	// the lifetime runs out. Leave it off for a process that is about to
	// be started again, so that what it wants keeps arriving meanwhile.
	WithdrawOnExit bool
	// OnError is called with errors from the socket other than those that
	// end the loop. It may be nil.
	OnError func(error)
}

type inbound struct {
	src  netip.AddrPort
	data []byte
}

// RunClient drives c over conn until ctx is done. conn must be an
// unconnected socket, so that it can reach every upstream. It returns nil
// when ctx ends and the socket error otherwise. It does not close conn.
func RunClient(ctx context.Context, conn *net.UDPConn, c *Client, opts RunOptions) error {
	in := make(chan inbound, 64)
	readErr := make(chan error, 1)
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	defer func() {
		// Stop the reader, wait for it, and leave the socket as it was.
		close(stop)
		_ = conn.SetReadDeadline(time.Now())
		<-readerDone
		_ = conn.SetReadDeadline(time.Time{})
	}()
	go func() {
		defer close(readerDone)
		buf := make([]byte, readBuffer)
		for {
			n, src, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
				}
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				select {
				case readErr <- err:
				case <-stop:
				}
				return
			}
			select {
			case in <- inbound{src, append([]byte(nil), buf[:n]...)}:
			case <-stop:
				return
			}
		}
	}()
	send := func(ds []Datagram) {
		for _, d := range ds {
			if _, err := conn.WriteToUDPAddrPort(d.Data, d.Addr); err != nil && opts.OnError != nil {
				opts.OnError(err)
			}
		}
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		out, next := c.Poll(time.Now())
		send(out)
		wait := time.Until(next)
		if wait < 0 {
			wait = 0
		}
		if wait > time.Hour {
			wait = time.Hour
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			if opts.WithdrawOnExit {
				send(c.Farewell())
			}
			return nil
		case err := <-readErr:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case p := <-in:
			c.Handle(p.src, p.data, time.Now())
		case <-c.Wake():
		case <-timer.C:
		}
	}
}
