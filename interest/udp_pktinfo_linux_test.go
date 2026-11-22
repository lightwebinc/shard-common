//go:build linux

package interest

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// A receiver bound to a wildcard address on a host with several addresses
// must answer from the address it was asked at: the sender accepts answers
// only from there. On Linux every address in 127.0.0.0/8 is local, so a
// sender talking to 127.0.0.2 shows it without any privilege; the kernel's
// own choice of source for the answer would be 127.0.0.1.
func TestAnswersFromTheAddressAsked(t *testing.T) {
	for _, network := range []string{"udp4", "udp"} { // udp: dual stack, IPv4 as mapped addresses
		t.Run(network, func(t *testing.T) {
			var laddr *net.UDPAddr
			if network == "udp4" {
				laddr = &net.UDPAddr{IP: net.IPv4zero}
			}
			rconn, err := net.ListenUDP(network, laddr)
			if err != nil {
				t.Skipf("listen %s: %v", network, err)
			}
			defer func() { _ = rconn.Close() }()
			port := rconn.LocalAddr().(*net.UDPAddr).Port
			asked := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(port))

			cconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cconn.Close() }()

			var mu sync.Mutex
			live := 0
			r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, OnChange: func(_ string, _ TopicID, on bool) {
				mu.Lock()
				defer mu.Unlock()
				if on {
					live++
				} else {
					live--
				}
			}})
			c := NewClient(ClientConfig{SenderID: NewSenderID("pktinfo"), Upstreams: []netip.AddrPort{asked}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); _ = ServeReceiver(ctx, rconn, r, ServeOptions{Tick: 50 * time.Millisecond}) }()
			go func() { defer wg.Done(); _ = RunClient(ctx, cconn, c, RunOptions{}) }()
			for _, x := range topics("p", 5) {
				c.Add(x)
			}
			waitFor(t, "the sender to be answered", func() bool {
				up := c.Upstreams()[0]
				return up.Synced && up.Reachable
			})
			mu.Lock()
			if live != 5 {
				t.Errorf("%d live, want 5", live)
			}
			mu.Unlock()
			// What the receiver sends unasked comes from there too: a poke is
			// counted only if it comes from the upstream's address.
			before := c.Upstreams()[0].Stats.Pokes
			r.PokeAll()
			waitFor(t, "the poke", func() bool { return c.Upstreams()[0].Stats.Pokes > before })
			cancel()
			wg.Wait()
		})
	}
}
