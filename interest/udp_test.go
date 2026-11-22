package interest

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func listenLoopback(t *testing.T) (*net.UDPConn, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The two halves over real sockets: announce, withdraw, and the farewell
// that withdraws everything on the way out.
func TestOverUDP(t *testing.T) {
	rconn, raddr := listenLoopback(t)
	cconn, _ := listenLoopback(t)

	var mu sync.Mutex
	live := map[TopicID]bool{}
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, OnChange: func(_ string, x TopicID, on bool) {
		mu.Lock()
		defer mu.Unlock()
		if on {
			live[x] = true
		} else {
			delete(live, x)
		}
	}})
	c := NewClient(ClientConfig{SenderID: NewSenderID("udp-test"), Upstreams: []netip.AddrPort{raddr}})
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(live)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := ServeReceiver(ctx, rconn, r, ServeOptions{Tick: 20 * time.Millisecond}); err != nil {
			t.Errorf("receiver: %v", err)
		}
	}()
	cctx, ccancel := context.WithCancel(ctx)
	clientDone := make(chan error, 1)
	go func() { clientDone <- RunClient(cctx, cconn, c, RunOptions{WithdrawOnExit: true}) }()

	ts := topics("udp", 500)
	for _, x := range ts {
		c.Add(x)
	}
	waitFor(t, "500 topics live", func() bool { return count() == 500 })
	for _, x := range ts[:200] {
		c.Remove(x)
	}
	waitFor(t, "300 topics live", func() bool { return count() == 300 })
	waitFor(t, "the client to settle", func() bool { u := c.Upstreams()[0]; return u.Synced && u.Held == 300 })
	checkReceiver(t, r)
	checkClient(t, c)
	if up := c.Upstreams()[0]; up.Stats.Syncs != 1 || up.Stats.Timeouts != 0 {
		t.Fatalf("upstream %+v", up.Stats)
	}

	// The client leaves and says so: everything goes at once, long before
	// any lifetime runs out.
	ccancel()
	if err := <-clientDone; err != nil {
		t.Fatalf("client: %v", err)
	}
	waitFor(t, "the farewell to withdraw everything", func() bool { return count() == 0 })
	if st := r.Stats(); st.Sweeps != 300 || st.Expiries != 0 {
		t.Fatalf("stats %+v", st)
	}
	cancel()
	wg.Wait()

	// The runners leave the sockets usable.
	if _, err := cconn.WriteToUDPAddrPort([]byte{0}, raddr); err != nil {
		t.Fatalf("client socket after the run: %v", err)
	}
	_ = rconn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 16)
	if n, _, err := rconn.ReadFromUDPAddrPort(buf); err != nil || n != 1 {
		t.Fatalf("receiver socket after the run: %d %v", n, err)
	}
}

// A RESYNC that reaches a receiver's socket is handed to the owner, as a
// relay needs.
func TestServeReceiverPassesResync(t *testing.T) {
	rconn, raddr := listenLoopback(t)
	cconn, caddr := listenLoopback(t)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	got := make(chan netip.AddrPort, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeReceiver(ctx, rconn, r, ServeOptions{Resync: func(src netip.AddrPort) { got <- src }})
	}()
	m := Resync{Header: Header{Version: Version}}
	b, _ := m.Append(nil)
	if _, err := cconn.WriteToUDPAddrPort(b, raddr); err != nil {
		t.Fatal(err)
	}
	select {
	case src := <-got:
		if src != caddr {
			t.Fatalf("resync from %v, sent from %v", src, caddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the resync was not passed on")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestFarewell(t *testing.T) {
	n, c, r := simplePair(t, 30, &testPolicy{}, nil)
	for _, x := range topics("t", 40) {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)
	for _, d := range c.Farewell() {
		n.send(cliAddr, d.Addr, d.Data)
	}
	n.clients[cliAddr].off = true
	n.run(100 * time.Millisecond)
	if len(r.Live("p")) != 0 {
		t.Fatalf("%d topics survived the farewell", len(r.Live("p")))
	}
	checkReceiver(t, r)

	// Used again afterwards, the client starts over and restores its set.
	n.clients[cliAddr].off = false
	n.kick()
	n.run(2 * time.Second)
	if len(r.Live("p")) != 40 {
		t.Fatalf("%d of 40 after the client came back", len(r.Live("p")))
	}
	checkClient(t, c)
}

func TestNewSenderID(t *testing.T) {
	a, b := NewSenderID("one"), NewSenderID("two")
	if a == 0 || b == 0 || a == b || a != NewSenderID("one") {
		t.Fatalf("sender ids %x %x", a, b)
	}
}
