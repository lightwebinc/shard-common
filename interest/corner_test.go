package interest

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// within fails the test if f does not return in time: a deadlock fails
// here instead of hanging the run.
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("did not return: a callback that calls back is stuck")
	}
}

// A callback may call the client or the receiver that is calling it. What
// that changes is reported after the callback returns, still in order.
func TestCallbacksMayCallBack(t *testing.T) {
	t.Run("client", func(t *testing.T) {
		x, d, alt := topic("x"), topic("d"), topic("alt")
		n := newSim(t, 51)
		n.addReceiver(rcvAddr, NewReceiver(ReceiverConfig{Policy: &testPolicy{denied: map[TopicID]bool{d: true}}}))
		var c *Client
		c = NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, OnStatus: func(tp TopicID, st Status) {
			if tp == d && st.Refused() {
				// Refused: ask for another topic instead.
				c.Remove(d)
				c.Add(alt)
			}
		}})
		n.addClient(cliAddr, c)
		within(t, func() {
			c.Add(x)
			c.Add(d)
			n.kick()
			n.run(time.Second)
		})
		if c.Wanted() != 2 || c.Status(x) != StatusOK || c.Status(alt) != StatusOK {
			t.Fatalf("%d wanted, x %v, alt %v", c.Wanted(), c.Status(x), c.Status(alt))
		}
	})
	t.Run("receiver", func(t *testing.T) {
		x := topic("x")
		pol := &testPolicy{denied: map[TopicID]bool{}}
		live := map[string]liveSet{}
		n := newSim(t, 52)
		var r *Receiver
		r = NewReceiver(ReceiverConfig{Policy: pol, OnChange: func(p string, tp TopicID, on bool) {
			trackLive(live)(p, tp, on)
			if on {
				// Taken back as soon as it is granted.
				pol.denied[tp] = true
				r.Reevaluate(p, n.now)
			}
		}})
		n.addReceiver(rcvAddr, r)
		c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
		n.addClient(cliAddr, c)
		within(t, func() {
			c.Add(x)
			n.kick()
			n.run(5 * time.Second)
		})
		if r.IsLive("p", x) || len(live["p"]) != 0 || c.Status(x) != StatusOutsideBound {
			t.Fatalf("live %v, %d live per the callback, x %v", r.IsLive("p", x), len(live["p"]), c.Status(x))
		}
	})
}

// A hold never outlasts what the replay said: when the upstream grants a
// lifetime shorter than the hold, the hold ends in time for a refresh.
func TestSweepHoldEndsBeforeTheLifetime(t *testing.T) {
	n := newSim(t, 53)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, Lifetimes: Lifetimes{Min: 30, Default: 30, Max: 30}})
	n.addReceiver(rcvAddr, r)
	const hold = 100 * time.Second
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SweepHold: hold})
	n.addClient(cliAddr, c)
	x := topic("x")
	c.Add(x)
	n.kick()
	for s := 10; s <= 150; s += 10 {
		n.run(10 * time.Second)
		if !r.IsLive("p", x) {
			t.Fatalf("x expired upstream %d s into a %v hold", s, hold)
		}
	}
	if up := c.Upstreams()[0]; !up.Synced || up.Stats.Syncs != 1 || r.Stats().Expiries != 0 {
		t.Fatalf("upstream %+v, %d expiries", up, r.Stats().Expiries)
	}
}

// A record too large for any datagram cannot be said. When the upstream
// holds the topic under what was said before, it is withdrawn there, not
// left to be refreshed under terms the sender no longer asks for.
func TestRecordTooLargeIsWithdrawn(t *testing.T) {
	n, c, r := simplePair(t, 54, &testPolicy{}, nil)
	x, y := topic("x"), topic("y")
	c.Add(x)
	c.Add(y)
	n.kick()
	n.run(time.Second)
	c.Set(y, AppendTLV(nil, 0x7E, make([]byte, MaxDatagram)))
	n.kick()
	for _, d := range []time.Duration{time.Second, 10 * time.Minute} {
		n.run(d)
		if c.Status(y) != StatusUnsupported || r.IsLive("p", y) || !r.IsLive("p", x) {
			t.Fatalf("y %v, live %v; x live %v", c.Status(y), r.IsLive("p", y), r.IsLive("p", x))
		}
		if up := c.Upstreams()[0]; up.Held != 1 || !up.Synced || up.Stats.Syncs != 1 {
			t.Fatalf("upstream %+v", up)
		}
	}
}

// What follows the records of an ANNOUNCE applies to every record in it. An
// extension there that this hop must understand and does not, or one it
// cannot read, refuses them all, and so does a delivery address that does
// not parse. A withdrawal is always applied.
func TestMessageExtensions(t *testing.T) {
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	now := time.Unix(1_700_000_000, 0)
	tok := r.token(cliAddr, 9)
	x, y := topic("x"), topic("y")
	seq := uint64(0)
	send := func(ext []byte, recs ...Record) []RecordStatus {
		t.Helper()
		seq++
		m := Announce{Header: Header{Version: Version, SenderID: 9, Token: tok, Seq: seq}, Records: recs, Ext: ext}
		pkt, err := m.Append(nil)
		if err != nil {
			t.Fatal(err)
		}
		a, err := DecodeAck(r.Handle(cliAddr, pkt, now))
		if err != nil || a.Result != ResultOK {
			t.Fatalf("answer %+v %v", a, err)
		}
		return a.Statuses
	}
	add := func(tp TopicID) Record { return Record{Topic: tp, Lifetime: LifetimeDefault} }
	good, err := (&Delivery{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: cliAddr.Addr(), Port: 9171}).AppendValue(nil)
	if err != nil {
		t.Fatal(err)
	}
	if st := send(AppendTLV(nil, ExtDelivery, good), add(x)); len(st) != 1 || st[0].Status != StatusAddressNotHonored || !r.IsLive("p", x) {
		t.Fatalf("a default delivery address: %+v", st)
	}
	for _, c := range []struct {
		what string
		ext  []byte
		want Status
	}{
		{"an unknown critical extension", AppendTLV(nil, 0xC1, nil), StatusUnsupported},
		{"an extension area that does not parse", []byte{0x01, 0xFF}, StatusUnsupported},
		{"a delivery address that does not parse", AppendTLV(nil, ExtDelivery, []byte{9}), StatusBadAddress},
	} {
		st := send(c.ext, add(x), add(y))
		if len(st) != 2 || st[0].Status != c.want || st[1].Status != c.want || r.IsLive("p", x) || r.IsLive("p", y) {
			t.Fatalf("%s: %+v", c.what, st)
		}
		// Granted again, for the next case.
		send(nil, add(x))
	}
	if st := send(AppendTLV(nil, 0xC1, nil), Record{Topic: x}); len(st) != 0 || r.IsLive("p", x) {
		t.Fatalf("a withdrawal under an unknown critical extension: %+v", st)
	}
}

// A datagram longer than any sender may send is not read at all.
func TestOversizedDatagramIsNotRead(t *testing.T) {
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	now := time.Unix(1_700_000_000, 0)
	m := Announce{Header: Header{Version: Version, SenderID: 9, Token: r.token(cliAddr, 9), Seq: 1}, Records: []Record{{Topic: topic("x"), Lifetime: LifetimeDefault}}}
	pkt, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt = append(pkt, make([]byte, MaxDatagram)...)
	if _, err := DecodeHeader(pkt); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("decoded the header of %d bytes: %v", len(pkt), err)
	}
	if resp := r.Handle(cliAddr, pkt, now); resp != nil || r.IsLive("p", topic("x")) || r.Stats().Malformed != 1 {
		t.Fatalf("answered with %d bytes, live %v, stats %+v", len(resp), r.IsLive("p", topic("x")), r.Stats())
	}
}

// A delivery address is checked as it is encoded: an IPv4 address in its
// IPv6-mapped form is the IPv4 address.
func TestDeliveryMappedAddresses(t *testing.T) {
	d := Delivery{
		Kind: DeliverMulticastSSM, Encoding: EncodeFrames, Port: 9000,
		Addr: netip.MustParseAddr("::ffff:233.252.0.1"), Source: netip.MustParseAddr("192.0.2.1"),
	}
	v, err := d.AppendValue(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDelivery(v)
	if err != nil || got.Addr != netip.MustParseAddr("233.252.0.1") || got.Source != d.Source {
		t.Fatalf("%+v %v", got, err)
	}
	u := Delivery{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: netip.MustParseAddr("::ffff:0.0.0.0"), Port: 1}
	if _, err := u.AppendValue(nil); err == nil {
		t.Fatal("encoded a unicast delivery to the unspecified address")
	}
}

// The socket loop remembers the local address of a sender that the
// receiver tracks, and of no other.
func TestLocalAddrsFollowTrackedSenders(t *testing.T) {
	n, c, r := simplePair(t, 55, &testPolicy{}, nil)
	c.Add(topic("x"))
	n.kick()
	n.run(time.Second)
	l := newLocalAddrs()
	here := netip.MustParseAddr("2001:db8::1")
	stranger := ap("[2001:db8::99]:5000")
	l.set(cliAddr, here)
	l.set(stranger, here)
	l.keepOnly(r.senderAddrs())
	if l.get(cliAddr) != here || l.get(stranger).IsValid() {
		t.Fatalf("kept %v for the sender and %v for a stranger", l.get(cliAddr), l.get(stranger))
	}
}
