package interest

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// deliverPolicy honors what a distributing relay would: a unicast stream of
// delivery records to an address inside the sender's own /64. Any other
// kind is held without its address, and an address outside is refused.
type deliverPolicy struct {
	testPolicy
}

func (p *deliverPolicy) Honor(_ string, src netip.AddrPort, _ TopicID, d Delivery) Status {
	if d.Kind != DeliverUnicast || d.Encoding != EncodeRecords {
		return StatusAddressNotHonored
	}
	if !netip.PrefixFrom(src.Addr(), 64).Masked().Contains(d.Addr) {
		return StatusBadAddress
	}
	return StatusOK
}

type deliveryEvent struct {
	topic TopicID
	addr  netip.AddrPort
	live  bool
}

func unicast(addr string) Delivery {
	ap := netip.MustParseAddrPort(addr)
	return Delivery{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: ap.Addr(), Port: ap.Port()}
}

func deliveryExt(t testing.TB, d Delivery) []byte {
	t.Helper()
	v, err := d.AppendValue(nil)
	if err != nil {
		t.Fatal(err)
	}
	return AppendTLV(nil, ExtDelivery, v)
}

// deliverPair is a simulated sender and a receiver whose policy distributes,
// with every OnDelivery call recorded. The callback reads the receiver back,
// as a distributor's would.
func deliverPair(t *testing.T, seed uint64) (*simNet, *Client, *Receiver, *[]deliveryEvent) {
	n := newSim(t, seed)
	var events []deliveryEvent
	var r *Receiver
	r = NewReceiver(ReceiverConfig{Policy: &deliverPolicy{}, OnDelivery: func(topic TopicID, d Delivery, live bool) {
		_ = r.Deliveries(topic) // a callback may read the receiver
		events = append(events, deliveryEvent{topic, netip.AddrPortFrom(d.Addr, d.Port), live})
	}})
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addReceiver(rcvAddr, r)
	n.addClient(cliAddr, c)
	return n, c, r, &events
}

func sameEvents(t *testing.T, what string, got []deliveryEvent, want ...deliveryEvent) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d delivery events %v, want %v", what, len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: event %d is %v, want %v", what, i, got[i], want[i])
		}
	}
}

// A distributing policy keeps the address it honors and reports it; holds a
// topic without an address of a kind it does not distribute; refuses an
// address it may not deliver to.
func TestDeliveryHonored(t *testing.T) {
	n, c, r, events := deliverPair(t, 61)
	x, y, z := topic("x"), topic("y"), topic("z")
	dx, dx2 := unicast("[2001:db8::10]:9171"), unicast("[2001:db8::11]:9171")
	group := Delivery{Kind: DeliverMulticast, Encoding: EncodeFrames, Addr: netip.MustParseAddr("ff0e::1"), Port: 9000}
	c.Set(x, deliveryExt(t, dx))
	c.Set(y, deliveryExt(t, group))
	c.Set(z, deliveryExt(t, unicast("[2001:db8:ffff::1]:9171")))
	n.kick()
	n.run(time.Second)
	if c.Status(x) != StatusOK || c.Status(y) != StatusAddressNotHonored || c.Status(z) != StatusBadAddress {
		t.Fatalf("x %v, y %v, z %v", c.Status(x), c.Status(y), c.Status(z))
	}
	if !r.IsLive("p", x) || !r.IsLive("p", y) || r.IsLive("p", z) {
		t.Fatal("held set")
	}
	if got := r.Deliveries(x); len(got) != 1 || got[0] != dx {
		t.Fatalf("x delivers to %v", got)
	}
	if got := r.Deliveries(y); len(got) != 0 {
		t.Fatalf("y delivers to %v", got)
	}
	sameEvents(t, "first", *events, deliveryEvent{x, netip.MustParseAddrPort("[2001:db8::10]:9171"), true})

	// A new address: the new one goes live before the old one goes.
	*events = nil
	c.Set(x, deliveryExt(t, dx2))
	n.kick()
	n.run(time.Second)
	sameEvents(t, "address changed", *events,
		deliveryEvent{x, netip.MustParseAddrPort("[2001:db8::11]:9171"), true},
		deliveryEvent{x, netip.MustParseAddrPort("[2001:db8::10]:9171"), false})
	if got := r.Deliveries(x); len(got) != 1 || got[0] != dx2 {
		t.Fatalf("x delivers to %v after the change", got)
	}

	// Withdrawn: the address goes with it.
	*events = nil
	c.Remove(x)
	n.kick()
	n.run(time.Second)
	sameEvents(t, "withdrawn", *events, deliveryEvent{x, netip.MustParseAddrPort("[2001:db8::11]:9171"), false})
	if st := r.Stats(); st.Deliveries != 0 {
		t.Fatalf("%d deliveries counted after the withdrawal", st.Deliveries)
	}
}

// Two senders give the same address for a topic: it goes live with the
// first and stops with the last.
func TestDeliveryCountedAcrossSenders(t *testing.T) {
	n, c, r, events := deliverPair(t, 62)
	c2 := NewClient(ClientConfig{SenderID: 78, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(ap("[2001:db8::10]:40001"), c2)
	x, d := topic("x"), unicast("[2001:db8::10]:9171")
	c.Set(x, deliveryExt(t, d))
	c2.Set(x, deliveryExt(t, d))
	n.kick()
	n.run(time.Second)
	want := deliveryEvent{x, netip.MustParseAddrPort("[2001:db8::10]:9171"), true}
	sameEvents(t, "both hold it", *events, want)
	c.Remove(x)
	n.kick()
	n.run(time.Second)
	sameEvents(t, "one withdrew", *events, want)
	if len(r.Deliveries(x)) != 1 {
		t.Fatal("the address went with the first sender")
	}
	c2.Remove(x)
	n.kick()
	n.run(time.Second)
	sameEvents(t, "both withdrew", *events, want, deliveryEvent{x, netip.MustParseAddrPort("[2001:db8::10]:9171"), false})
}

// A sender that goes silent loses its address when its topic expires.
func TestDeliveryExpires(t *testing.T) {
	n, c, r, events := deliverPair(t, 63)
	x := topic("x")
	c.Set(x, deliveryExt(t, unicast("[2001:db8::10]:9171")))
	n.kick()
	n.run(time.Second)
	n.clients[cliAddr].off = true
	n.run(time.Duration(DefaultLifetimes.Default+10) * time.Second)
	if r.IsLive("p", x) || len(r.Deliveries(x)) != 0 {
		t.Fatal("the topic or its address outlived the lifetime")
	}
	if got := *events; len(got) != 2 || got[1].live {
		t.Fatalf("events %v", got)
	}
}

// The address after the records is every record's default; a record's own
// address overrides it.
func TestDeliveryDefaultAndOverride(t *testing.T) {
	r := NewReceiver(ReceiverConfig{Policy: &deliverPolicy{}})
	now := time.Unix(1_700_000_000, 0)
	x, y := topic("x"), topic("y")
	def, own := unicast("[2001:db8::10]:9171"), unicast("[2001:db8::12]:9171")
	m := Announce{
		Header: Header{Version: Version, SenderID: 9, Token: r.token(cliAddr, 9), Seq: 1},
		Records: []Record{
			{Topic: x, Lifetime: LifetimeDefault},
			{Topic: y, Lifetime: LifetimeDefault, Ext: deliveryExt(t, own)},
		},
		Ext: deliveryExt(t, def),
	}
	pkt, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := DecodeAck(r.Handle(cliAddr, pkt, now))
	if err != nil || a.Result != ResultOK || len(a.Statuses) != 0 {
		t.Fatalf("answer %+v %v", a, err)
	}
	if got := r.Deliveries(x); len(got) != 1 || got[0] != def {
		t.Fatalf("x delivers to %v, want the default", got)
	}
	if got := r.Deliveries(y); len(got) != 1 || got[0] != own {
		t.Fatalf("y delivers to %v, want its own", got)
	}
}

// Without a distributing policy nothing changes: the address is not
// honored, and OnDelivery is never called.
func TestDeliveryWithoutDeliverer(t *testing.T) {
	n := newSim(t, 64)
	calls := 0
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, OnDelivery: func(TopicID, Delivery, bool) { calls++ }})
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addReceiver(rcvAddr, r)
	n.addClient(cliAddr, c)
	x := topic("x")
	c.Set(x, deliveryExt(t, unicast("[2001:db8::10]:9171")))
	n.kick()
	n.run(time.Second)
	if c.Status(x) != StatusAddressNotHonored || calls != 0 || len(r.Deliveries(x)) != 0 {
		t.Fatalf("x %v, %d calls, deliveries %v", c.Status(x), calls, r.Deliveries(x))
	}
}

// switchPolicy distributes until told otherwise, so a test can change its
// answer and re-evaluate.
type switchPolicy struct {
	testPolicy
	answer Status
}

func (p *switchPolicy) Honor(string, netip.AddrPort, TopicID, Delivery) Status { return p.answer }

// A changed answer applies on Reevaluate: an address the policy now refuses
// takes its topic with it, and one it no longer honors goes alone.
func TestDeliveryReevaluated(t *testing.T) {
	for _, c := range []struct {
		answer   Status
		wantLive bool
	}{{StatusBadAddress, false}, {StatusAddressNotHonored, true}} {
		n := newSim(t, 65)
		pol := &switchPolicy{answer: StatusOK}
		var gone []bool
		r := NewReceiver(ReceiverConfig{Policy: pol, OnDelivery: func(_ TopicID, _ Delivery, live bool) { gone = append(gone, !live) }})
		cl := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
		n.addReceiver(rcvAddr, r)
		n.addClient(cliAddr, cl)
		x := topic("x")
		cl.Set(x, deliveryExt(t, unicast("[2001:db8::10]:9171")))
		n.kick()
		n.run(time.Second)
		if len(r.Deliveries(x)) != 1 {
			t.Fatal("the address was not kept")
		}
		pol.answer = c.answer
		r.Reevaluate("p", n.now)
		if len(r.Deliveries(x)) != 0 || r.IsLive("p", x) != c.wantLive {
			t.Fatalf("%v: deliveries %v, live %v", c.answer, r.Deliveries(x), r.IsLive("p", x))
		}
		if len(gone) != 2 || !gone[1] {
			t.Fatalf("%v: delivery events (true = gone) %v", c.answer, gone)
		}
		checkReceiver(t, r)
	}
}

// The calls nest: a topic goes live before its address does, and its
// address goes before it does.
func TestDeliveryEventOrder(t *testing.T) {
	n := newSim(t, 66)
	var order []string
	r := NewReceiver(ReceiverConfig{
		Policy: &deliverPolicy{},
		OnChange: func(_ string, _ TopicID, live bool) {
			order = append(order, map[bool]string{true: "topic+", false: "topic-"}[live])
		},
		OnDelivery: func(_ TopicID, _ Delivery, live bool) {
			order = append(order, map[bool]string{true: "addr+", false: "addr-"}[live])
		},
	})
	cl := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addReceiver(rcvAddr, r)
	n.addClient(cliAddr, cl)
	x := topic("x")
	cl.Set(x, deliveryExt(t, unicast("[2001:db8::10]:9171")))
	n.kick()
	n.run(time.Second)
	cl.Remove(x)
	n.kick()
	n.run(time.Second)
	if got := strings.Join(order, " "); got != "topic+ addr+ addr- topic-" {
		t.Fatalf("order %q", got)
	}
}

// A note on the topic itself wins over the note on its address: a topic no
// path serves is not served at any address. The record's own status says
// so; a client would also learn it from the notice the same answer carries.
func TestDeliveryNoteOnTheTopicWins(t *testing.T) {
	x := topic("x")
	r := NewReceiver(ReceiverConfig{Policy: notingPolicy{&testPolicy{notes: map[TopicID]Status{x: StatusUnserved}}}})
	m := Announce{
		Header:  Header{Version: Version, SenderID: 9, Token: r.token(cliAddr, 9), Seq: 1},
		Records: []Record{{Topic: x, Lifetime: LifetimeDefault, Ext: deliveryExt(t, unicast("[2001:db8::10]:9171"))}},
	}
	pkt, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := DecodeAck(r.Handle(cliAddr, pkt, time.Unix(1_700_000_000, 0)))
	if err != nil || len(a.Statuses) != 1 || a.Statuses[0].Status != StatusUnserved {
		t.Fatalf("answer %+v %v", a, err)
	}
}
