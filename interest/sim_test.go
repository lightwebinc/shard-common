package interest

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/shard"
)

// A simulated network: clients and receivers at addresses, a clock that
// moves only when the test moves it, and links that can lose, duplicate and
// delay datagrams. Everything is deterministic for a given seed.

type simPkt struct {
	at       time.Time
	from, to netip.AddrPort
	data     []byte
	order    int
}

type simNet struct {
	t         testing.TB
	now       time.Time
	rng       *rand.Rand
	loss      float64
	dup       float64
	maxDelay  time.Duration
	minDelay  time.Duration
	pkts      []simPkt
	order     int
	clients   map[netip.AddrPort]*simClient
	receivers map[netip.AddrPort]*Receiver
	lastTick  time.Time
	sent      int
	delivered int
	down      map[netip.AddrPort]bool
	tap       func(from, to netip.AddrPort, data []byte)
}

type simClient struct {
	c    *Client
	next time.Time
	off  bool
}

func newSim(t testing.TB, seed uint64) *simNet {
	start := time.Unix(1_700_000_000, 0)
	return &simNet{
		t: t, now: start, lastTick: start,
		rng:       rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15)),
		minDelay:  time.Millisecond,
		maxDelay:  2 * time.Millisecond,
		clients:   map[netip.AddrPort]*simClient{},
		receivers: map[netip.AddrPort]*Receiver{},
		down:      map[netip.AddrPort]bool{},
	}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func (n *simNet) addClient(addr netip.AddrPort, c *Client) *simClient {
	sc := &simClient{c: c, next: n.now}
	n.clients[addr] = sc
	return sc
}

func (n *simNet) addReceiver(addr netip.AddrPort, r *Receiver) { n.receivers[addr] = r }

func (n *simNet) send(from, to netip.AddrPort, data []byte) {
	n.sent++
	if n.tap != nil {
		n.tap(from, to, data)
	}
	if n.down[to] || n.down[from] {
		return
	}
	copies := 1
	if n.rng.Float64() < n.loss {
		copies = 0
	} else if n.rng.Float64() < n.dup {
		copies = 2
	}
	for i := 0; i < copies; i++ {
		d := n.minDelay
		if n.maxDelay > n.minDelay {
			d += time.Duration(n.rng.Int64N(int64(n.maxDelay - n.minDelay)))
		}
		n.order++
		n.pkts = append(n.pkts, simPkt{at: n.now.Add(d), from: from, to: to, data: append([]byte(nil), data...), order: n.order})
	}
}

func (n *simNet) pollClient(addr netip.AddrPort, sc *simClient) {
	out, next := sc.c.Poll(n.now)
	sc.next = next
	for _, d := range out {
		n.send(addr, d.Addr, d.Data)
	}
}

// step advances to the next event at or before limit and processes it. It
// reports false when nothing is due before limit.
func (n *simNet) step(limit time.Time) bool {
	// Earliest of: a packet, a client's next poll, the next tick.
	next := limit
	kind := 0
	var pi int
	for i := range n.pkts {
		p := &n.pkts[i]
		if p.at.Before(next) || (kind == 1 && p.at.Equal(next) && p.order < n.pkts[pi].order) {
			next, kind, pi = p.at, 1, i
		}
	}
	var cAddr netip.AddrPort
	for a, sc := range n.clients {
		if sc.off {
			continue
		}
		if sc.next.Before(next) || (kind == 2 && sc.next.Equal(next) && a.Compare(cAddr) < 0) {
			next, kind, cAddr = sc.next, 2, a
		}
	}
	if tick := n.lastTick.Add(time.Second); tick.Before(next) {
		next, kind = tick, 3
	}
	if kind == 0 {
		n.now = limit
		return false
	}
	if next.After(n.now) {
		n.now = next
	}
	switch kind {
	case 1:
		p := n.pkts[pi]
		n.pkts = append(n.pkts[:pi], n.pkts[pi+1:]...)
		n.delivered++
		if r := n.receivers[p.to]; r != nil {
			if resp := r.Handle(p.from, p.data, n.now); resp != nil {
				n.send(p.to, p.from, resp)
			}
		} else if sc := n.clients[p.to]; sc != nil && !sc.off {
			sc.c.Handle(p.from, p.data, n.now)
			n.pollClient(p.to, sc)
		}
	case 2:
		n.pollClient(cAddr, n.clients[cAddr])
	case 3:
		n.lastTick = next
		// Tick receivers in a fixed order so runs repeat exactly.
		addrs := make([]netip.AddrPort, 0, len(n.receivers))
		for a := range n.receivers {
			addrs = append(addrs, a)
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
		for _, a := range addrs {
			for _, d := range n.receivers[a].Tick(n.now) {
				n.send(a, d.Addr, d.Data)
			}
		}
	}
	return true
}

// run advances the clock by d, processing everything due, and then checks
// that every party's bookkeeping still agrees with a recount.
func (n *simNet) run(d time.Duration) {
	limit := n.now.Add(d)
	for n.step(limit) {
	}
	for _, r := range n.receivers {
		checkReceiver(n.t, r)
	}
	for _, sc := range n.clients {
		checkClient(n.t, sc.c)
	}
}

// kick polls every client now, as its owner would after changing its set.
func (n *simNet) kick() {
	for a, sc := range n.clients {
		if !sc.off {
			n.pollClient(a, sc)
		}
	}
}

// A policy for tests: one principal per source address unless mapped,
// with a settable scope, list and quota.
type testPolicy struct {
	principal func(netip.AddrPort) (string, bool)
	scope     *Scope
	listed    map[TopicID]bool
	denied    map[TopicID]bool
	quota     int // applies to topics that are not listed
	listOnly  bool
	notes     map[TopicID]Status
}

func (p *testPolicy) Identify(src netip.AddrPort) (string, bool) {
	if p.principal != nil {
		return p.principal(src)
	}
	return "p", true
}
func (p *testPolicy) Scope(string) *Scope { return p.scope }
func (p *testPolicy) Bound(_ string, t TopicID) Bound {
	switch {
	case p.denied[t]:
		return BoundDenied
	case p.listed == nil && !p.listOnly:
		return BoundFree
	case p.listed[t]:
		return BoundFree
	}
	return BoundQuota
}
func (p *testPolicy) Quota(string) int { return p.quota }

type notingPolicy struct{ *testPolicy }

func (p notingPolicy) Note(_ string, t TopicID) Status { return p.notes[t] }
func (p notingPolicy) Notes(_ string, each func(TopicID, Status) bool) {
	for t, s := range p.notes {
		if !each(t, s) {
			return
		}
	}
}

type liveSet map[TopicID]bool

func trackLive(dst map[string]liveSet) func(string, TopicID, bool) {
	return func(p string, t TopicID, live bool) {
		if dst[p] == nil {
			dst[p] = liveSet{}
		}
		if live {
			if dst[p][t] {
				panic("topic reported live twice")
			}
			dst[p][t] = true
		} else {
			if !dst[p][t] {
				panic("topic reported gone while not live")
			}
			delete(dst[p], t)
		}
	}
}

func topics(prefix string, n int) []TopicID {
	out := make([]TopicID, n)
	for i := range out {
		out[i] = topic(fmt.Sprintf("%s-%d", prefix, i))
	}
	return out
}

func sameSet(t testing.TB, what string, got []TopicID, want map[TopicID]bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d topics, want %d", what, len(got), len(want))
	}
	for _, x := range got {
		if !want[x] {
			t.Fatalf("%s: holds a topic that is not wanted", what)
		}
	}
}

var (
	cliAddr = ap("[2001:db8::10]:40000")
	rcvAddr = ap("[2001:db8::1]:8729")
)

func simplePair(t testing.TB, seed uint64, pol Policy, onChange func(string, TopicID, bool)) (*simNet, *Client, *Receiver) {
	n := newSim(t, seed)
	r := NewReceiver(ReceiverConfig{Policy: pol, OnChange: onChange})
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addReceiver(rcvAddr, r)
	n.addClient(cliAddr, c)
	return n, c, r
}

func TestAddAndWithdraw(t *testing.T) {
	live := map[string]liveSet{}
	n, c, r := simplePair(t, 1, &testPolicy{}, trackLive(live))
	ts := topics("t", 100)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)

	want := map[TopicID]bool{}
	for _, x := range ts {
		want[x] = true
		if st := c.Status(x); st != StatusOK {
			t.Fatalf("status %v", st)
		}
	}
	sameSet(t, "receiver", r.Live("p"), want)
	if len(live["p"]) != 100 {
		t.Fatalf("%d live per the callback", len(live["p"]))
	}
	up := c.Upstreams()[0]
	if !up.Synced || !up.Reachable || up.Held != 100 || up.Stats.Syncs != 1 {
		t.Fatalf("upstream %+v", up)
	}

	for _, x := range ts[:40] {
		c.Remove(x)
		delete(want, x)
	}
	n.kick()
	n.run(time.Second)
	sameSet(t, "receiver after withdraw", r.Live("p"), want)
	if up := c.Upstreams()[0]; up.Held != 60 || up.Tracked != 60 || up.Stats.Syncs != 1 {
		t.Fatalf("upstream after withdraw %+v", up)
	}
	if st := r.Stats(); st.Withdrawals != 40 || st.Topics != 60 || st.LiveTopics != 60 || st.Expiries != 0 {
		t.Fatalf("receiver stats %+v", st)
	}
}

// Nothing changes for a long time: the periodic digest alone keeps every
// topic alive, and one small datagram does it.
func TestDigestRefreshKeepsStateAlive(t *testing.T) {
	n, c, r := simplePair(t, 2, &testPolicy{}, nil)
	for _, x := range topics("t", 500) {
		c.Add(x)
	}
	n.kick()
	n.run(2 * time.Second)
	before := n.sent
	n.run(4 * time.Duration(DefaultLifetimes.Default) * time.Second)
	st := r.Stats()
	if st.Expiries != 0 || st.Topics != 500 {
		t.Fatalf("state decayed: %+v", st)
	}
	// Refresh is at a third of the lifetime: about twelve digests and
	// their answers in four lifetimes, whatever the size of the set.
	if d := n.sent - before; d < 20 || d > 30 {
		t.Fatalf("%d datagrams to keep 500 topics alive for four lifetimes", d)
	}
	if up := c.Upstreams()[0]; up.Stats.Syncs != 1 || up.Stats.Mismatches != 0 {
		t.Fatalf("upstream %+v", up)
	}
}

// The sender dies. Its topics lapse at their lifetime, and not before.
func TestExpiryWhenSenderGoesSilent(t *testing.T) {
	live := map[string]liveSet{}
	n, c, r := simplePair(t, 3, &testPolicy{}, trackLive(live))
	for _, x := range topics("t", 50) {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)
	n.clients[cliAddr].off = true

	n.run(time.Duration(DefaultLifetimes.Default-5) * time.Second)
	if len(r.Live("p")) != 50 {
		t.Fatalf("lapsed early: %d live", len(r.Live("p")))
	}
	n.run(10 * time.Second)
	if len(r.Live("p")) != 0 || len(live["p"]) != 0 {
		t.Fatalf("did not lapse: %d live", len(r.Live("p")))
	}
	if st := r.Stats(); st.Expiries != 50 {
		t.Fatalf("expiries %d", st.Expiries)
	}
	// The sender is remembered while idle, then forgotten.
	if len(r.Senders()) != 1 {
		t.Fatal("an idle sender must be remembered for a while")
	}
	n.run(time.Duration(DefaultLifetimes.Max+5) * time.Second)
	if len(r.Senders()) != 0 {
		t.Fatal("an idle sender must be forgotten in the end")
	}
}

// The upstream restarts and holds nothing. The sender sees a new token at
// its next refresh and replays.
func TestReceiverRestart(t *testing.T) {
	n, c, r := simplePair(t, 4, &testPolicy{}, nil)
	ts := topics("t", 300)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)
	if len(r.Live("p")) != 300 {
		t.Fatal("setup")
	}

	r2 := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	n.addReceiver(rcvAddr, r2)
	n.run(time.Duration(DefaultLifetimes.Default/3+2) * time.Second)
	if len(r2.Live("p")) != 300 {
		t.Fatalf("new upstream holds %d of 300", len(r2.Live("p")))
	}
	if up := c.Upstreams()[0]; up.Stats.Syncs != 2 || up.Stats.Tokens != 2 || !up.Synced {
		t.Fatalf("upstream %+v", up)
	}

	// A restarted upstream that knows its senders asks at once instead of
	// waiting for the refresh.
	r3 := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	n.addReceiver(rcvAddr, r3)
	m := Resync{Header: Header{Version: Version}}
	poke, _ := m.Append(nil)
	n.send(rcvAddr, cliAddr, poke)
	n.run(3 * time.Second)
	if len(r3.Live("p")) != 300 {
		t.Fatalf("poked upstream holds %d of 300", len(r3.Live("p")))
	}
}

// The sender restarts wanting less than before. Its replay ends with a
// sweep that removes what it no longer wants, and nothing it still wants is
// ever dropped on the way.
func TestSenderRestartSweeps(t *testing.T) {
	live := map[string]liveSet{}
	var removed int
	n := newSim(t, 5)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, OnChange: func(p string, x TopicID, on bool) {
		if !on {
			removed++
		}
		trackLive(live)(p, x, on)
	}})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(cliAddr, c)
	ts := topics("t", 200)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)

	n.run(time.Second)
	c2 := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(cliAddr, c2)
	want := map[TopicID]bool{}
	for _, x := range ts[:120] {
		c2.Add(x)
		want[x] = true
	}
	n.kick()
	n.run(time.Second)
	sameSet(t, "receiver after sender restart", r.Live("p"), want)
	if removed != 80 {
		t.Fatalf("%d topics removed, want exactly the 80 no longer wanted", removed)
	}
	if st := r.Stats(); st.Sweeps != 80 || st.Expiries != 0 {
		t.Fatalf("stats %+v", st)
	}
}

// A sender whose clock went backwards starts below the sequence number the
// upstream last applied. It is told, jumps forward, and converges.
func TestSenderRestartWithLowerSequence(t *testing.T) {
	n := newSim(t, 6)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SeqStart: 1_000_000})
	n.addClient(cliAddr, c)
	for _, x := range topics("a", 10) {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)

	c2 := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SeqStart: 5})
	n.addClient(cliAddr, c2)
	want := map[TopicID]bool{}
	for _, x := range topics("b", 10) {
		c2.Add(x)
		want[x] = true
	}
	n.kick()
	n.run(3 * time.Second)
	sameSet(t, "receiver", r.Live("p"), want)
	if up := c2.Upstreams()[0]; up.Stats.Stale == 0 || !up.Synced {
		t.Fatalf("upstream %+v", up)
	}
}

// Loss, duplication and reordering while the wanted set keeps changing. At
// the end both sides must hold the same set, and at no point may the
// receiver hold a topic the sender never wanted.
func TestConvergesUnderLossAndChurn(t *testing.T) {
	// INTEREST_SEEDS widens the search when hunting a rare interleaving.
	seeds := uint64(12)
	if v, err := strconv.ParseUint(os.Getenv("INTEREST_SEEDS"), 10, 32); err == nil && v > 0 {
		seeds = v
	}
	for seed := uint64(1); seed <= seeds; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) {
			live := map[string]liveSet{}
			n, c, r := simplePair(t, seed, &testPolicy{}, trackLive(live))
			n.loss, n.dup = 0.25, 0.10
			n.minDelay, n.maxDelay = time.Millisecond, 400*time.Millisecond
			pool := topics("t", 400)
			ever := map[TopicID]bool{}
			want := map[TopicID]bool{}
			rng := rand.New(rand.NewPCG(seed, 99))
			for round := 0; round < 60; round++ {
				for i := 0; i < 25; i++ {
					x := pool[rng.IntN(len(pool))]
					if rng.IntN(3) == 0 {
						c.Remove(x)
						delete(want, x)
					} else {
						c.Add(x)
						want[x] = true
						ever[x] = true
					}
				}
				n.kick()
				n.run(time.Duration(rng.IntN(1500)) * time.Millisecond)
				for _, x := range r.Live("p") {
					if !ever[x] {
						t.Fatal("the receiver holds a topic that was never wanted")
					}
				}
			}
			// Quiesce: no more changes, the links stay lossy.
			n.run(3 * time.Minute)
			sameSet(t, "receiver", r.Live("p"), want)
			sameSet(t, "callback view", keys(live["p"]), want)
			// A refresh may be in flight at any instant, so only the
			// settled facts are checked.
			up := c.Upstreams()[0]
			if !up.Synced || up.Held != len(want) || up.Tracked != len(want) {
				t.Fatalf("upstream %+v", up)
			}
			for x := range want {
				if st := c.Status(x); st != StatusOK {
					t.Fatalf("status %v for a wanted topic", st)
				}
			}
			if st := r.Stats(); st.Expiries != 0 {
				t.Fatalf("%d topics lapsed although the sender never stopped", st.Expiries)
			}
			t.Logf("sent %d datagrams; client %+v", n.sent, up.Stats)
		})
	}
}

func keys(m liveSet) []TopicID {
	out := make([]TopicID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// With no loss and no reordering, nothing is ever said twice: one replay at
// first contact, and after it only the changes themselves.
func TestNoReplayWithoutLoss(t *testing.T) {
	n, c, r, want := churn(t, 7, 20*time.Millisecond, 20*time.Millisecond)
	sameSet(t, "receiver", r.Live("p"), want)
	up := c.Upstreams()[0]
	if up.Stats.Syncs != 1 || up.Stats.Mismatches != 0 || up.Stats.Timeouts != 0 || up.Stats.Stale != 0 {
		t.Fatalf("upstream %+v", up.Stats)
	}
	if st := r.Stats(); st.Mismatches != 0 || st.Stale != 0 || st.Expiries != 0 {
		t.Fatalf("receiver %+v", st)
	}
	_ = n
}

// The network reorders datagrams. A datagram overtaken by a later one is
// not applied, and what it carried is said again, but that is all it
// costs: no replay, no wait for a timeout, and the same set at the end.
func TestReorderingCostsAResendOnly(t *testing.T) {
	_, c, r, want := churn(t, 8, time.Millisecond, 50*time.Millisecond)
	sameSet(t, "receiver", r.Live("p"), want)
	up := c.Upstreams()[0]
	if up.Stats.Stale == 0 {
		t.Fatal("the test needs reordering to happen")
	}
	if up.Stats.Syncs != 1 || up.Stats.Mismatches != 0 || up.Stats.Timeouts != 0 {
		t.Fatalf("upstream %+v", up.Stats)
	}
	if st := r.Stats(); st.Mismatches != 0 || st.Expiries != 0 {
		t.Fatalf("receiver %+v", st)
	}
}

// churn changes the wanted set at random over a long run on lossless
// links with the given delay range, then lets everything settle.
func churn(t *testing.T, seed uint64, minDelay, maxDelay time.Duration) (*simNet, *Client, *Receiver, map[TopicID]bool) {
	n, c, r := simplePair(t, seed, &testPolicy{}, nil)
	n.minDelay, n.maxDelay = minDelay, maxDelay
	pool := topics("t", 2000)
	want := map[TopicID]bool{}
	rng := rand.New(rand.NewPCG(seed, seed))
	for round := 0; round < 200; round++ {
		for i := 0; i < 100; i++ {
			x := pool[rng.IntN(len(pool))]
			if rng.IntN(2) == 0 {
				c.Remove(x)
				delete(want, x)
			} else {
				c.Add(x)
				want[x] = true
			}
		}
		n.kick()
		n.run(time.Duration(rng.IntN(3000)) * time.Millisecond)
	}
	n.run(10 * time.Second)
	return n, c, r, want
}

// A captured datagram replayed later changes nothing.
func TestReplayedDatagramIsStale(t *testing.T) {
	n, c, r := simplePair(t, 8, &testPolicy{}, nil)
	var captured []byte
	n.tap = func(from, to netip.AddrPort, data []byte) {
		if h, err := DecodeHeader(data); err == nil && h.Type == MsgAnnounce && captured == nil {
			captured = append([]byte(nil), data...)
		}
	}
	x := topic("x")
	c.Add(x)
	n.kick()
	n.run(time.Second)
	c.Remove(x)
	n.kick()
	n.run(time.Second)
	if r.IsLive("p", x) || captured == nil {
		t.Fatal("setup")
	}
	resp := r.Handle(cliAddr, captured, n.now)
	a, err := DecodeAck(resp)
	if err != nil || a.Result != ResultStale {
		t.Fatalf("replay answered %+v %v", a, err)
	}
	if r.IsLive("p", x) {
		t.Fatal("a replayed datagram brought a withdrawn topic back")
	}
}

func TestTokenProvesTheSourceAddress(t *testing.T) {
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	now := time.Unix(1_700_000_000, 0)
	m := Announce{Header: Header{Version: Version, SenderID: 9, Seq: 1}, Records: []Record{{Topic: topic("x"), Lifetime: 60}}}
	pkt, _ := m.Append(nil)

	resp := r.Handle(cliAddr, pkt, now)
	a, err := DecodeAck(resp)
	if err != nil || a.Result != ResultToken || a.Token == 0 {
		t.Fatalf("first contact answered %+v %v", a, err)
	}
	if len(resp) > len(pkt) || len(resp) != HeaderSize {
		t.Fatalf("a %d-byte answer to a %d-byte request from an unproven source", len(resp), len(pkt))
	}
	if r.IsLive("p", topic("x")) {
		t.Fatal("applied without a token")
	}

	// The token is bound to the address: the same sender identity at
	// another address cannot use it.
	m.Token = a.Token
	pkt, _ = m.Append(nil)
	other := ap("[2001:db8::66]:40000")
	if b, _ := DecodeAck(r.Handle(other, pkt, now)); b.Result != ResultToken || b.Token == a.Token {
		t.Fatalf("token accepted from another address: %+v", b)
	}
	if b, _ := DecodeAck(r.Handle(cliAddr, pkt, now)); b.Result != ResultOK {
		t.Fatalf("token refused at its own address: %+v", b)
	}
	if !r.IsLive("p", topic("x")) {
		t.Fatal("not applied with the right token")
	}
	// A new receiver issues different tokens.
	r2 := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	if b, _ := DecodeAck(r2.Handle(cliAddr, pkt, now)); b.Result != ResultToken || b.Token == a.Token {
		t.Fatalf("a restarted receiver accepted an old token: %+v", b)
	}
	st := r.Stats()
	if st.TokensIssued != 2 || st.Announces != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestReceiverIgnoresWhatItShould(t *testing.T) {
	pol := &testPolicy{principal: func(a netip.AddrPort) (string, bool) {
		return "p", a.Addr() == cliAddr.Addr()
	}}
	r := NewReceiver(ReceiverConfig{Policy: pol})
	now := time.Unix(1_700_000_000, 0)
	m := Announce{Header: Header{Version: Version, SenderID: 9, Seq: 1}}
	pkt, _ := m.Append(nil)

	if resp := r.Handle(ap("[2001:db8::99]:1"), pkt, now); resp != nil {
		t.Error("answered a source the policy does not know")
	}
	if resp := r.Handle(cliAddr, pkt[:20], now); resp != nil {
		t.Error("answered a truncated datagram")
	}
	ack, _ := (&Ack{Header: Header{Version: Version, SenderID: 9}}).Append(nil)
	if resp := r.Handle(cliAddr, ack, now); resp != nil {
		t.Error("answered an ACK")
	}
	zero := Announce{Header: Header{Version: Version, SenderID: 0, Seq: 1}}
	zpkt, _ := zero.Append(nil)
	if resp := r.Handle(cliAddr, zpkt, now); resp != nil {
		t.Error("answered a sender without an identity")
	}

	// Another version is answered with the version this receiver speaks,
	// in a header and nothing else.
	v1 := Announce{Header: Header{Version: 1, SenderID: 9, Seq: 1}, Records: []Record{{Topic: topic("x"), Lifetime: 1}}}
	vpkt, _ := v1.Append(nil)
	resp := r.Handle(cliAddr, vpkt, now)
	a, err := DecodeAck(resp)
	if err != nil || a.Result != ResultVersion || a.Version != Version || len(resp) != HeaderSize {
		t.Fatalf("version answer %+v %v", a, err)
	}
	st := r.Stats()
	if st.Unidentified != 1 || st.Malformed != 3 || st.WrongVersion != 1 || st.Datagrams != 5 {
		t.Fatalf("stats %+v", st)
	}
}

// A topic whose group the path does not deliver is not processed: no state
// is kept for it, and the sender is told. Once the sender knows the scope
// it stops sending such topics at all.
func TestScopeNotServed(t *testing.T) {
	const bits = 4
	gen := [16]byte{1}
	var groups []uint16
	for g := uint16(0); g < 8; g++ {
		groups = append(groups, 0x1000+g)
	}
	sc, _ := NewScope(shard.DomainBEEF, bits, gen, groups)
	pol := &testPolicy{scope: sc}
	n, c, r := simplePair(t, 9, pol, nil)

	ts := topics("t", 400)
	want := map[TopicID]bool{}
	for _, x := range ts {
		c.Add(x)
		if sc.Contains(x) {
			want[x] = true
		}
	}
	if len(want) == 0 || len(want) == len(ts) {
		t.Fatal("the test needs topics on both sides of the scope")
	}
	n.kick()
	n.run(2 * time.Second)

	sameSet(t, "receiver", r.Live("p"), want)
	st := r.Stats()
	if st.Topics != len(want) {
		t.Fatalf("the receiver keeps state for %d topics, %d are in scope", st.Topics, len(want))
	}
	for _, x := range ts {
		got := c.Status(x)
		if want[x] && got != StatusOK || !want[x] && got != StatusNotServed {
			t.Fatalf("status %v, in scope %v", got, want[x])
		}
	}
	up := c.Upstreams()[0]
	if up.Scope == nil || !up.Scope.Equal(sc) || up.Tracked != len(want) || !up.Synced {
		t.Fatalf("upstream %+v", up)
	}

	// From here on the sender knows the scope: a new topic outside it is
	// never sent.
	refusedBefore := r.Stats().Refused[StatusNotServed]
	var outside TopicID
	for i := 0; ; i++ {
		outside = topic(fmt.Sprintf("late-%d", i))
		if !sc.Contains(outside) {
			break
		}
	}
	sentBefore := n.sent
	c.Add(outside)
	n.kick()
	n.run(time.Second)
	if c.Status(outside) != StatusNotServed {
		t.Fatalf("status %v", c.Status(outside))
	}
	if n.sent != sentBefore || r.Stats().Refused[StatusNotServed] != refusedBefore {
		t.Fatal("a topic known to be out of scope was sent anyway")
	}
}

// The delivered scope changes: the plane's membership moves. The upstream
// drops what it no longer delivers and pokes; the sender learns the new
// scope and announces what is now served.
func TestScopeChange(t *testing.T) {
	const bits = 4
	gen := [16]byte{1}
	low, _ := NewScope(shard.DomainBEEF, bits, gen, []uint16{0x1000, 0x1001, 0x1002, 0x1003})
	high, _ := NewScope(shard.DomainBEEF, bits, gen, []uint16{0x1002, 0x1003, 0x1004, 0x1005})
	pol := &testPolicy{scope: low}
	live := map[string]liveSet{}
	n, c, r := simplePair(t, 10, pol, trackLive(live))
	ts := topics("t", 600)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(2 * time.Second)
	wantLow := map[TopicID]bool{}
	wantHigh := map[TopicID]bool{}
	for _, x := range ts {
		if low.Contains(x) {
			wantLow[x] = true
		}
		if high.Contains(x) {
			wantHigh[x] = true
		}
	}
	sameSet(t, "before", r.Live("p"), wantLow)

	pol.scope = high
	r.Reevaluate("p", n.now)
	// Dropped at once at the upstream, before the sender knows.
	for _, x := range r.Live("p") {
		if !high.Contains(x) {
			t.Fatal("a topic outside the new scope survived the re-evaluation")
		}
	}
	n.run(5 * time.Second)
	sameSet(t, "after", r.Live("p"), wantHigh)
	sameSet(t, "callback view", keys(live["p"]), wantHigh)
	up := c.Upstreams()[0]
	if !up.Scope.Equal(high) || !up.Synced || up.Held != len(wantHigh) {
		t.Fatalf("upstream %+v", up)
	}
	for _, x := range ts {
		got := c.Status(x)
		if wantHigh[x] && got != StatusOK || !wantHigh[x] && got != StatusNotServed {
			t.Fatalf("status %v, in new scope %v", got, wantHigh[x])
		}
	}
}

// Two upstreams that each deliver half of the plane: every topic goes to
// the one that serves it and to no other. A topic both serve goes to both,
// so that a standby already holds it.
func TestRoutesByShard(t *testing.T) {
	const bits = 3
	gen := [16]byte{1}
	a, _ := NewScope(shard.DomainBEEF, bits, gen, []uint16{0x1000, 0x1001, 0x1002, 0x1003, 0x1004})
	b, _ := NewScope(shard.DomainBEEF, bits, gen, []uint16{0x1004, 0x1005, 0x1006})
	addrA, addrB := ap("[2001:db8::a]:8729"), ap("[2001:db8::b]:8729")
	n := newSim(t, 11)
	ra := NewReceiver(ReceiverConfig{Policy: &testPolicy{scope: a}})
	rb := NewReceiver(ReceiverConfig{Policy: &testPolicy{scope: b}})
	n.addReceiver(addrA, ra)
	n.addReceiver(addrB, rb)
	c := NewClient(ClientConfig{SenderID: 5, Upstreams: []netip.AddrPort{addrA, addrB}})
	n.addClient(cliAddr, c)
	ts := topics("t", 800)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(3 * time.Second)

	wantA, wantB := map[TopicID]bool{}, map[TopicID]bool{}
	unserved := 0
	for _, x := range ts {
		if a.Contains(x) {
			wantA[x] = true
		}
		if b.Contains(x) {
			wantB[x] = true
		}
		st := c.Status(x)
		switch {
		case a.Contains(x) || b.Contains(x):
			if st != StatusOK {
				t.Fatalf("served topic has status %v", st)
			}
		default:
			unserved++
			if st != StatusNotServed {
				t.Fatalf("unserved topic has status %v", st)
			}
			if c.UnservedStatus(x) != StatusNotServed {
				t.Fatal("unserved topic is not listed as unserved")
			}
		}
	}
	sameSet(t, "upstream a", ra.Live("p"), wantA)
	sameSet(t, "upstream b", rb.Live("p"), wantB)
	if unserved == 0 {
		t.Fatal("the test needs a group neither upstream serves")
	}
	listed := 0
	c.Unserved(func(TopicID, Status) bool { listed++; return true })
	if listed != unserved {
		t.Fatalf("%d topics listed as unserved, %d are", listed, unserved)
	}
	u := c.Scope()
	if u == nil || len(u.Groups()) != 7 {
		t.Fatalf("the union of the upstream scopes: %+v", u)
	}
}

// A sharded tunnel with a standby: A serves two groups, and B, the standby,
// holds no record of the sender and never answers, so its scope is not
// known. A topic outside A's groups must still be reported as not served
// once B has stopped answering, instead of waiting at B as pending for
// ever; and when B takes the sender over, what B serves is delivered.
func TestStandbyDoesNotHideARefusal(t *testing.T) {
	const bits = 3
	gen := [16]byte{2}
	a, _ := NewScope(shard.DomainBEEF, bits, gen, []uint16{0x1000, 0x1001})
	addrA, addrB := ap("[2001:db8::a]:8729"), ap("[2001:db8::b]:8729")
	known := false
	n := newSim(t, 12)
	ra := NewReceiver(ReceiverConfig{Policy: &testPolicy{scope: a}})
	rb := NewReceiver(ReceiverConfig{Policy: &testPolicy{principal: func(netip.AddrPort) (string, bool) { return "p", known }}})
	n.addReceiver(addrA, ra)
	n.addReceiver(addrB, rb)
	c := NewClient(ClientConfig{SenderID: 6, Upstreams: []netip.AddrPort{addrA, addrB}})
	n.addClient(cliAddr, c)
	ts := topics("s", 200)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Minute)
	if up := c.Upstreams()[1]; up.Reachable {
		t.Fatalf("the standby answered: %+v", up)
	}
	outside := 0
	for _, x := range ts {
		st := c.Status(x)
		switch {
		case a.Contains(x):
			if st != StatusOK {
				t.Fatalf("a topic A serves: %v", st)
			}
		default:
			outside++
			if st != StatusNotServed || c.UnservedStatus(x) != StatusNotServed {
				t.Fatalf("a topic outside A's groups, with the standby silent: %v", st)
			}
		}
	}
	if outside == 0 {
		t.Fatal("the test needs topics outside A's groups")
	}

	// B takes the sender over, serving every group: all are served now.
	known = true
	c.Poke(addrB, n.now)
	n.kick()
	n.run(5 * time.Second)
	for _, x := range ts {
		if st := c.Status(x); st != StatusOK {
			t.Fatalf("after the standby took over: %v", st)
		}
	}
	if got := len(rb.Live("p")); got != len(ts) {
		t.Fatalf("the standby holds %d of %d", got, len(ts))
	}
}

// The bound: listed topics are free, the rest draw on a quota.
func TestBoundAndQuota(t *testing.T) {
	listed := topics("listed", 5)
	extra := topics("extra", 10)
	pol := &testPolicy{listed: map[TopicID]bool{}, quota: 4}
	for _, x := range listed {
		pol.listed[x] = true
	}
	n, c, r := simplePair(t, 12, pol, nil)
	for _, x := range listed {
		c.Add(x)
	}
	for _, x := range extra {
		c.Add(x)
	}
	n.kick()
	n.run(2 * time.Second)

	held := 0
	for _, x := range extra {
		switch c.Status(x) {
		case StatusOK:
			held++
		case StatusOverCap:
		default:
			t.Fatalf("status %v", c.Status(x))
		}
	}
	if held != 4 || len(r.Live("p")) != 9 {
		t.Fatalf("%d of the unlisted topics are held and %d are live; the quota is 4", held, len(r.Live("p")))
	}
	for _, x := range listed {
		if c.Status(x) != StatusOK {
			t.Fatal("a listed topic was refused")
		}
	}

	// Withdrawing some frees quota, and the refused ones are asked again
	// at the next refresh without the caller doing anything.
	freed := 0
	for _, x := range extra {
		if c.Status(x) == StatusOK && freed < 2 {
			c.Remove(x)
			freed++
		}
	}
	n.kick()
	n.run(time.Duration(DefaultLifetimes.Default/3+5) * time.Second)
	held = 0
	for _, x := range extra {
		if c.Status(x) == StatusOK {
			held++
		}
	}
	if held != 4 {
		t.Fatalf("%d unlisted topics held after quota was freed, want 4 again", held)
	}

	// No quota at all: an unlisted topic is outside the bound.
	pol2 := &testPolicy{listed: map[TopicID]bool{listed[0]: true}, quota: 0}
	n2, c2, r2 := simplePair(t, 13, pol2, nil)
	c2.Add(listed[0])
	c2.Add(extra[0])
	n2.kick()
	n2.run(time.Second)
	if c2.Status(listed[0]) != StatusOK || c2.Status(extra[0]) != StatusOutsideBound || len(r2.Live("p")) != 1 {
		t.Fatalf("listed %v, unlisted %v", c2.Status(listed[0]), c2.Status(extra[0]))
	}
	if r2.Stats().Refused[StatusOutsideBound] == 0 {
		t.Fatal("the refusal was not counted")
	}
}

// The quota shrinks while topics are live. The newest go, the sender is
// told at once, and both sides agree afterwards.
func TestQuotaShrinks(t *testing.T) {
	pol := &testPolicy{listOnly: true, quota: 10}
	n, c, r := simplePair(t, 14, pol, nil)
	ts := topics("q", 10)
	for i, x := range ts {
		c.Add(x)
		n.kick()
		n.run(100 * time.Millisecond)
		_ = i
	}
	if len(r.Live("p")) != 10 {
		t.Fatal("setup")
	}
	pol.quota = 6
	r.Reevaluate("p", n.now)
	if len(r.Live("p")) != 6 {
		t.Fatalf("%d live after the quota shrank to 6", len(r.Live("p")))
	}
	for _, x := range ts[:6] {
		if !r.IsLive("p", x) {
			t.Fatal("an older topic was dropped instead of a newer one")
		}
	}
	n.run(5 * time.Second)
	for i, x := range ts {
		got := c.Status(x)
		if i < 6 && got != StatusOK || i >= 6 && got != StatusOverCap {
			t.Fatalf("topic %d: status %v", i, got)
		}
	}
	if up := c.Upstreams()[0]; !up.Synced || up.Held != 6 {
		t.Fatalf("upstream %+v", up)
	}
}

// Several senders of one principal: the principal's live set is the union,
// and a topic stays live until the last sender lets go.
func TestUnionAcrossSenders(t *testing.T) {
	live := map[string]liveSet{}
	n := newSim(t, 15)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, OnChange: trackLive(live)})
	n.addReceiver(rcvAddr, r)
	a1, a2 := ap("[2001:db8::11]:4000"), ap("[2001:db8::12]:4000")
	c1 := NewClient(ClientConfig{SenderID: 1, Upstreams: []netip.AddrPort{rcvAddr}})
	c2 := NewClient(ClientConfig{SenderID: 2, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(a1, c1)
	n.addClient(a2, c2)
	shared, only1, only2 := topic("shared"), topic("one"), topic("two")
	c1.Add(shared)
	c1.Add(only1)
	c2.Add(shared)
	c2.Add(only2)
	n.kick()
	n.run(time.Second)
	if len(live["p"]) != 3 || r.Stats().Topics != 4 || r.Stats().LiveTopics != 3 {
		t.Fatalf("live %d, stats %+v", len(live["p"]), r.Stats())
	}
	c1.Remove(shared)
	n.kick()
	n.run(time.Second)
	if !r.IsLive("p", shared) {
		t.Fatal("the topic went away while a sender still held it")
	}
	c2.Remove(shared)
	n.kick()
	n.run(time.Second)
	if r.IsLive("p", shared) || len(live["p"]) != 2 {
		t.Fatal("the topic stayed after the last sender let go")
	}
	if got := r.MaxSenderHops(); got != 0 {
		t.Fatalf("hops %d", got)
	}
	r.DropPrincipal("p")
	if len(live["p"]) != 0 || len(r.Senders()) != 0 {
		t.Fatal("dropping the principal left state behind")
	}
}

func TestRateLimit(t *testing.T) {
	n := newSim(t, 16)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, ChangeRate: 20, ChangeBurst: 20})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(cliAddr, c)
	ts := topics("t", 200)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(2 * time.Second)
	if got := len(r.Live("p")); got < 20 || got > 80 {
		t.Fatalf("%d topics after two seconds at 20 a second", got)
	}
	n.run(15 * time.Second)
	if got := len(r.Live("p")); got != 200 {
		t.Fatalf("%d of 200 topics after the limit had time to pass them all", got)
	}
	if r.Stats().Refused[StatusRateLimited] == 0 {
		t.Fatal("nothing was rate limited")
	}
	if up := c.Upstreams()[0]; !up.Synced || up.Held != 200 {
		t.Fatalf("upstream %+v", up)
	}
}

func TestCaps(t *testing.T) {
	n := newSim(t, 17)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, MaxTopicsPerSender: 25, MaxSendersPerPrincipal: 1})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(cliAddr, c)
	for _, x := range topics("t", 40) {
		c.Add(x)
	}
	n.kick()
	n.run(2 * time.Second)
	if len(r.Live("p")) != 25 || r.Stats().Refused[StatusOverCap] != 15 {
		t.Fatalf("live %d, stats %+v", len(r.Live("p")), r.Stats())
	}
	// A second sender of the same principal is over the sender cap.
	c2 := NewClient(ClientConfig{SenderID: 78, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(ap("[2001:db8::20]:4000"), c2)
	c2.Add(topic("other"))
	n.kick()
	n.run(2 * time.Second)
	if r.IsLive("p", topic("other")) || r.Stats().Busy == 0 || len(r.Senders()) != 1 {
		t.Fatalf("stats %+v", r.Stats())
	}
}

func TestHopLimit(t *testing.T) {
	n, c, r := simplePair(t, 18, &testPolicy{}, nil)
	c.SetHops(DefaultMaxHops + 1)
	c.Add(topic("x"))
	n.kick()
	n.run(2 * time.Second)
	if r.IsLive("p", topic("x")) || r.Stats().HopLimited == 0 {
		t.Fatalf("stats %+v", r.Stats())
	}
	c.SetHops(DefaultMaxHops)
	n.run(30 * time.Second)
	if !r.IsLive("p", topic("x")) {
		t.Fatal("not applied at the hop limit itself")
	}
	if got := r.MaxSenderHops(); got != DefaultMaxHops {
		t.Fatalf("hops %d", got)
	}
}

// A hop that holds a topic it cannot have served says so, when the topic
// is announced and again with each refresh.
func TestNotes(t *testing.T) {
	x, y := topic("x"), topic("y")
	pol := notingPolicy{&testPolicy{notes: map[TopicID]Status{x: StatusUnserved}}}
	var events []string
	n := newSim(t, 19)
	r := NewReceiver(ReceiverConfig{Policy: pol})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, OnStatus: func(t TopicID, s Status) {
		events = append(events, fmt.Sprintf("%x=%v", t[:2], s))
	}})
	n.addClient(cliAddr, c)
	c.Add(x)
	c.Add(y)
	n.kick()
	n.run(time.Second)
	if c.Status(x) != StatusUnserved || c.Status(y) != StatusOK {
		t.Fatalf("x %v, y %v", c.Status(x), c.Status(y))
	}
	if !r.IsLive("p", x) {
		t.Fatal("a noted topic must still be held")
	}
	if c.UnservedStatus(x) != StatusUnserved || c.UnservedStatus(y) != StatusOK {
		t.Fatal("the unserved list")
	}

	// The note moves to the other topic. The sender hears of it with the
	// next refresh, or sooner when poked.
	delete(pol.notes, x)
	pol.notes[y] = StatusUpstreamRefused
	r.PokeAll()
	n.run(3 * time.Second)
	if c.Status(y) != StatusUpstreamRefused {
		t.Fatalf("y %v after a poke", c.Status(y))
	}
	// A lifted note is not listed any more in the digest's answer, which
	// lists them all, so the topic is served again for the sender.
	if c.Status(x) != StatusOK || c.UnservedStatus(x) != StatusOK {
		t.Fatalf("x %v after its note was lifted", c.Status(x))
	}
	if len(events) == 0 {
		t.Fatal("no status events")
	}
	if up := c.Upstreams()[0]; up.Stats.Syncs != 1 || up.Held != 2 {
		t.Fatalf("upstream %+v", up)
	}
}

func TestDeliveryAddressIsNotHonored(t *testing.T) {
	n, c, r := simplePair(t, 20, &testPolicy{}, nil)
	v, err := (&Delivery{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: cliAddr.Addr(), Port: 9171}).AppendValue(nil)
	if err != nil {
		t.Fatal(err)
	}
	x, y, z := topic("x"), topic("y"), topic("z")
	c.Set(x, AppendTLV(nil, ExtDelivery, v))
	c.Add(y)
	c.Set(z, AppendTLV(nil, 0xC0, []byte("critical and unknown")))
	n.kick()
	n.run(time.Second)
	if c.Status(x) != StatusAddressNotHonored || c.Status(y) != StatusOK || c.Status(z) != StatusUnsupported {
		t.Fatalf("x %v, y %v, z %v", c.Status(x), c.Status(y), c.Status(z))
	}
	if !r.IsLive("p", x) || r.IsLive("p", z) {
		t.Fatal("held set")
	}
	// Changing the extensions of a held topic says it again.
	c.Set(x, nil)
	n.kick()
	n.run(time.Second)
	if c.Status(x) != StatusOK {
		t.Fatalf("x %v after dropping the address", c.Status(x))
	}
	if up := c.Upstreams()[0]; up.Held != 2 || up.Stats.Syncs != 1 || !up.Synced {
		t.Fatalf("upstream %+v", up)
	}
}

// The upstream is unreachable, then comes back.
func TestUpstreamOutage(t *testing.T) {
	n, c, r := simplePair(t, 21, &testPolicy{}, nil)
	n.down[rcvAddr] = true
	ts := topics("t", 60)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Minute)
	up := c.Upstreams()[0]
	if up.Reachable || up.Stats.Timeouts < 3 {
		t.Fatalf("upstream %+v", up)
	}
	// Backoff: far fewer probes than one every RTOMin.
	if n.sent > 30 {
		t.Fatalf("%d datagrams into a dead upstream in a minute", n.sent)
	}
	delete(n.down, rcvAddr)
	n.run(20 * time.Second)
	if len(r.Live("p")) != 60 {
		t.Fatalf("%d of 60 after the upstream came back", len(r.Live("p")))
	}
	if up := c.Upstreams()[0]; !up.Reachable || !up.Synced {
		t.Fatalf("upstream %+v", up)
	}

	// An outage longer than the lifetime: everything lapses upstream, and
	// is restored without the caller doing anything.
	n.down[rcvAddr] = true
	n.run(time.Duration(DefaultLifetimes.Default+30) * time.Second)
	if len(r.Live("p")) != 0 {
		t.Fatal("state survived an outage longer than its lifetime")
	}
	delete(n.down, rcvAddr)
	n.run(time.Minute)
	if len(r.Live("p")) != 60 {
		t.Fatalf("%d of 60 after the long outage", len(r.Live("p")))
	}
}

// An upstream that holds no record of the sender ignores it, and the
// sender's timeouts grow to the longest. When the upstream takes the sender
// over (a standby edge after a flip, an edge the consumer returns to) it
// pokes, and the sender must be heard within a few round trips, not at the
// end of that timeout.
func TestPokeEndsABackoff(t *testing.T) {
	known := false
	pol := &testPolicy{principal: func(netip.AddrPort) (string, bool) { return "p", known }}
	n, c, r := simplePair(t, 31, pol, nil)
	resync, err := (&Resync{}).Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	heard := func(what string, want int) {
		t.Helper()
		start := n.now
		for len(r.Live("p")) != want && n.now.Sub(start) < 20*time.Second {
			n.run(time.Millisecond)
		}
		if got := len(r.Live("p")); got != want {
			t.Fatalf("%s: %d of %d live", what, got, want)
		}
		// The links take 1 to 2 ms each way.
		if took := n.now.Sub(start); took > 30*time.Millisecond {
			t.Fatalf("%s: heard %v after the poke", what, took)
		}
	}

	// First contact with an upstream that ignored the sender for a minute.
	ts := topics("t", 20)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Minute)
	if up := c.Upstreams()[0]; up.Reachable || up.Synced {
		t.Fatalf("an upstream that ignores the sender: %+v", up)
	}
	known = true
	n.send(rcvAddr, cliAddr, resync) // the RESYNC reaches the sending socket
	heard("first contact", 20)

	// Synced, then ignored while the sender changed its set, then taken
	// back: the edge dropped the consumer when it left and holds nothing.
	n.run(5 * time.Second)
	known = false
	for _, x := range topics("u", 10) {
		c.Add(x)
	}
	n.kick()
	n.run(time.Minute)
	if up := c.Upstreams()[0]; up.Reachable {
		t.Fatalf("an upstream that ignores the sender: %+v", up)
	}
	r.DropPrincipal("p")
	known = true
	c.Poke(rcvAddr, n.now) // as a relay does when its listening socket is poked
	n.kick()               // as the owner does when the client wakes it
	heard("taken back", 30)

	// A poke is acted on at most once a second: a flood of them sends no
	// more than that.
	sent := n.sent
	for i := 0; i < 100; i++ {
		c.Poke(rcvAddr, n.now)
		n.kick()
		n.run(10 * time.Millisecond)
	}
	if extra := n.sent - sent; extra > 8 {
		t.Fatalf("%d datagrams for 100 pokes in a second", extra)
	}
}

func TestReplace(t *testing.T) {
	n, c, r := simplePair(t, 22, &testPolicy{}, nil)
	a := topics("a", 30)
	c.Replace(a)
	n.kick()
	n.run(time.Second)
	b := append(topics("b", 10), a[:5]...)
	c.Replace(b)
	n.kick()
	n.run(time.Second)
	want := map[TopicID]bool{}
	for _, x := range b {
		want[x] = true
	}
	sameSet(t, "receiver", r.Live("p"), want)
	if c.Wanted() != 15 {
		t.Fatalf("wanted %d", c.Wanted())
	}
}

// A large set, replayed after an upstream restart, with loss.
func TestLargeSetReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("large set")
	}
	n, c, r := simplePair(t, 23, &testPolicy{}, nil)
	n.loss = 0.05
	n.minDelay, n.maxDelay = time.Millisecond, 20*time.Millisecond
	ts := topics("big", 20000)
	want := map[TopicID]bool{}
	for _, x := range ts {
		c.Add(x)
		want[x] = true
	}
	n.kick()
	n.run(2 * time.Minute)
	sameSet(t, "receiver", r.Live("p"), want)

	r2 := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	n.addReceiver(rcvAddr, r2)
	n.run(time.Duration(DefaultLifetimes.Default/3)*time.Second + 2*time.Minute)
	sameSet(t, "restarted receiver", r2.Live("p"), want)
	if up := c.Upstreams()[0]; !up.Synced || up.Held != 20000 {
		t.Fatalf("upstream %+v", up)
	}
}

// A relay restarts. It comes back knowing nothing and learns its set from
// the senders below it over the next while. Its upstream must keep
// delivering what the previous run announced until the relay has had the
// time to learn it again: a topic that is still wanted is never dropped on
// the way, and what is no longer wanted goes when the hold ends.
func TestSweepHoldCoversARestart(t *testing.T) {
	live := map[string]liveSet{}
	dropped := map[TopicID]bool{}
	n := newSim(t, 40)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}, OnChange: func(p string, x TopicID, on bool) {
		if !on {
			dropped[x] = true
		}
		trackLive(live)(p, x, on)
	}})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}})
	n.addClient(cliAddr, c)
	ts := topics("t", 90)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)

	// The new run: empty at first, with a hold.
	const hold = 100 * time.Second
	c2 := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SweepHold: hold})
	n.addClient(cliAddr, c2)
	n.kick()
	n.run(time.Second)
	if len(r.Live("p")) != 90 {
		t.Fatalf("%d of 90 live right after the restart", len(r.Live("p")))
	}
	// It learns 60 of the 90 again, a few at a time.
	want := map[TopicID]bool{}
	for i := 0; i < 60; i++ {
		c2.Add(ts[i])
		want[ts[i]] = true
		if i%10 == 9 {
			n.kick()
			n.run(10 * time.Second)
		}
	}
	if len(r.Live("p")) != 90 || len(dropped) != 0 {
		t.Fatalf("%d live and %d dropped during the hold", len(r.Live("p")), len(dropped))
	}
	n.run(hold)
	sameSet(t, "after the hold", r.Live("p"), want)
	for x := range dropped {
		if want[x] {
			t.Fatal("a topic that is still wanted was dropped on the way")
		}
	}
	if up := c2.Upstreams()[0]; !up.Synced || up.Held != 60 || up.Stats.Syncs != 1 {
		t.Fatalf("upstream %+v", up)
	}

	// A later replay, after the upstream restarts, is not held: by then
	// the sender knows its set.
	r2 := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	n.addReceiver(rcvAddr, r2)
	n.run(time.Duration(DefaultLifetimes.Default/3+5) * time.Second)
	if up := c2.Upstreams()[0]; !up.Synced || up.Stats.Syncs != 2 {
		t.Fatalf("upstream after the upstream restarted %+v", up)
	}
	sameSet(t, "restarted upstream", r2.Live("p"), want)
}

func TestOnScope(t *testing.T) {
	sc, _ := AllScope(shard.DomainBEEF, 6, [16]byte{1})
	pol := &testPolicy{scope: sc}
	calls := 0
	n := newSim(t, 41)
	r := NewReceiver(ReceiverConfig{Policy: pol})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, OnScope: func() { calls++ }})
	n.addClient(cliAddr, c)
	c.Add(topic("x"))
	n.kick()
	n.run(time.Second)
	if calls != 1 || c.Scope() == nil || !c.Scope().All() {
		t.Fatalf("%d scope calls, scope %+v", calls, c.Scope())
	}
	sc2, _ := AllScope(shard.DomainBEEF, 7, [16]byte{2})
	pol.scope = sc2
	r.PokeAll()
	n.run(3 * time.Second)
	if calls != 2 || c.Scope().ShardBits() != 7 {
		t.Fatalf("%d scope calls after a change, scope %+v", calls, c.Scope())
	}
}

// A sender that holds its sweep, as a relay does after a restart, still
// learns what its upstream delivers at once, so that it can refuse what is
// not served instead of passing it on for the length of the hold.
func TestScopeLearnedDuringAHeldReplay(t *testing.T) {
	sc, _ := NewScope(shard.DomainBEEF, 3, [16]byte{1}, []uint16{0x1000, 0x1001})
	n := newSim(t, 42)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{scope: sc}})
	n.addReceiver(rcvAddr, r)
	scoped := 0
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SweepHold: 100 * time.Second,
		OnScope: func() { scoped++ }})
	n.addClient(cliAddr, c)
	ts := topics("t", 100)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)
	if scoped != 1 || c.Scope() == nil || !c.Scope().Equal(sc) {
		t.Fatalf("scope after a second of a held replay: %+v (%d calls)", c.Scope(), scoped)
	}
	up := c.Upstreams()[0]
	if up.Synced || !up.Holding {
		t.Fatalf("the replay must be settled and held: %+v", up)
	}
	in := 0
	for _, x := range ts {
		if sc.Contains(x) {
			in++
		}
	}
	if up.Tracked != in || up.Held != in {
		t.Fatalf("tracked %d, held %d, in scope %d", up.Tracked, up.Held, in)
	}
	n.run(101 * time.Second)
	if up := c.Upstreams()[0]; !up.Synced || up.Holding || up.Stats.Syncs != 1 || up.Stats.Mismatches != 0 {
		t.Fatalf("upstream after the hold %+v", up)
	}
}

// A relay that has nothing to announce yet still learns what its upstream
// delivers as soon as it has a token, so that the first host to announce is
// told at once what is not served.
func TestScopeLearnedWithNothingToSay(t *testing.T) {
	sc, _ := NewScope(shard.DomainBEEF, 3, [16]byte{1}, []uint16{0x1000, 0x1001})
	n := newSim(t, 43)
	n.addReceiver(rcvAddr, NewReceiver(ReceiverConfig{Policy: &testPolicy{scope: sc}}))
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SweepHold: 100 * time.Second})
	n.addClient(cliAddr, c)
	n.kick()
	n.run(time.Second)
	if got := c.Scope(); got == nil || !got.Equal(sc) {
		t.Fatalf("scope with nothing announced: %+v", got)
	}
	sent := n.sent
	n.run(50 * time.Second)
	if n.sent != sent {
		t.Fatalf("%d datagrams while idle and held; the probe must not repeat", n.sent-sent)
	}

	// An upstream with no scope at all is asked once and not again.
	n2 := newSim(t, 44)
	n2.addReceiver(rcvAddr, NewReceiver(ReceiverConfig{Policy: &testPolicy{}}))
	c2 := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SweepHold: 100 * time.Second})
	n2.addClient(cliAddr, c2)
	n2.kick()
	n2.run(time.Second)
	sent = n2.sent
	n2.run(50 * time.Second)
	if c2.Scope() != nil || n2.sent != sent {
		t.Fatalf("scope %+v, %d datagrams while idle", c2.Scope(), n2.sent-sent)
	}
}

// A probe asks and claims nothing: whatever it says about the set, the
// upstream compares nothing, refreshes nothing and removes nothing.
func TestProbeChangesNothing(t *testing.T) {
	n, c, r := simplePair(t, 45, &testPolicy{}, nil)
	for _, x := range topics("t", 20) {
		c.Add(x)
	}
	n.kick()
	n.run(time.Second)
	s := r.Senders()[0]
	before := r.Stats()
	m := Digest{
		Header: Header{Version: Version, Flags: FlagProbe, SenderID: 77, Token: r.token(cliAddr, 77), Seq: s.LastSeq + 1},
		Since:  s.LastSeq + 1, // would sweep everything if it were believed
	}
	pkt, _ := m.Append(nil)
	a, err := DecodeAck(r.Handle(cliAddr, pkt, n.now))
	if err != nil || a.Result != ResultOK || a.SetCount != 20 {
		t.Fatalf("probe answered %+v %v", a, err)
	}
	if st := r.Stats(); st.Probes != before.Probes+1 || st.Mismatches != 0 || st.Sweeps != 0 || st.Topics != 20 || st.Digests != before.Digests {
		t.Fatalf("stats %+v", st)
	}
}

// The sequence number space has no end to run into: a sender that starts
// near the top wraps past zero and carries on, in order.
func TestSequenceWraps(t *testing.T) {
	n := newSim(t, 46)
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{}})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SeqStart: ^uint64(0) - 3})
	n.addClient(cliAddr, c)
	n.minDelay, n.maxDelay = 5*time.Millisecond, 5*time.Millisecond
	want := map[TopicID]bool{}
	for round := 0; round < 12; round++ {
		for _, x := range topics(fmt.Sprintf("r%d", round), 40) {
			c.Add(x)
			want[x] = true
		}
		n.kick()
		n.run(200 * time.Millisecond)
	}
	sameSet(t, "receiver", r.Live("p"), want)
	s := r.Senders()[0]
	if s.LastSeq > 1000 {
		t.Fatalf("last sequence number %d; it should have wrapped to a small one", s.LastSeq)
	}
	up := c.Upstreams()[0]
	if !up.Synced || up.Stats.Stale != 0 || up.Stats.Syncs != 1 || up.Stats.Mismatches != 0 {
		t.Fatalf("upstream %+v", up)
	}
	// The sweep that ends a replay compares across the wrap too.
	c2 := NewClient(ClientConfig{SenderID: 77, Upstreams: []netip.AddrPort{rcvAddr}, SeqStart: ^uint64(0) - 1})
	n.addClient(cliAddr, c2)
	keep := topics("r0", 40)
	for _, x := range keep {
		c2.Add(x)
	}
	n.kick()
	n.run(3 * time.Second)
	if got := len(r.Live("p")); got != 40 {
		t.Fatalf("%d topics after a replay that wrapped, want the 40 it named", got)
	}
}

func TestSeqNewer(t *testing.T) {
	top := ^uint64(0)
	cases := []struct {
		a, b uint64
		want bool
	}{
		{2, 1, true}, {1, 2, false}, {1, 1, false},
		{1, top, true}, {top, 1, false},
		{5, top - 5, true},
		{1 << 62, 1, true},
		{1, 1 << 62, false},
	}
	for _, c := range cases {
		if got := SeqNewer(c.a, c.b); got != c.want {
			t.Errorf("SeqNewer(%d, %d) = %v", c.a, c.b, got)
		}
	}
	if seqAfter(top) != 1 || seqAfter(1) != 2 {
		t.Error("the number after the top is 1; zero is never used")
	}
}

// A topic outside the delivered scope is not processed at all: it is told
// not served even when the sender is at its cap and over its rate, and it
// uses up neither.
func TestScopeIsCheckedBeforeCapsAndRate(t *testing.T) {
	sc, _ := NewScope(shard.DomainBEEF, 1, [16]byte{}, []uint16{0x1000})
	r := NewReceiver(ReceiverConfig{Policy: &testPolicy{scope: sc}, Secret: []byte("k"),
		MaxTopicsPerSender: 1, ChangeRate: 0.001, ChangeBurst: 1})
	now := time.Unix(1_700_000_000, 0)
	var in, out []TopicID
	for i := 0; len(in) < 2 || len(out) < 2; i++ {
		x := topic(fmt.Sprintf("s-%d", i))
		if sc.Contains(x) {
			in = append(in, x)
		} else {
			out = append(out, x)
		}
	}
	m := Announce{
		Header:  Header{Version: Version, SenderID: 9, Token: r.token(cliAddr, 9), Seq: 1},
		Records: []Record{{Topic: in[0], Lifetime: 60}, {Topic: out[0], Lifetime: 60}, {Topic: in[1], Lifetime: 60}, {Topic: out[1], Lifetime: 60}},
	}
	pkt, _ := m.Append(nil)
	a, err := DecodeAck(r.Handle(cliAddr, pkt, now))
	if err != nil || a.Result != ResultOK {
		t.Fatalf("%+v %v", a, err)
	}
	got := map[uint16]Status{}
	for _, s := range a.Statuses {
		got[s.Index] = s.Status
	}
	if got[0] != StatusOK || got[1] != StatusNotServed || got[2] != StatusOverCap || got[3] != StatusNotServed {
		t.Fatalf("statuses %v", got)
	}
	if st := r.Stats(); st.Topics != 1 || st.Refused[StatusNotServed] != 2 || st.Refused[StatusOverCap] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// A relay that has just started holds its upstream's sweep for a while,
// and sends it no digest meanwhile. A poke then (a change of what the
// upstream serves) must still be acted on: the relay asks for the scope.
func TestPokeDuringAHeldReplayLearnsTheScope(t *testing.T) {
	const bits = 3
	gen := [16]byte{3}
	narrow, _ := NewScope(shard.DomainBEEF, bits, gen, []uint16{0x1000})
	pol := &testPolicy{scope: narrow}
	n := newSim(t, 23)
	r := NewReceiver(ReceiverConfig{Policy: pol})
	n.addReceiver(rcvAddr, r)
	c := NewClient(ClientConfig{SenderID: 8, Upstreams: []netip.AddrPort{rcvAddr}, SweepHold: time.Minute})
	n.addClient(cliAddr, c)
	ts := topics("h", 40)
	for _, x := range ts {
		c.Add(x)
	}
	n.kick()
	n.run(2 * time.Second)
	up := c.Upstreams()[0]
	if !up.Holding || up.Scope == nil || !up.Scope.Equal(narrow) {
		t.Fatalf("a held replay with the narrow scope: %+v", up)
	}
	// The upstream now serves everything, and pokes.
	pol.scope = nil
	r.PokeAll()
	n.run(2 * time.Second)
	if sc := c.Upstreams()[0].Scope; sc != nil {
		t.Fatalf("still the old scope during the hold: %v", sc)
	}
	for _, x := range ts {
		if st := c.Status(x); st != StatusOK {
			t.Fatalf("a topic the upstream serves now: %v", st)
		}
	}
	if got := len(r.Live("p")); got != len(ts) {
		t.Fatalf("%d of %d held after the scope widened", got, len(ts))
	}
}
