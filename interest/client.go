package interest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"os"
	"sync"
	"time"
)

// Client defaults.
const (
	// DefaultWindow is how many datagrams a client keeps in flight to one
	// upstream.
	DefaultWindow = 8
	// DefaultRTOMin is the shortest wait for an acknowledgment, and the
	// first. After that the wait follows the measured round-trip time.
	// Each loss doubles it, up to DefaultRTOMax, until an acknowledgment
	// arrives.
	DefaultRTOMin = 250 * time.Millisecond
	// DefaultRTOMax is the longest wait for an acknowledgment.
	DefaultRTOMax = 8 * time.Second
	// maxSyncBackoff bounds the wait between replays that keep failing.
	maxSyncBackoff = time.Minute
	// rateLimitRetry is how long a rate-limited topic waits before it is
	// announced again.
	rateLimitRetry = time.Second
	// pokeInterval is the least time between two digests sent because the
	// upstream asked.
	pokeInterval = time.Second
)

// NewSenderID derives a sender identity from the host name and a label, so
// that it is the same after a restart and differs between two programs on
// one host that use different labels. Two senders that share a source
// address must not share an identity.
func NewSenderID(label string) uint64 {
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte(host + "\x00" + label))
	id := binary.BigEndian.Uint64(sum[:8])
	if id == 0 {
		id = 1
	}
	return id
}

// ClientConfig configures a [Client].
type ClientConfig struct {
	// SenderID identifies this sender to its upstreams. Required. See
	// [NewSenderID].
	SenderID uint64
	// Upstreams are where interest is sent, in the manner of default
	// routes. Every upstream is told every topic it serves, so a standby
	// already holds the interest when it takes over.
	Upstreams []netip.AddrPort
	// Lifetime is the lifetime asked for, in seconds. Zero asks for each
	// upstream's default.
	Lifetime uint32
	// Window defaults to [DefaultWindow].
	Window int
	// RTOMin and RTOMax default to [DefaultRTOMin] and [DefaultRTOMax].
	RTOMin time.Duration
	RTOMax time.Duration
	// SeqStart is the first sequence number. Zero uses the clock at first
	// use, in nanoseconds, so that a restarted sender starts above where
	// it left off without keeping any state.
	SeqStart uint64
	// SweepHold delays the sweep that ends the first replay to each
	// upstream. A sender that starts with its full set, as an announcer
	// does, leaves it zero: what it does not name is withdrawn at once. A
	// relay starts empty and learns its set from the senders below it, so
	// it holds the sweep for as long as they take to check in. Until then
	// its upstream keeps what the relay's previous run announced, and
	// nothing that is still wanted stops being delivered. A hold ends at
	// the latest two thirds of the granted lifetime after the replay
	// begins, so that what the replay said is refreshed before it expires
	// upstream.
	SweepHold time.Duration
	// OnStatus is called when the outcome for a topic changes: whether any
	// upstream serves it, and if none does, why. Calls arrive in order, one
	// at a time, without the client's lock held. A call may use the client;
	// what that changes is reported after the call returns.
	OnStatus func(topic TopicID, status Status)
	// OnScope is called when what the upstreams deliver changes, under the
	// same rules as OnStatus. See [Client.Scope].
	OnScope func()
}

// UpstreamInfo describes one upstream, for inspection.
type UpstreamInfo struct {
	Addr   netip.AddrPort
	Synced bool // the upstream holds exactly what it should
	// Holding: everything wanted has been said and answered, and only the
	// sweep that ends the first replay is being held back. The upstream
	// holds all that is wanted, and may still hold more.
	Holding   bool
	Reachable bool // it has answered since the last loss
	Held      int  // topics the upstream holds
	Tracked   int  // topics this client is keeping the upstream told about
	InFlight  int
	Scope     *Scope
	Lifetimes Lifetimes
	Stats     UpstreamStats
}

// UpstreamStats counts what a client has exchanged with one upstream.
type UpstreamStats struct {
	Announces  uint64
	Digests    uint64
	Acks       uint64
	Timeouts   uint64
	Syncs      uint64 // full replays started
	Tokens     uint64 // tokens adopted
	Stale      uint64
	Mismatches uint64
	Busy       uint64
	Pokes      uint64
	Ignored    uint64 // datagrams from the upstream that matched nothing
}

const (
	phaseHello  = iota // no token yet
	phaseSync          // replaying
	phaseSynced        // the upstream holds what it should; deltas only
)

type upTopic struct {
	want      bool
	ext       []byte
	ver       uint32 // bumped whenever the topic must be said (again)
	ackVer    uint32 // the version the upstream has answered
	sentVer   uint32 // the version last put on the wire
	sentSeq   uint64 // the datagram carrying it, while unanswered
	heldSeq   uint64 // the datagram that last settled held and status
	held      bool
	unsure    bool // a datagram naming it went unanswered
	queued    bool
	status    Status
	notBefore int64
}

type batch struct {
	seq    uint64
	sentAt int64
	digest bool
	asked  bool // the digest asked for the scope
	probe  bool // a digest sent only to ask for the scope; its result is not acted on
	since  uint64
	topics []TopicID
	vers   []uint32
	adds   []bool
}

type upstream struct {
	addr     netip.AddrPort
	token    uint64
	nextSeq  uint64
	lastSent uint64 // the sequence number most recently used
	life     Lifetimes
	scope    *Scope
	scopeGen uint32
	askScope bool
	probing  bool // a scope probe is in flight
	scoped   bool // an answer has said what the scope generation is
	holding  bool // settled except for a sweep that is being held back

	topics     map[TopicID]*upTopic
	queue      []TopicID // to say now
	later      []TopicID // changes held back while a digest is due
	inflight   map[uint64]*batch
	heldCount  uint32
	heldDigest SetDigest

	phase       int
	since       uint64
	needSync    bool
	nextSyncAt  int64
	lastSync    int64
	syncBackoff time.Duration
	digestDue   bool
	nextRefresh int64
	lastPoke    int64
	rto         time.Duration
	srtt        time.Duration
	rttvar      time.Duration
	timeouts    int
	reachable   bool
	pausedUntil int64
	stats       UpstreamStats
}

type wanted struct {
	ext []byte
	agg Status
}

type statusEvent struct {
	topic  TopicID
	status Status
}

// Client is the downstream half of the protocol: it keeps every upstream
// told of a set of topics, through loss, restarts and changes of scope. An
// announcer is a Client; so is the upstream side of a relay.
//
// It does no I/O and reads no clock. It is safe for concurrent use.
type Client struct {
	cfg ClientConfig

	mu       sync.Mutex
	hops     uint8
	want     map[TopicID]*wanted
	noted    map[TopicID]Status // wanted topics no upstream serves
	ups      []*upstream
	events   []statusEvent
	scoped   bool  // a scope changed since the last flush
	holdTo   int64 // first replays are not swept before this
	flushing bool  // callbacks are being delivered
	wake     chan struct{}
}

// NewClient builds a client. It panics on a zero sender identity or an
// empty upstream list, which are programming errors.
func NewClient(cfg ClientConfig) *Client {
	if cfg.SenderID == 0 {
		panic("interest: client without a sender identity")
	}
	if len(cfg.Upstreams) == 0 {
		panic("interest: client without an upstream")
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.RTOMin <= 0 {
		cfg.RTOMin = DefaultRTOMin
	}
	if cfg.RTOMax < cfg.RTOMin {
		cfg.RTOMax = DefaultRTOMax
		if cfg.RTOMax < cfg.RTOMin {
			cfg.RTOMax = cfg.RTOMin
		}
	}
	c := &Client{
		cfg:   cfg,
		want:  make(map[TopicID]*wanted),
		noted: make(map[TopicID]Status),
		wake:  make(chan struct{}, 1),
	}
	for _, a := range cfg.Upstreams {
		c.ups = append(c.ups, &upstream{
			addr:        netip.AddrPortFrom(a.Addr().Unmap(), a.Port()),
			nextSeq:     cfg.SeqStart,
			life:        DefaultLifetimes,
			topics:      make(map[TopicID]*upTopic),
			inflight:    make(map[uint64]*batch),
			rto:         cfg.RTOMin,
			syncBackoff: time.Second,
		})
	}
	return c
}

// Wake returns a channel that receives when the client has new work and
// should be polled. It carries no data and never closes.
func (c *Client) Wake() <-chan struct{} { return c.wake }

func (c *Client) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Add asks for a topic. It is the same as Set with no extensions.
func (c *Client) Add(t TopicID) { c.Set(t, nil) }

// Set asks for a topic, with the record extensions to send with it. Calling
// it again with different extensions updates them.
func (c *Client) Set(t TopicID, ext []byte) {
	c.mu.Lock()
	w := c.want[t]
	if w == nil {
		w = &wanted{agg: StatusPending}
		c.want[t] = w
	} else if bytes.Equal(w.ext, ext) {
		c.mu.Unlock()
		return
	}
	w.ext = bytes.Clone(ext)
	for _, u := range c.ups {
		c.setTarget(u, t, u.scope == nil || u.scope.Contains(t), w.ext)
	}
	c.reaggregate(t)
	c.mu.Unlock()
	c.signal()
	c.flush()
}

// Remove stops asking for a topic.
func (c *Client) Remove(t TopicID) {
	c.mu.Lock()
	if c.want[t] == nil {
		c.mu.Unlock()
		return
	}
	delete(c.want, t)
	delete(c.noted, t)
	for _, u := range c.ups {
		c.setTarget(u, t, false, nil)
	}
	c.mu.Unlock()
	c.signal()
}

// Replace makes the wanted set exactly the given topics, without
// extensions.
func (c *Client) Replace(topics []TopicID) {
	keep := make(map[TopicID]struct{}, len(topics))
	for _, t := range topics {
		keep[t] = struct{}{}
	}
	c.mu.Lock()
	var drop []TopicID
	for t := range c.want {
		if _, ok := keep[t]; !ok {
			drop = append(drop, t)
		}
	}
	c.mu.Unlock()
	for _, t := range drop {
		c.Remove(t)
	}
	for _, t := range topics {
		c.Add(t)
	}
}

// SetHops sets the hop count this client sends: zero for an announcer, and
// for a relay one more than the largest among the senders below it.
func (c *Client) SetHops(h uint8) {
	c.mu.Lock()
	c.hops = h
	c.mu.Unlock()
}

// Status returns the outcome for a wanted topic: [StatusOK] or
// [StatusAddressNotHonored] when an upstream serves it, [StatusPending]
// while none has answered, and otherwise the reason none serves it. A topic
// that is not wanted reports [StatusPending].
func (c *Client) Status(t TopicID) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	if w := c.want[t]; w != nil {
		return w.agg
	}
	return StatusPending
}

// Wanted returns the number of wanted topics.
func (c *Client) Wanted() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.want)
}

// Unserved calls each for every wanted topic that no upstream serves, with
// the reason, until each returns false.
func (c *Client) Unserved(each func(TopicID, Status) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for t, st := range c.noted {
		if !each(t, st) {
			return
		}
	}
}

// UnservedStatus returns the reason no upstream serves a wanted topic, or
// [StatusOK] when one does or none has answered yet.
func (c *Client) UnservedStatus(t TopicID) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.noted[t]
}

// Scope returns what this client's upstreams deliver between them, or nil
// when that is unknown. A relay advertises it to the senders below it.
func (c *Client) Scope() *Scope {
	c.mu.Lock()
	defer c.mu.Unlock()
	scopes := make([]*Scope, len(c.ups))
	for i, u := range c.ups {
		scopes[i] = u.scope
	}
	return UnionScope(scopes)
}

// Upstreams describes every upstream.
func (c *Client) Upstreams() []UpstreamInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]UpstreamInfo, len(c.ups))
	for i, u := range c.ups {
		out[i] = UpstreamInfo{
			Addr: u.addr, Synced: u.phase == phaseSynced && !u.needSync, Holding: u.holding, Reachable: u.reachable,
			Held: int(u.heldCount), Tracked: len(u.topics), InFlight: len(u.inflight),
			Scope: u.scope, Lifetimes: u.life, Stats: u.stats,
		}
	}
	return out
}

// Poke acts on a RESYNC from an upstream, as one that reaches the sending
// socket is acted on. A relay calls it when a RESYNC reaches its listening
// socket instead.
func (c *Client) Poke(addr netip.AddrPort, now time.Time) {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	c.mu.Lock()
	for _, u := range c.ups {
		if u.addr.Addr() == addr.Addr() {
			c.poke(u, now.UnixNano())
		}
	}
	c.mu.Unlock()
	c.signal()
}

// poke is an upstream asking to hear from this sender: it restarted, took
// the sender over (a standby edge after a flip), or changed what it serves.
// A poke is not authenticated, so it is acted on at most once a
// pokeInterval, and all it can cause is datagrams to the upstream itself.
func (c *Client) poke(u *upstream, now int64) {
	u.stats.Pokes++
	if now-u.lastPoke < int64(pokeInterval) {
		return
	}
	if u.phase != phaseSynced && u.reachable {
		// Contact or a replay is under way and being answered. A replay
		// whose sweep is held (a relay's restart hold) sends no digest for
		// a while, so ask what the upstream serves with a probe: a change
		// of scope is one reason to poke.
		if u.phase == phaseSync {
			u.lastPoke = now
			u.askScope = true
		}
		return
	}
	u.lastPoke = now
	if !u.reachable {
		// An upstream that asks is listening now, and what was sent to it
		// while it was not will never be answered. Say it again at once,
		// instead of at the end of a timeout that grew while it was away,
		// and time the next answer afresh.
		for seq, b := range u.inflight {
			c.lose(u, seq, b)
		}
		wasDown := u.down()
		u.timeouts = 0
		u.rto = c.clampRTO(c.cfg.RTOMin)
		if u.srtt > 0 {
			u.rto = c.clampRTO(u.srtt + 4*u.rttvar)
		}
		if wasDown {
			c.reaggregateAll()
		}
	}
	if u.phase == phaseSynced {
		u.digestDue = true
	}
}

// lose drops a datagram in flight as unanswered. Nothing is retransmitted
// as it was: what it carried is still to be said, and is said as it stands
// now.
func (c *Client) lose(u *upstream, seq uint64, b *batch) {
	delete(u.inflight, seq)
	if b.probe {
		u.probing = false
	}
	for _, id := range b.topics {
		if t := u.topics[id]; t != nil {
			t.unsure = true
		}
	}
	c.requeue(u, b)
}

// Farewell returns one datagram for each upstream that withdraws
// everything this sender holds there: a digest of the empty set that sweeps
// all that came before it. It is sent once, without waiting for an answer,
// by a sender that is going away for good. If the client is used again
// afterwards it starts over with each upstream.
func (c *Client) Farewell() []Datagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Datagram
	for _, u := range c.ups {
		if u.token == 0 || u.nextSeq == 0 {
			continue
		}
		seq := c.takeSeq(u)
		m := Digest{
			Header: Header{Version: Version, Hops: c.hops, SenderID: c.cfg.SenderID, Token: u.token, Seq: seq},
			Since:  seq,
		}
		data, _ := m.Append(nil)
		out = append(out, Datagram{Addr: u.addr, Data: data})
		u.token = 0
		u.inflight = make(map[uint64]*batch)
	}
	return out
}

// takeSeq allocates the next sequence number for an upstream.
func (c *Client) takeSeq(u *upstream) uint64 {
	seq := u.nextSeq
	u.nextSeq = seqAfter(seq)
	u.lastSent = seq
	return seq
}

// setTarget records whether an upstream should hold a topic.
func (c *Client) setTarget(u *upstream, id TopicID, present bool, ext []byte) {
	t := u.topics[id]
	if present {
		if t == nil {
			t = &upTopic{status: StatusPending}
			u.topics[id] = t
		}
		if !t.want || !bytes.Equal(t.ext, ext) {
			t.want = true
			t.ext = ext
			t.status = StatusPending
			c.bump(u, id, t, false)
		}
		return
	}
	if t == nil || !t.want {
		return
	}
	t.want = false
	t.ext = nil
	if !t.held && !t.unsure && t.sentSeq == 0 {
		// The upstream holds nothing and nothing is on its way.
		delete(u.topics, id)
		return
	}
	c.bump(u, id, t, false)
}

// bump marks a topic as needing to be said and queues it.
func (c *Client) bump(u *upstream, id TopicID, t *upTopic, urgent bool) {
	t.ver++
	if t.ver == 0 {
		t.ver = 1
	}
	c.enqueue(u, id, t, urgent)
}

// enqueue queues a topic. Changes made while a digest is due wait behind
// it, so that a steady stream of changes cannot hold off the refresh;
// retries of what went unanswered do not wait, because the digest is only
// meaningful once they are settled.
func (c *Client) enqueue(u *upstream, id TopicID, t *upTopic, urgent bool) {
	if t.queued {
		return
	}
	t.queued = true
	if u.digestDue && !urgent && u.phase == phaseSynced {
		u.later = append(u.later, id)
		return
	}
	u.queue = append(u.queue, id)
}

func (c *Client) setHeld(u *upstream, id TopicID, t *upTopic, held bool) {
	if t.held == held {
		return
	}
	t.held = held
	u.heldDigest.Toggle(id)
	if held {
		u.heldCount++
	} else {
		u.heldCount--
	}
}

// statusRank orders outcomes from best to worst for the caller.
func statusRank(s Status) int {
	switch s {
	case StatusOK:
		return 0
	case StatusAddressNotHonored:
		return 1
	case StatusPending:
		return 2
	case StatusRateLimited:
		return 3
	case StatusUpstreamRefused:
		return 4
	case StatusOverCap:
		return 5
	case StatusOutsideBound:
		return 6
	case StatusBadAddress:
		return 7
	case StatusUnsupported:
		return 8
	case StatusUnserved:
		return 9
	case StatusNotServed:
		return 10
	}
	return 11
}

// reaggregate recomputes the outcome for a wanted topic across upstreams
// and queues an event if it changed.
func (c *Client) reaggregate(id TopicID) {
	w := c.want[id]
	if w == nil {
		return
	}
	// An upstream that has stopped answering serves nothing now, and what
	// it might say is not waited for while another answers: otherwise a
	// standby that holds no record of this sender would keep every topic
	// the others refuse at pending, and the sender would never learn that
	// nothing comes. Unless all have stopped.
	anyUp := false
	for _, u := range c.ups {
		if !u.down() {
			anyUp = true
			break
		}
	}
	best := StatusNotServed
	first := true
	for _, u := range c.ups {
		if anyUp && u.down() {
			continue
		}
		st := StatusNotServed
		if t := u.topics[id]; t != nil && t.want {
			st = t.status
		}
		if first || statusRank(st) < statusRank(best) {
			best, first = st, false
		}
	}
	if best.Served() || best == StatusPending {
		delete(c.noted, id)
	} else {
		c.noted[id] = best
	}
	if best != w.agg {
		w.agg = best
		if c.cfg.OnStatus != nil {
			c.events = append(c.events, statusEvent{id, best})
		}
	}
}

// reaggregateAll recomputes every wanted topic's status, after an upstream
// stopped answering or answered again.
func (c *Client) reaggregateAll() {
	for id := range c.want {
		c.reaggregate(id)
	}
}

// down reports that the upstream has stopped answering: three timeouts in
// a row, and nothing heard since. One that has not answered yet is not down.
func (u *upstream) down() bool { return !u.reachable && u.timeouts >= 3 }

// flush delivers queued callbacks in order, one at a time. A callback that
// calls the client queues more, and the flush already under way delivers
// them once the callback returns, so a nested call never waits for itself.
func (c *Client) flush() {
	if c.cfg.OnStatus == nil && c.cfg.OnScope == nil {
		return
	}
	c.mu.Lock()
	if c.flushing {
		c.mu.Unlock()
		return
	}
	c.flushing = true
	finished := false
	defer func() {
		if !finished {
			// A callback panicked. The next flush delivers the rest.
			c.mu.Lock()
			c.flushing = false
			c.mu.Unlock()
		}
	}()
	for {
		ev, scoped := c.events, c.scoped
		c.events, c.scoped = nil, false
		if len(ev) == 0 && !scoped {
			c.flushing = false
			finished = true
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		if scoped && c.cfg.OnScope != nil {
			c.cfg.OnScope()
		}
		for _, e := range ev {
			c.cfg.OnStatus(e.topic, e.status)
		}
		c.mu.Lock()
	}
}

func (c *Client) refreshInterval(u *upstream) int64 {
	req := c.cfg.Lifetime
	if req == 0 {
		req = LifetimeDefault
	}
	d := int64(u.life.Grant(req)) * int64(time.Second) / 3
	if d < int64(time.Second) {
		d = int64(time.Second)
	}
	return d
}

// beginSync starts a full replay toward an upstream: everything wanted is
// said again, and the digest that follows sweeps whatever the upstream
// holds that was not.
func (c *Client) beginSync(u *upstream, now int64) {
	u.stats.Syncs++
	u.phase = phaseSync
	u.lastSync = now
	u.needSync = false
	u.digestDue = false
	u.since = u.nextSeq
	u.inflight = make(map[uint64]*batch)
	u.probing = false
	u.queue = u.queue[:0]
	u.later = u.later[:0]
	u.heldCount = 0
	u.heldDigest = SetDigest{}
	for id, t := range u.topics {
		if !t.want {
			delete(u.topics, id)
			continue
		}
		t.held = false
		t.unsure = false
		t.sentSeq = 0
		t.queued = false
		t.notBefore = 0
		c.bump(u, id, t, true)
	}
}

// rescope applies a changed scope: topics the upstream no longer serves are
// withdrawn from it, and topics it now serves are announced.
func (c *Client) rescope(u *upstream) {
	for id, w := range c.want {
		ok := u.scope == nil || u.scope.Contains(id)
		c.setTarget(u, id, ok, w.ext)
		if t := u.topics[id]; ok && t != nil && t.want && t.status == StatusNotServed {
			t.status = StatusPending
			c.bump(u, id, t, false)
		}
		c.reaggregate(id)
	}
}

// Handle processes one datagram from an upstream.
func (c *Client) Handle(src netip.AddrPort, pkt []byte, now time.Time) {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	h, err := DecodeHeader(pkt)
	if err != nil {
		return
	}
	nowNS := now.UnixNano()
	c.mu.Lock()
	var u *upstream
	for _, x := range c.ups {
		if x.addr == src {
			u = x
			break
		}
	}
	switch {
	case u == nil:
	case h.Type == MsgResync:
		if h.SenderID == 0 || h.SenderID == c.cfg.SenderID {
			c.poke(u, nowNS)
		}
	case h.Type == MsgAck && h.SenderID == c.cfg.SenderID:
		if a, err := DecodeAck(pkt); err == nil {
			c.handleAck(u, a, nowNS)
		} else {
			u.stats.Ignored++
		}
	default:
		u.stats.Ignored++
	}
	c.mu.Unlock()
	c.signal()
	c.flush()
}

func (c *Client) handleAck(u *upstream, a *Ack, now int64) {
	b := u.inflight[a.Seq]
	if b == nil {
		// Late, duplicated, or not ours. Whatever it answered has been
		// said again or will be.
		u.stats.Ignored++
		return
	}
	delete(u.inflight, a.Seq)
	u.stats.Acks++
	c.measure(u, time.Duration(now-b.sentAt))
	wasDown := u.down()
	u.timeouts = 0
	u.reachable = true
	if wasDown {
		c.reaggregateAll()
	}

	switch a.Result {
	case ResultVersion:
		// The upstream speaks another version. Nothing can be said to it;
		// keep asking slowly in case it is replaced.
		c.requeue(u, b)
		u.pausedUntil = now + int64(maxSyncBackoff)
		return
	case ResultToken:
		// The upstream holds nothing it trusts for us: first contact, a
		// restart on its side, or a change of our address. Replay.
		u.stats.Tokens++
		u.token = a.Token
		u.probing = false
		u.scoped = false
		c.requeue(u, b)
		c.scheduleSync(u, now)
		return
	}

	// Every other result carries a body.
	if a.Token != 0 && a.Token != u.token {
		u.token = a.Token
	}
	if a.LifetimeMin > 0 && a.LifetimeMin <= a.LifetimeDefault && a.LifetimeDefault <= a.LifetimeMax {
		u.life = Lifetimes{a.LifetimeMin, a.LifetimeDefault, a.LifetimeMax}
	}
	c.learnScope(u, a, b)
	if b.probe {
		// Sent only to learn the scope, which is done.
		u.probing = false
		return
	}

	switch a.Result {
	case ResultStale:
		// The upstream has applied a sequence number at or past ours: a
		// later datagram overtook this one, or this sender started below
		// where an earlier run left off. Move past it.
		u.stats.Stale++
		if !SeqNewer(u.nextSeq, a.LastSeq) {
			u.nextSeq = seqAfter(a.LastSeq)
			if u.phase == phaseSync {
				// Started below an earlier run, so nothing this replay
				// sent was applied. Its sweep counts from where it can be.
				u.since = u.nextSeq
			}
		}
		c.requeue(u, b)
		return
	case ResultBusy, ResultHopLimit:
		u.stats.Busy++
		c.requeue(u, b)
		u.pausedUntil = now + int64(c.cfg.RTOMax)
		return
	}

	if b.digest {
		c.handleDigestAck(u, a, b, now)
		return
	}
	if a.Result != ResultOK {
		c.requeue(u, b)
		return
	}

	statuses := make(map[uint16]Status, len(a.Statuses))
	for _, s := range a.Statuses {
		statuses[s.Index] = s.Status
	}
	for i, id := range b.topics {
		t := u.topics[id]
		if t == nil {
			continue
		}
		if t.sentSeq == b.seq {
			t.sentSeq = 0
		}
		st := statuses[uint16(i)]
		if t.heldSeq == 0 || SeqNewer(b.seq, t.heldSeq) {
			t.heldSeq = b.seq
			t.unsure = false
			if b.adds[i] {
				c.setHeld(u, id, t, st.Held())
				if t.want {
					t.status = st
				}
			} else {
				c.setHeld(u, id, t, false)
			}
		}
		if b.vers[i] == t.ver {
			t.ackVer = t.ver
			if b.adds[i] && st == StatusRateLimited && t.want {
				// Refused for now. Say it again shortly.
				t.notBefore = now + int64(rateLimitRetry)
				c.bump(u, id, t, true)
			}
		}
		if !t.want && !t.held && t.sentSeq == 0 && t.ackVer == t.ver {
			delete(u.topics, id)
		}
		c.reaggregate(id)
	}
	c.applyNotices(u, a, false)

	// With nothing in flight and nothing waiting, the upstream's set must
	// be the one we believe it holds. If it is not, something was lost in
	// a way the acknowledgments did not show: replay.
	if u.phase == phaseSynced && len(u.inflight) == 0 && len(u.queue) == 0 && len(u.later) == 0 &&
		a.Seq == u.lastSent && (a.SetCount != u.heldCount || a.SetDigest != u.heldDigest) {
		u.stats.Mismatches++
		c.scheduleSync(u, now)
	}
}

func (c *Client) handleDigestAck(u *upstream, a *Ack, b *batch, now int64) {
	switch {
	case u.phase == phaseHello:
		// A probe is only ever answered with a token, handled above. An
		// upstream that accepts a zero token is not following the
		// protocol; treat its answer as a reason to replay.
		c.beginSync(u, now)
	case a.Result == ResultOK && u.phase == phaseSync && b.since != 0:
		u.phase = phaseSynced
		u.digestDue = u.askScope
		u.nextRefresh = now + c.refreshInterval(u)
		c.applyNotices(u, a, true)
	case a.Result == ResultOK:
		// If the answer showed that the scope changed, the next digest
		// goes at once, to ask for it.
		u.digestDue = u.askScope
		u.nextRefresh = now + c.refreshInterval(u)
		u.queue = append(u.queue, u.later...)
		u.later = u.later[:0]
		c.applyNotices(u, a, true)
		// What was refused may be allowed by now. Ask again once per
		// refresh. A topic outside the scope is asked again only when the
		// scope changes.
		for id, t := range u.topics {
			if t.want && !t.held && t.status.Refused() && t.status != StatusNotServed && t.sentSeq == 0 {
				c.bump(u, id, t, false)
			}
		}
	default:
		u.stats.Mismatches++
		u.digestDue = false
		u.queue = append(u.queue, u.later...)
		u.later = u.later[:0]
		c.scheduleSync(u, now)
	}
}

// scheduleSync asks for a replay, at once the first time and with a growing
// wait when replays keep being needed.
func (c *Client) scheduleSync(u *upstream, now int64) {
	if u.needSync {
		return
	}
	u.needSync = true
	u.nextSyncAt = now
	if now-u.lastSync > int64(maxSyncBackoff) {
		// The last replay was long ago. This one is not part of a streak.
		u.syncBackoff = time.Second
	}
	if u.lastSync != 0 {
		if at := u.lastSync + int64(u.syncBackoff); at > now {
			u.nextSyncAt = at
		}
		if u.syncBackoff *= 2; u.syncBackoff > maxSyncBackoff {
			u.syncBackoff = maxSyncBackoff
		}
	}
}

// learnScope tracks the upstream's delivered scope from an ACK body.
func (c *Client) learnScope(u *upstream, a *Ack, b *batch) {
	u.scoped = true
	if a.ScopeGen == u.scopeGen {
		u.askScope = false
		return
	}
	var sc *Scope
	found := false
	if len(a.Ext) > 0 {
		if tlvs, err := ParseTLVs(a.Ext); err == nil {
			if v, ok := FindTLV(tlvs, ExtScope); ok {
				if p, err := ParseScope(v); err == nil {
					sc, found = p, true
				}
			}
		}
	}
	switch {
	case found:
	case b.asked:
		// Asked on a message whose answer had room, and none came: the
		// upstream has no scope, or one too large to advertise. Either
		// way nothing is known, and statuses say what is not served.
	default:
		// Ask with the next digest, and send one soon.
		u.askScope = true
		if u.phase == phaseSynced {
			u.digestDue = true
		}
		return
	}
	u.scope = sc
	u.scopeGen = a.ScopeGen
	u.askScope = false
	c.scoped = true
	c.rescope(u)
}

// applyNotices takes the notes an answer carries. A digest's answer that
// is not truncated lists every note the upstream holds for this sender, so
// a relay's note (unserved, refused further up) that it no longer lists
// has been lifted: the topic is served again. Only a relay gives those two
// notes, and it gives them only this way.
func (c *Client) applyNotices(u *upstream, a *Ack, complete bool) {
	var ns []Notice
	if len(a.Ext) > 0 {
		if tlvs, err := ParseTLVs(a.Ext); err == nil {
			if v, ok := FindTLV(tlvs, ExtNotice); ok {
				ns, _ = ParseNotices(v)
			}
		}
	}
	listed := make(map[TopicID]bool, len(ns))
	for _, n := range ns {
		listed[n.Topic] = true
		t := u.topics[n.Topic]
		if t == nil || !t.want || !t.held || !n.Status.Held() {
			continue
		}
		t.status = n.Status
		c.reaggregate(n.Topic)
	}
	if !complete || a.Flags&FlagNoticesTruncated != 0 {
		return
	}
	for id, t := range u.topics {
		if t.want && t.held && (t.status == StatusUnserved || t.status == StatusUpstreamRefused) && !listed[id] {
			t.status = StatusOK
			c.reaggregate(id)
		}
	}
}

// measure folds one round-trip time into the wait for an acknowledgment,
// as TCP does (RFC 6298). Every sample is clean: a datagram is never sent
// twice under one sequence number, so an answer always belongs to the
// datagram it names.
func (c *Client) measure(u *upstream, rtt time.Duration) {
	if rtt < 0 {
		rtt = 0
	}
	if u.srtt == 0 && u.rttvar == 0 {
		u.srtt = rtt
		u.rttvar = rtt / 2
	} else {
		d := u.srtt - rtt
		if d < 0 {
			d = -d
		}
		u.rttvar = (3*u.rttvar + d) / 4
		u.srtt = (7*u.srtt + rtt) / 8
	}
	u.rto = c.clampRTO(u.srtt + 4*u.rttvar)
}

func (c *Client) clampRTO(d time.Duration) time.Duration {
	return min(max(d, c.cfg.RTOMin), c.cfg.RTOMax)
}

// requeue puts back what an unanswered or unapplied datagram carried.
func (c *Client) requeue(u *upstream, b *batch) {
	for i, id := range b.topics {
		t := u.topics[id]
		if t == nil {
			continue
		}
		if t.sentSeq == b.seq {
			t.sentSeq = 0
		}
		if b.vers[i] == t.ver && t.ver != t.ackVer {
			c.enqueue(u, id, t, true)
		}
	}
}

// Poll returns the datagrams to send now and the time by which Poll must be
// called again. It must also be called after every Handle and whenever the
// channel from Wake receives.
func (c *Client) Poll(now time.Time) ([]Datagram, time.Time) {
	nowNS := now.UnixNano()
	var out []Datagram
	next := int64(1<<63 - 1)
	c.mu.Lock()
	if c.holdTo == 0 {
		c.holdTo = nowNS + int64(c.cfg.SweepHold)
	}
	for _, u := range c.ups {
		if n := c.pollUpstream(u, nowNS, &out); n < next {
			next = n
		}
	}
	c.mu.Unlock()
	c.flush()
	return out, time.Unix(0, next)
}

func (c *Client) pollUpstream(u *upstream, now int64, out *[]Datagram) int64 {
	if u.nextSeq == 0 {
		if u.nextSeq = uint64(now); u.nextSeq == 0 {
			u.nextSeq = 1
		}
	}
	// What has waited a full timeout is lost.
	lost := false
	for seq, b := range u.inflight {
		if b.sentAt+int64(u.rto) <= now {
			u.stats.Timeouts++
			lost = true
			c.lose(u, seq, b)
		}
	}
	if lost {
		u.timeouts++
		if u.timeouts >= 3 {
			u.reachable = false
		}
		if u.timeouts == 3 {
			c.reaggregateAll()
		}
		if u.rto *= 2; u.rto > c.cfg.RTOMax {
			u.rto = c.cfg.RTOMax
		}
	}
	next := int64(1<<63 - 1)
	earlier := func(t int64) {
		if t < next {
			next = t
		}
	}
	u.holding = false
	if now < u.pausedUntil {
		return u.pausedUntil
	}

	if u.token == 0 {
		// First contact: a probe that carries nothing, answered with the
		// token.
		u.phase = phaseHello
		if len(u.inflight) == 0 {
			c.sendDigest(u, now, 0, 0, SetDigest{}, out)
		}
	} else {
		if u.needSync {
			if now >= u.nextSyncAt {
				c.beginSync(u, now)
			} else {
				earlier(u.nextSyncAt)
			}
		}
		if u.phase == phaseSynced && !u.digestDue {
			if now >= u.nextRefresh {
				u.digestDue = true
			} else {
				earlier(u.nextRefresh)
			}
		}
		for len(u.inflight) < c.cfg.Window {
			sent, wait := c.sendAnnounce(u, now, out)
			if wait > 0 {
				earlier(wait)
			}
			if !sent {
				break
			}
		}
		// The first replay of a sender that is still learning its set is
		// not swept yet, though never so late that what the replay said
		// expires upstream before the sweep refreshes it.
		holdTo := c.holdTo
		if end := u.lastSync + 2*c.refreshInterval(u); end < holdTo {
			holdTo = end
		}
		held := u.phase == phaseSync && u.stats.Syncs <= 1 && now < holdTo
		if held {
			earlier(holdTo)
		}
		// The scope normally arrives with an answer that has room for it.
		// During a replay that can be a while off, or never come if there
		// is nothing to say yet, and a relay needs the scope early, to
		// refuse what is not served instead of passing it on. So ask with
		// a digest of its own, whose result is ignored.
		if u.phase == phaseSync && (u.askScope || !u.scoped) && !u.probing && !u.needSync && len(u.inflight) < c.cfg.Window {
			c.sendProbe(u, now, out)
		}
		u.holding = held && !u.needSync && len(u.inflight) == 0 && !c.ready(u, now)
		// A digest is exact only when nothing is in flight and nothing
		// more is ready to be said.
		if (u.phase == phaseSync || u.digestDue) && !held && !u.needSync && len(u.inflight) == 0 && !c.ready(u, now) {
			since := uint64(0)
			if u.phase == phaseSync {
				since = u.since
			}
			c.sendDigest(u, now, since, u.heldCount, u.heldDigest, out)
		}
	}
	for _, b := range u.inflight {
		earlier(b.sentAt + int64(u.rto))
	}
	return next
}

// ready reports whether any queued topic can be sent now.
func (c *Client) ready(u *upstream, now int64) bool {
	for _, id := range u.queue {
		t := u.topics[id]
		if t != nil && t.ver != t.ackVer && (t.sentSeq == 0 || t.sentVer != t.ver) && t.notBefore <= now {
			return true
		}
	}
	return false
}

// sendAnnounce sends one datagram of queued topics. It reports whether it
// sent, and the earliest time a held-back topic becomes ready, if any.
func (c *Client) sendAnnounce(u *upstream, now int64, out *[]Datagram) (bool, int64) {
	var m Announce
	b := &batch{}
	size := HeaderSize
	var held []TopicID
	wait := int64(0)
	n := 0
	for ; n < len(u.queue); n++ {
		id := u.queue[n]
		t := u.topics[id]
		if t == nil {
			continue
		}
		if t.ver == t.ackVer || (t.sentSeq != 0 && t.sentVer == t.ver) {
			t.queued = false
			continue
		}
		if t.notBefore > now {
			held = append(held, id)
			if wait == 0 || t.notBefore < wait {
				wait = t.notBefore
			}
			continue
		}
		add := t.want
		rec := Record{Topic: id}
		if add {
			rec.Lifetime = c.cfg.Lifetime
			if rec.Lifetime == 0 {
				rec.Lifetime = LifetimeDefault
			}
			rec.Ext = t.ext
		}
		if size+rec.size() > MaxDatagram {
			if len(m.Records) > 0 {
				break
			}
			// A record too large for any datagram can never be sent, so
			// the topic is refused here. What the upstream may hold under
			// what was said before is withdrawn.
			t.status = StatusUnsupported
			c.reaggregate(id)
			if !t.held && !t.unsure {
				t.queued = false
				t.ackVer = t.ver
				continue
			}
			add, rec = false, Record{Topic: id}
		}
		size += rec.size()
		t.queued = false
		m.Records = append(m.Records, rec)
		b.topics = append(b.topics, id)
		b.vers = append(b.vers, t.ver)
		b.adds = append(b.adds, add)
	}
	u.queue = append(held, u.queue[n:]...)
	if len(m.Records) == 0 {
		return false, wait
	}
	b.seq = c.takeSeq(u)
	b.sentAt = now
	m.Header = Header{Version: Version, Hops: c.hops, SenderID: c.cfg.SenderID, Token: u.token, Seq: b.seq}
	if u.phase == phaseSync {
		m.Flags |= FlagSync
	}
	// Ask for the scope here too. The answer carries it when there is
	// room; when there is not, nothing is concluded and a digest asks.
	if u.askScope || u.scopeGen == 0 {
		m.Flags |= FlagScopeWanted
	}
	data, err := m.Append(nil)
	if err != nil {
		// Sized above; cannot happen.
		return false, wait
	}
	for _, id := range b.topics {
		t := u.topics[id]
		t.sentVer = t.ver
		t.sentSeq = b.seq
	}
	u.inflight[b.seq] = b
	u.stats.Announces++
	*out = append(*out, Datagram{Addr: u.addr, Data: data})
	return true, wait
}

// sendProbe sends a digest whose only purpose is to carry the request for
// the scope. It is marked as a probe, so the upstream compares nothing.
func (c *Client) sendProbe(u *upstream, now int64, out *[]Datagram) {
	b := &batch{seq: c.takeSeq(u), sentAt: now, digest: true, asked: true, probe: true}
	m := Digest{
		Header: Header{Version: Version, Flags: FlagScopeWanted | FlagProbe, Hops: c.hops, SenderID: c.cfg.SenderID, Token: u.token, Seq: b.seq},
	}
	data, _ := m.Append(nil)
	u.inflight[b.seq] = b
	u.probing = true
	u.stats.Digests++
	*out = append(*out, Datagram{Addr: u.addr, Data: data})
}

func (c *Client) sendDigest(u *upstream, now int64, since uint64, count uint32, digest SetDigest, out *[]Datagram) {
	b := &batch{seq: c.takeSeq(u), sentAt: now, digest: true, since: since}
	m := Digest{
		Header:    Header{Version: Version, Hops: c.hops, SenderID: c.cfg.SenderID, Token: u.token, Seq: b.seq},
		Since:     since,
		SetCount:  count,
		SetDigest: digest,
	}
	// The scope is asked for on a digest, whose answer has room for it.
	if u.askScope || u.scopeGen == 0 {
		m.Flags |= FlagScopeWanted
		b.asked = true
	}
	data, _ := m.Append(nil)
	u.inflight[b.seq] = b
	u.stats.Digests++
	*out = append(*out, Datagram{Addr: u.addr, Data: data})
}
