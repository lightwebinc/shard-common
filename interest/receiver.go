package interest

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Lifetimes are the bounds an upstream puts on how long it holds an
// interest without hearing from the sender, in seconds.
type Lifetimes struct {
	Min     uint32
	Default uint32
	Max     uint32
}

// DefaultLifetimes are the lifetimes a receiver enforces unless configured
// otherwise. A sender refreshes at a third of the lifetime it was granted,
// so three refreshes may be lost before an interest lapses.
var DefaultLifetimes = Lifetimes{Min: 30, Default: 300, Max: 3600}

// Grant returns the lifetime granted for a requested one.
func (l Lifetimes) Grant(requested uint32) uint32 {
	switch {
	case requested == LifetimeDefault:
		return l.Default
	case requested < l.Min:
		return l.Min
	case requested > l.Max:
		return l.Max
	}
	return requested
}

func (l Lifetimes) valid() bool {
	return l.Min > 0 && l.Min <= l.Default && l.Default <= l.Max
}

// DefaultMaxHops is the number of relays a message may have crossed.
const DefaultMaxHops = 16

// Bound is how a principal's bound treats one topic.
type Bound byte

const (
	// BoundFree: allowed, and not counted against the quota.
	BoundFree Bound = iota
	// BoundQuota: allowed while the principal has quota left.
	BoundQuota
	// BoundDenied: not allowed.
	BoundDenied
)

// Policy is what a [Receiver] asks of its owner. A principal is whoever the
// bound belongs to: a consumer at a delivery edge, a class of hosts at a
// relay. Several senders may share one principal, and the principal's live
// set is the union of theirs.
//
// A policy is called with the receiver's lock held and must not call back
// into the receiver.
type Policy interface {
	// Identify names the principal a source address belongs to. A source it
	// does not know is ignored without an answer.
	Identify(src netip.AddrPort) (principal string, ok bool)
	// Scope is the set of groups delivered to the principal, or nil when
	// that is unknown or unrestricted and need not be advertised.
	Scope(principal string) *Scope
	// Bound classifies a topic for the principal.
	Bound(principal string, topic TopicID) Bound
	// Quota is how many [BoundQuota] topics the principal may have live at
	// once. Negative means no limit.
	Quota(principal string) int
}

// Noter is an optional interface of a [Policy] for topics that are held but
// carry a note, as at a relay whose upstream does not serve them.
type Noter interface {
	// Note returns [StatusOK] or a note for a topic the receiver holds.
	Note(principal string, topic TopicID) Status
	// Notes calls each for every topic that currently carries a note, until
	// each returns false.
	Notes(principal string, each func(TopicID, Status) bool)
}

// ReceiverConfig configures a [Receiver].
type ReceiverConfig struct {
	// Policy is required.
	Policy Policy
	// Lifetimes default to [DefaultLifetimes].
	Lifetimes Lifetimes
	// Secret keys the tokens. A receiver with a new secret holds nothing
	// its senders trust, which is what makes a restart visible to them, so
	// it is random unless set. Set it only to share one identity between
	// processes that share state.
	Secret []byte
	// MaxHops defaults to [DefaultMaxHops].
	MaxHops uint8
	// MaxTopicsPerSender caps the topics held for one sender. Zero is no
	// cap.
	MaxTopicsPerSender int
	// MaxSenders caps the senders tracked at once. Zero is no cap.
	MaxSenders int
	// MaxSendersPerPrincipal caps the senders tracked for one principal, so
	// that one principal cannot use up the receiver. Zero is no cap.
	MaxSendersPerPrincipal int
	// ChangeRate and ChangeBurst limit how fast one sender may add topics
	// it does not already hold: a token bucket, in topics per second. A
	// zero rate is no limit.
	ChangeRate  float64
	ChangeBurst int
	// SenderIdle is how long a sender with no topics is remembered, so that
	// an old datagram of its cannot be replayed. It defaults to the maximum
	// lifetime.
	SenderIdle time.Duration
	// OnChange is called when a topic becomes live for a principal, or
	// stops being live. Calls arrive in order, one at a time, without the
	// receiver's lock held.
	OnChange func(principal string, topic TopicID, live bool)
}

// ReceiverStats counts what a receiver has seen and done.
type ReceiverStats struct {
	Datagrams     uint64 // every datagram offered
	Malformed     uint64 // not an interest message, or inconsistent
	Unidentified  uint64 // from a source the policy does not know
	TokensIssued  uint64 // answered with a token instead of applied
	WrongVersion  uint64
	Stale         uint64
	HopLimited    uint64
	Busy          uint64
	Announces     uint64 // applied
	Digests       uint64 // matched
	Probes        uint64 // digests that only asked
	Mismatches    uint64 // digests that did not match
	Sweeps        uint64 // topics removed at the end of a replay
	Adds          uint64 // topics newly held for a sender
	Refreshes     uint64 // topics announced again while held
	Withdrawals   uint64
	Expiries      uint64
	Reevaluated   uint64 // topics dropped because the bound or scope changed
	Refused       map[Status]uint64
	Senders       int // tracked now
	Topics        int // held now, summed over senders
	LiveTopics    int // live now, summed over principals
	ResyncsQueued uint64
}

type senderKey struct {
	addr netip.Addr
	id   uint64
}

type entry struct {
	setAt    int64 // unix nanoseconds
	setSeq   uint64
	lifetime uint32 // granted, seconds
}

type session struct {
	key       senderKey
	principal string
	addr      netip.AddrPort
	lastSeq   uint64
	seen      bool // lastSeq holds a sequence number
	hops      uint8
	heard     int64
	entries   map[TopicID]entry
	digest    SetDigest
	refreshed int64 // every entry counts as set no earlier than this
	nextScan  int64 // nothing expires before this
	minLife   uint32
	tokens    float64
	tokensAt  int64
	poke      bool
}

type liveEntry struct {
	refs    uint32
	metered bool
	since   int64
}

type principalState struct {
	live    map[TopicID]*liveEntry
	metered int
}

// PrincipalStats is what a receiver holds and has done for one principal.
// It exists while the principal has at least one sender.
type PrincipalStats struct {
	Principal   string
	Senders     int    // tracked now
	Held        int    // topics held now, summed over its senders
	Live        int    // distinct topics live now
	Metered     int    // of those, how many count against the quota
	Adds        uint64 // topics that became held for a sender
	Withdrawals uint64
	Expiries    uint64
	Dropped     uint64 // swept at the end of a replay, or dropped by a re-evaluation
	Refused     map[Status]uint64
}

type principalCounters struct {
	held                                 int
	adds, withdrawals, expiries, dropped uint64
	refused                              map[Status]uint64
}

type change struct {
	principal string
	topic     TopicID
	live      bool
}

// Datagram is a message to send.
type Datagram struct {
	Addr netip.AddrPort
	Data []byte
}

// Receiver is the upstream half of the protocol: it holds, per sender, the
// topics announced to it, keeps them as soft state, and reports the union
// per principal. A delivery edge is a Receiver; so is the downstream side
// of a relay.
//
// It does no I/O and reads no clock. It is safe for concurrent use.
type Receiver struct {
	cfg    ReceiverConfig
	noter  Noter
	secret []byte

	mu         sync.Mutex
	sessions   map[senderKey]*session
	senders    map[string]int // sessions per principal
	principals map[string]*principalState
	counters   map[string]*principalCounters // while the principal has a sender
	events     []change
	stats      ReceiverStats

	cbMu sync.Mutex
}

// NewReceiver builds a receiver. It panics if the configuration has no
// policy or inconsistent lifetimes, which are programming errors.
func NewReceiver(cfg ReceiverConfig) *Receiver {
	if cfg.Policy == nil {
		panic("interest: receiver without a policy")
	}
	if cfg.Lifetimes == (Lifetimes{}) {
		cfg.Lifetimes = DefaultLifetimes
	}
	if !cfg.Lifetimes.valid() {
		panic("interest: receiver lifetimes must satisfy 0 < min <= default <= max")
	}
	if cfg.MaxHops == 0 {
		cfg.MaxHops = DefaultMaxHops
	}
	if cfg.SenderIdle <= 0 {
		cfg.SenderIdle = time.Duration(cfg.Lifetimes.Max) * time.Second
	}
	if cfg.ChangeRate > 0 && cfg.ChangeBurst <= 0 {
		cfg.ChangeBurst = int(cfg.ChangeRate) + 1
	}
	r := &Receiver{
		cfg:        cfg,
		secret:     cfg.Secret,
		sessions:   make(map[senderKey]*session),
		senders:    make(map[string]int),
		principals: make(map[string]*principalState),
		counters:   make(map[string]*principalCounters),
	}
	r.noter, _ = cfg.Policy.(Noter)
	if len(r.secret) == 0 {
		r.secret = make([]byte, 32)
		if _, err := rand.Read(r.secret); err != nil {
			panic("interest: no randomness for the token secret: " + err.Error())
		}
	}
	r.stats.Refused = make(map[Status]uint64)
	return r
}

// token is what this receiver issues to a sender at a source address: a
// keyed hash of both, so it needs no state, cannot be guessed by a party
// that cannot receive at the address, and changes with the secret.
func (r *Receiver) token(src netip.AddrPort, senderID uint64) uint64 {
	var m [26]byte
	a := src.Addr().As16()
	copy(m[0:16], a[:])
	binary.BigEndian.PutUint16(m[16:18], src.Port())
	binary.BigEndian.PutUint64(m[18:26], senderID)
	mac := hmac.New(sha256.New, r.secret)
	mac.Write(m[:])
	t := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	if t == 0 {
		t = 1
	}
	return t
}

// Handle processes one datagram and returns the answer to send to src, or
// nil when there is none. The answer is a new slice.
func (r *Receiver) Handle(src netip.AddrPort, pkt []byte, now time.Time) []byte {
	out := r.handle(src, pkt, now)
	r.flush()
	return out
}

func (r *Receiver) handle(src netip.AddrPort, pkt []byte, now time.Time) []byte {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	h, err := DecodeHeader(pkt)
	if err != nil || h.SenderID == 0 || (h.Type != MsgAnnounce && h.Type != MsgDigest) {
		r.count(func(s *ReceiverStats) { s.Datagrams++; s.Malformed++ })
		return nil
	}
	principal, ok := r.cfg.Policy.Identify(src)
	if !ok {
		r.count(func(s *ReceiverStats) { s.Datagrams++; s.Unidentified++ })
		return nil
	}
	if h.Version != Version {
		r.count(func(s *ReceiverStats) { s.Datagrams++; s.WrongVersion++ })
		a := Ack{Header: Header{Version: Version, Result: ResultVersion, SenderID: h.SenderID, Seq: h.Seq}}
		b, _ := a.Append(nil)
		return b
	}
	tok := r.token(src, h.SenderID)
	if h.Token != tok {
		r.count(func(s *ReceiverStats) { s.Datagrams++; s.TokensIssued++ })
		a := Ack{Header: Header{Version: Version, Result: ResultToken, SenderID: h.SenderID, Token: tok, Seq: h.Seq}}
		b, _ := a.Append(nil)
		return b
	}

	// Decode in full before touching any state, so a malformed message
	// changes nothing and consumes no sequence number.
	var ann *Announce
	var dig *Digest
	if h.Type == MsgAnnounce {
		ann, err = DecodeAnnounce(pkt)
	} else {
		dig, err = DecodeDigest(pkt)
	}
	if err != nil {
		r.count(func(s *ReceiverStats) { s.Datagrams++; s.Malformed++ })
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.Datagrams++
	nowNS := now.UnixNano()

	s := r.sessions[senderKey{src.Addr(), h.SenderID}]
	if s != nil && s.principal != principal {
		// The address now belongs to another principal. What it held was
		// held for the old one.
		r.dropSession(s)
		s = nil
	}
	if s == nil {
		if (r.cfg.MaxSenders > 0 && len(r.sessions) >= r.cfg.MaxSenders) ||
			(r.cfg.MaxSendersPerPrincipal > 0 && r.senders[principal] >= r.cfg.MaxSendersPerPrincipal) {
			r.stats.Busy++
			return r.ack(&h, tok, ResultBusy, nil, principal, nil, false)
		}
		s = &session{
			key:       senderKey{src.Addr(), h.SenderID},
			principal: principal,
			entries:   make(map[TopicID]entry),
			tokens:    float64(r.cfg.ChangeBurst),
			tokensAt:  nowNS,
			nextScan:  1<<63 - 1,
		}
		r.sessions[s.key] = s
		r.senders[principal]++
		if r.counters[principal] == nil {
			r.counters[principal] = &principalCounters{refused: make(map[Status]uint64)}
		}
	}
	s.addr = src
	s.heard = nowNS

	if h.Hops > r.cfg.MaxHops {
		r.stats.HopLimited++
		return r.ack(&h, tok, ResultHopLimit, s, principal, nil, false)
	}
	if s.seen && !SeqNewer(h.Seq, s.lastSeq) {
		r.stats.Stale++
		return r.ack(&h, tok, ResultStale, s, principal, nil, false)
	}
	s.lastSeq = h.Seq
	s.seen = true
	s.hops = h.Hops

	if ann != nil {
		r.stats.Announces++
		var statuses []RecordStatus
		var defaultDelivery bool
		if len(ann.Ext) > 0 {
			if tlvs, err := ParseTLVs(ann.Ext); err == nil {
				_, defaultDelivery = FindTLV(tlvs, ExtDelivery)
			}
		}
		for i := range ann.Records {
			st := r.apply(s, &ann.Records[i], h.Seq, nowNS, defaultDelivery)
			if st != StatusOK {
				statuses = append(statuses, RecordStatus{Index: uint16(i), Status: st})
				if st.Refused() {
					r.stats.Refused[st]++
					r.counters[principal].refused[st]++
				}
			}
		}
		return r.ack(&h, tok, ResultOK, s, principal, statuses, false)
	}

	if dig.Flags&FlagProbe != 0 {
		// A question, not a claim about the set.
		r.stats.Probes++
		return r.ack(&h, tok, ResultOK, s, principal, nil, false)
	}
	res := ResultMismatch
	if dig.Since == 0 {
		if uint32(len(s.entries)) == dig.SetCount && s.digest == dig.SetDigest {
			res = ResultOK
		}
	} else {
		var n uint32
		var d SetDigest
		for t, e := range s.entries {
			if !SeqNewer(dig.Since, e.setSeq) {
				n++
				d.Toggle(t)
			}
		}
		if n == dig.SetCount && d == dig.SetDigest {
			res = ResultOK
			for t, e := range s.entries {
				if SeqNewer(dig.Since, e.setSeq) {
					r.remove(s, t)
					r.stats.Sweeps++
					r.counters[principal].dropped++
				}
			}
		}
	}
	if res == ResultOK {
		// A matching digest proves both ends hold the same set, so it
		// refreshes every entry at once.
		r.stats.Digests++
		s.refreshed = nowNS
		if len(s.entries) > 0 {
			s.nextScan = nowNS + int64(s.minLife)*int64(time.Second)
		}
	} else {
		r.stats.Mismatches++
	}
	return r.ack(&h, tok, res, s, principal, nil, true)
}

// apply applies one record to a sender's set and returns its status.
func (r *Receiver) apply(s *session, rec *Record, seq uint64, now int64, defaultDelivery bool) Status {
	_, held := s.entries[rec.Topic]
	if rec.Lifetime == LifetimeWithdraw {
		if held {
			r.remove(s, rec.Topic)
			r.stats.Withdrawals++
			r.counters[s.principal].withdrawals++
		}
		return StatusOK
	}
	delivery := defaultDelivery
	if len(rec.Ext) > 0 {
		tlvs, err := ParseTLVs(rec.Ext)
		if err != nil {
			if held {
				r.remove(s, rec.Topic)
			}
			return StatusUnsupported
		}
		for _, t := range tlvs {
			switch {
			case t.Type == ExtDelivery:
				delivery = true
			case t.Type&ExtCritical != 0:
				if held {
					r.remove(s, rec.Topic)
				}
				return StatusUnsupported
			}
		}
	}
	// Scope first: a topic this path does not deliver is not processed at
	// all, so it is never charged against a bound, a cap or a rate.
	st, metered := r.judge(s.principal, rec.Topic)
	if st != StatusOK {
		if held {
			r.remove(s, rec.Topic)
		}
		return st
	}
	if !held && r.cfg.MaxTopicsPerSender > 0 && len(s.entries) >= r.cfg.MaxTopicsPerSender {
		return StatusOverCap
	}
	if !held && r.cfg.ChangeRate > 0 {
		s.tokens += float64(now-s.tokensAt) / float64(time.Second) * r.cfg.ChangeRate
		if burst := float64(r.cfg.ChangeBurst); s.tokens > burst {
			s.tokens = burst
		}
		s.tokensAt = now
		if s.tokens < 1 {
			return StatusRateLimited
		}
		s.tokens--
	}

	life := r.cfg.Lifetimes.Grant(rec.Lifetime)
	s.entries[rec.Topic] = entry{setAt: now, setSeq: seq, lifetime: life}
	if exp := now + int64(life)*int64(time.Second); exp < s.nextScan {
		s.nextScan = exp
	}
	if s.minLife == 0 || life < s.minLife {
		s.minLife = life
	}
	if held {
		r.stats.Refreshes++
	} else {
		r.stats.Adds++
		r.stats.Topics++
		c := r.counters[s.principal]
		c.adds++
		c.held++
		s.digest.Toggle(rec.Topic)
		r.acquire(s.principal, rec.Topic, metered, now)
	}

	// The first build of every hop delivers as provisioned: a delivery
	// address is accepted and not honored.
	if delivery {
		return StatusAddressNotHonored
	}
	if r.noter != nil {
		return r.noter.Note(s.principal, rec.Topic)
	}
	return StatusOK
}

// judge decides whether a principal may hold a topic now, and whether it
// would count against the quota.
func (r *Receiver) judge(principal string, t TopicID) (Status, bool) {
	if sc := r.cfg.Policy.Scope(principal); sc != nil && !sc.Contains(t) {
		return StatusNotServed, false
	}
	switch r.cfg.Policy.Bound(principal, t) {
	case BoundFree:
		return StatusOK, false
	case BoundDenied:
		return StatusOutsideBound, false
	}
	ps := r.principals[principal]
	if ps != nil {
		if le := ps.live[t]; le != nil && le.metered {
			return StatusOK, true
		}
	}
	q := r.cfg.Policy.Quota(principal)
	switch {
	case q == 0:
		return StatusOutsideBound, false
	case q > 0 && ps != nil && ps.metered >= q:
		return StatusOverCap, false
	}
	return StatusOK, true
}

// acquire records that one more sender of the principal holds the topic.
func (r *Receiver) acquire(principal string, t TopicID, metered bool, now int64) {
	ps := r.principals[principal]
	if ps == nil {
		ps = &principalState{live: make(map[TopicID]*liveEntry)}
		r.principals[principal] = ps
	}
	le := ps.live[t]
	if le == nil {
		le = &liveEntry{metered: metered, since: now}
		ps.live[t] = le
		if metered {
			ps.metered++
		}
		r.stats.LiveTopics++
		r.events = append(r.events, change{principal, t, true})
	} else if metered != le.metered {
		// The bound's view of the topic changed since it went live.
		le.metered = metered
		if metered {
			ps.metered++
		} else {
			ps.metered--
		}
	}
	le.refs++
}

// remove drops a topic from a sender's set.
func (r *Receiver) remove(s *session, t TopicID) {
	if _, ok := s.entries[t]; !ok {
		return
	}
	delete(s.entries, t)
	s.digest.Toggle(t)
	r.stats.Topics--
	if c := r.counters[s.principal]; c != nil {
		c.held--
	}
	ps := r.principals[s.principal]
	if ps == nil {
		return
	}
	le := ps.live[t]
	if le == nil {
		return
	}
	le.refs--
	if le.refs == 0 {
		if le.metered {
			ps.metered--
		}
		delete(ps.live, t)
		r.stats.LiveTopics--
		r.events = append(r.events, change{s.principal, t, false})
		if len(ps.live) == 0 {
			delete(r.principals, s.principal)
		}
	}
}

func (r *Receiver) dropSession(s *session) {
	for t := range s.entries {
		r.remove(s, t)
	}
	r.forget(s)
}

// forget stops tracking a sender that holds nothing.
func (r *Receiver) forget(s *session) {
	delete(r.sessions, s.key)
	if n := r.senders[s.principal] - 1; n > 0 {
		r.senders[s.principal] = n
	} else {
		delete(r.senders, s.principal)
		delete(r.counters, s.principal)
	}
}

// ack builds an ACK. s may be nil when no sender state exists.
func (r *Receiver) ack(h *Header, tok uint64, res Result, s *session, principal string, statuses []RecordStatus, notices bool) []byte {
	a := Ack{
		Header:          Header{Version: Version, Result: res, SenderID: h.SenderID, Token: tok, Seq: h.Seq},
		LifetimeMin:     r.cfg.Lifetimes.Min,
		LifetimeDefault: r.cfg.Lifetimes.Default,
		LifetimeMax:     r.cfg.Lifetimes.Max,
		Statuses:        statuses,
	}
	if s != nil {
		a.LastSeq = s.lastSeq
		a.SetCount = uint32(len(s.entries))
		a.SetDigest = s.digest
	}
	room := MaxDatagram - HeaderSize - AckBodySize - len(statuses)*StatusSize
	if sc := r.cfg.Policy.Scope(principal); sc != nil {
		a.ScopeGen = sc.Gen()
		if v := sc.Value(); v != nil && h.Flags&FlagScopeWanted != 0 && TLVHeaderSize+len(v) <= room {
			a.Ext = AppendTLV(a.Ext, ExtScope, v)
			room -= TLVHeaderSize + len(v)
		}
	}
	if notices && r.noter != nil && s != nil && res == ResultOK {
		var ns []Notice
		most := (room - TLVHeaderSize) / NoticeSize
		r.noter.Notes(principal, func(t TopicID, st Status) bool {
			if _, held := s.entries[t]; !held {
				return true
			}
			if len(ns) >= most {
				a.Flags |= FlagNoticesTruncated
				return false
			}
			ns = append(ns, Notice{Topic: t, Status: st})
			return true
		})
		if len(ns) > 0 {
			a.Ext = AppendNotices(a.Ext, ns)
		}
	}
	b, err := a.Append(nil)
	if err != nil {
		// Cannot happen: every part was sized against the room left.
		a.Statuses, a.Ext = nil, nil
		b, _ = a.Append(nil)
	}
	return b
}

// Tick expires what has not been refreshed and forgets idle senders. It
// returns the RESYNC messages that are due. Call it about once a second.
func (r *Receiver) Tick(now time.Time) []Datagram {
	nowNS := now.UnixNano()
	var out []Datagram
	r.mu.Lock()
	for _, s := range r.sessions {
		if len(s.entries) > 0 && s.nextScan <= nowNS {
			next := int64(1<<63 - 1)
			var minLife uint32
			for t, e := range s.entries {
				base := e.setAt
				if s.refreshed > base {
					base = s.refreshed
				}
				exp := base + int64(e.lifetime)*int64(time.Second)
				if exp <= nowNS {
					r.remove(s, t)
					r.stats.Expiries++
					r.counters[s.principal].expiries++
					continue
				}
				if exp < next {
					next = exp
				}
				if minLife == 0 || e.lifetime < minLife {
					minLife = e.lifetime
				}
			}
			s.nextScan = next
			s.minLife = minLife
		}
		if s.poke {
			s.poke = false
			m := Resync{Header: Header{Version: Version, SenderID: s.key.id}}
			b, _ := m.Append(nil)
			out = append(out, Datagram{Addr: s.addr, Data: b})
		}
		if len(s.entries) == 0 && nowNS-s.heard > int64(r.cfg.SenderIdle) {
			r.forget(s)
		}
	}
	r.stats.Senders = len(r.sessions)
	r.mu.Unlock()
	r.flush()
	return out
}

// Reevaluate applies a changed bound or scope to what a principal already
// holds. Topics that are no longer allowed are dropped, the newest first
// when a quota shrank, and every sender of the principal that lost a topic
// is poked so it learns of it at once instead of at its next refresh. Call
// it after the policy's answers for the principal change.
func (r *Receiver) Reevaluate(principal string, now time.Time) {
	r.mu.Lock()
	ps := r.principals[principal]
	if ps == nil {
		r.mu.Unlock()
		return
	}
	drop := make(map[TopicID]struct{})
	sc := r.cfg.Policy.Scope(principal)
	var metered []TopicID
	for t, le := range ps.live {
		if sc != nil && !sc.Contains(t) {
			drop[t] = struct{}{}
			continue
		}
		switch r.cfg.Policy.Bound(principal, t) {
		case BoundDenied:
			drop[t] = struct{}{}
		case BoundFree:
			if le.metered {
				le.metered = false
				ps.metered--
			}
		case BoundQuota:
			if !le.metered {
				le.metered = true
				ps.metered++
			}
			metered = append(metered, t)
		}
	}
	if q := r.cfg.Policy.Quota(principal); q >= 0 && len(metered) > q {
		// Keep the topics that have been live longest. The TopicID breaks
		// ties so the outcome does not depend on map order.
		sort.Slice(metered, func(i, j int) bool {
			a, b := ps.live[metered[i]], ps.live[metered[j]]
			if a.since != b.since {
				return a.since < b.since
			}
			return string(metered[i][:]) < string(metered[j][:])
		})
		for _, t := range metered[q:] {
			drop[t] = struct{}{}
		}
	}
	if len(drop) > 0 {
		for _, s := range r.sessions {
			if s.principal != principal {
				continue
			}
			for t := range drop {
				if _, ok := s.entries[t]; ok {
					r.remove(s, t)
					r.stats.Reevaluated++
					r.counters[principal].dropped++
					if !s.poke {
						s.poke = true
						r.stats.ResyncsQueued++
					}
				}
			}
		}
	}
	r.mu.Unlock()
	r.flush()
}

// DropPrincipal forgets every sender of a principal and everything they
// hold. Call it when the principal ceases to exist.
func (r *Receiver) DropPrincipal(principal string) {
	r.mu.Lock()
	for _, s := range r.sessions {
		if s.principal == principal {
			r.dropSession(s)
		}
	}
	r.mu.Unlock()
	r.flush()
}

// PokeAll queues a RESYNC to every sender, sent by the next [Receiver.Tick].
// A hop uses it when something its senders should know has changed, such as
// the scope it advertises.
func (r *Receiver) PokeAll() {
	r.mu.Lock()
	for _, s := range r.sessions {
		if !s.poke {
			s.poke = true
			r.stats.ResyncsQueued++
		}
	}
	r.mu.Unlock()
}

// PokePrincipal queues a RESYNC to every sender of a principal. An edge
// uses it when what it delivers to the principal changed, so that the
// senders learn the new scope now instead of at their next refresh.
func (r *Receiver) PokePrincipal(principal string) {
	r.mu.Lock()
	for _, s := range r.sessions {
		if s.principal == principal && !s.poke {
			s.poke = true
			r.stats.ResyncsQueued++
		}
	}
	r.mu.Unlock()
}

// PokeHolders queues a RESYNC to every sender that holds a topic. A relay
// uses it when it learns that a topic it holds is not served upstream, so
// that the senders hear of it with their next digest instead of at their
// next refresh.
func (r *Receiver) PokeHolders(t TopicID) {
	r.mu.Lock()
	for _, s := range r.sessions {
		if _, ok := s.entries[t]; ok && !s.poke {
			s.poke = true
			r.stats.ResyncsQueued++
		}
	}
	r.mu.Unlock()
}

// PrincipalStats returns the state and counters of every principal that has
// a sender, in no particular order. The counters start again when a
// principal's last sender is forgotten.
func (r *Receiver) PrincipalStats() []PrincipalStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]PrincipalStats, 0, len(r.counters))
	for p, c := range r.counters {
		st := PrincipalStats{
			Principal: p, Senders: r.senders[p], Held: c.held,
			Adds: c.adds, Withdrawals: c.withdrawals, Expiries: c.expiries, Dropped: c.dropped,
			Refused: make(map[Status]uint64, len(c.refused)),
		}
		for k, v := range c.refused {
			st.Refused[k] = v
		}
		if ps := r.principals[p]; ps != nil {
			st.Live = len(ps.live)
			st.Metered = ps.metered
		}
		out = append(out, st)
	}
	return out
}

// Live returns the topics live for a principal, in no particular order.
func (r *Receiver) Live(principal string) []TopicID {
	r.mu.Lock()
	defer r.mu.Unlock()
	ps := r.principals[principal]
	if ps == nil {
		return nil
	}
	out := make([]TopicID, 0, len(ps.live))
	for t := range ps.live {
		out = append(out, t)
	}
	return out
}

// IsLive reports whether a topic is live for a principal.
func (r *Receiver) IsLive(principal string, t TopicID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ps := r.principals[principal]
	return ps != nil && ps.live[t] != nil
}

// Principals returns the principals that have at least one live topic.
func (r *Receiver) Principals() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.principals))
	for p := range r.principals {
		out = append(out, p)
	}
	return out
}

// MaxSenderHops returns the largest hop count among senders that hold at
// least one topic. A relay announces upward with one more.
func (r *Receiver) MaxSenderHops() uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var m uint8
	for _, s := range r.sessions {
		if len(s.entries) > 0 && s.hops > m {
			m = s.hops
		}
	}
	return m
}

// SenderInfo describes one sender, for inspection.
type SenderInfo struct {
	Addr      netip.AddrPort
	SenderID  uint64
	Principal string
	Topics    int
	Hops      uint8
	LastSeq   uint64
	LastHeard time.Time
}

// Senders returns the senders tracked now.
func (r *Receiver) Senders() []SenderInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SenderInfo, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, SenderInfo{
			Addr: s.addr, SenderID: s.key.id, Principal: s.principal, Topics: len(s.entries),
			Hops: s.hops, LastSeq: s.lastSeq, LastHeard: time.Unix(0, s.heard),
		})
	}
	return out
}

// Stats returns a copy of the counters.
func (r *Receiver) Stats() ReceiverStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stats
	st.Senders = len(r.sessions)
	st.Refused = make(map[Status]uint64, len(r.stats.Refused))
	for k, v := range r.stats.Refused {
		st.Refused[k] = v
	}
	return st
}

func (r *Receiver) count(f func(*ReceiverStats)) {
	r.mu.Lock()
	f(&r.stats)
	r.mu.Unlock()
}

// flush delivers queued changes in order. It is called with no lock held.
func (r *Receiver) flush() {
	if r.cfg.OnChange == nil {
		r.mu.Lock()
		r.events = r.events[:0]
		r.mu.Unlock()
		return
	}
	r.cbMu.Lock()
	defer r.cbMu.Unlock()
	for {
		r.mu.Lock()
		ev := r.events
		r.events = nil
		r.mu.Unlock()
		if len(ev) == 0 {
			return
		}
		for _, c := range ev {
			r.cfg.OnChange(c.principal, c.topic, c.live)
		}
	}
}
