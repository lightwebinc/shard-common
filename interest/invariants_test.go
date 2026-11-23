package interest

import (
	"fmt"
	"testing"
)

// checkReceiver verifies that the receiver's incremental bookkeeping agrees
// with a recount from scratch.
func checkReceiver(t testing.TB, r *Receiver) {
	t.Helper()
	if err := receiverInvariants(r); err != nil {
		t.Fatalf("receiver invariant: %v", err)
	}
}

func receiverInvariants(r *Receiver) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	topics := 0
	refs := map[string]map[TopicID]uint32{}
	senders := map[string]int{}
	for key, s := range r.sessions {
		if s.key != key {
			return fmt.Errorf("session filed under the wrong key")
		}
		senders[s.principal]++
		var d SetDigest
		for id := range s.entries {
			d.Toggle(id)
			topics++
			if refs[s.principal] == nil {
				refs[s.principal] = map[TopicID]uint32{}
			}
			refs[s.principal][id]++
		}
		if d != s.digest {
			return fmt.Errorf("a sender's digest does not match its entries")
		}
	}
	if topics != r.stats.Topics {
		return fmt.Errorf("%d topics held, the counter says %d", topics, r.stats.Topics)
	}
	live := 0
	for p, ps := range r.principals {
		if len(ps.live) == 0 {
			return fmt.Errorf("principal %q kept with nothing live", p)
		}
		metered := 0
		for id, le := range ps.live {
			if le.refs == 0 || le.refs != refs[p][id] {
				return fmt.Errorf("principal %q: %d references recorded, %d senders hold the topic", p, le.refs, refs[p][id])
			}
			if le.metered {
				metered++
			}
			live++
		}
		if metered != ps.metered {
			return fmt.Errorf("principal %q: %d metered topics, the counter says %d", p, metered, ps.metered)
		}
	}
	for p, m := range refs {
		for id := range m {
			if ps := r.principals[p]; ps == nil || ps.live[id] == nil {
				return fmt.Errorf("principal %q: a held topic is not live", p)
			}
		}
	}
	if live != r.stats.LiveTopics {
		return fmt.Errorf("%d topics live, the counter says %d", live, r.stats.LiveTopics)
	}
	held := map[string]int{}
	for _, s := range r.sessions {
		held[s.principal] += len(s.entries)
	}
	if len(r.counters) != len(senders) {
		return fmt.Errorf("%d principals have counters, %d have senders", len(r.counters), len(senders))
	}
	for p, c := range r.counters {
		if c.held != held[p] {
			return fmt.Errorf("principal %q holds %d topics, its counter says %d", p, held[p], c.held)
		}
	}
	if len(senders) != len(r.senders) {
		return fmt.Errorf("%d principals have senders, the index has %d", len(senders), len(r.senders))
	}
	for p, n := range senders {
		if r.senders[p] != n {
			return fmt.Errorf("principal %q has %d senders, the index says %d", p, n, r.senders[p])
		}
	}
	// Honored delivery addresses: the reference counts are a recount of the
	// entries that hold them.
	dels := map[deliveryRef]int{}
	for _, s := range r.sessions {
		for id, e := range s.entries {
			if e.delivery != "" {
				dels[deliveryRef{id, e.delivery}]++
			}
		}
	}
	if len(dels) != len(r.deliveries) || len(dels) != r.stats.Deliveries {
		return fmt.Errorf("%d delivery addresses held, the index has %d, the counter says %d", len(dels), len(r.deliveries), r.stats.Deliveries)
	}
	for ref, n := range dels {
		if de := r.deliveries[ref]; de == nil || de.refs != n {
			return fmt.Errorf("a delivery address held by %d senders has the wrong count", n)
		}
	}
	return nil
}

// checkClient verifies the client's per-upstream bookkeeping.
func checkClient(t testing.TB, c *Client) {
	t.Helper()
	if err := clientInvariants(c); err != nil {
		t.Fatalf("client invariant: %v", err)
	}
}

func clientInvariants(c *Client) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range c.ups {
		var d SetDigest
		var n uint32
		for id, t := range u.topics {
			if t.held {
				n++
				d.Toggle(id)
			}
			if t.want {
				if c.want[id] == nil {
					return fmt.Errorf("upstream %s is told a topic nobody wants", u.addr)
				}
			}
		}
		if n != u.heldCount || d != u.heldDigest {
			return fmt.Errorf("upstream %s: held count or digest drifted from the topics", u.addr)
		}
		queued := map[TopicID]int{}
		for _, id := range u.queue {
			queued[id]++
		}
		for _, id := range u.later {
			queued[id]++
		}
		for id, t := range u.topics {
			if t.ver != t.ackVer && t.sentSeq == 0 && !t.queued {
				return fmt.Errorf("upstream %s: a topic that must be said is neither queued nor in flight", u.addr)
			}
			if t.queued && queued[id] == 0 {
				return fmt.Errorf("upstream %s: a topic is marked queued and is in no queue", u.addr)
			}
			if t.sentSeq != 0 && u.inflight[t.sentSeq] == nil {
				return fmt.Errorf("upstream %s: a topic is marked in flight in a datagram that is not", u.addr)
			}
		}
	}
	for id := range c.noted {
		if c.want[id] == nil {
			return fmt.Errorf("a topic nobody wants is listed as unserved")
		}
	}
	return nil
}
