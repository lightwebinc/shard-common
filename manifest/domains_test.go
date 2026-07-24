package manifest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/frame"
)

func beefDescriptor(bits uint8) frame.DomainDescriptor {
	return frame.DomainDescriptor{
		DomainID:  0x1,
		ShardBits: bits,
		SlotSpan:  1,
		Flags:     frame.DomainFlagSourceModeSSM | frame.DomainFlagActive,
	}
}

func domEntry(src byte, doms ...frame.DomainDescriptor) *Entry {
	var a [16]byte
	a[0], a[15] = 0xfd, src
	return &Entry{
		SrcIPv6:          netip.AddrFrom16(a),
		InstanceID:       uint32(src),
		Flags:            frame.ShardManifestFlagAuthoritative,
		ShardBits:        8,
		AnnounceInterval: 30,
		Domains:          doms,
	}
}

// domainEvaluator returns an evaluator with quorum 2, 1 s hysteresis, and an
// advanceable clock.
func domainEvaluator(pin Pin) (*Evaluator, *time.Time) {
	now := time.Unix(1_000_000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: time.Second,
		Pin:        pin,
		Clock:      func() time.Time { return now },
	})
	return ev, &now
}

func TestDomainAdoptionQuorum(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	snap := []*Entry{domEntry(1, beefDescriptor(12)), domEntry(2, beefDescriptor(12))}

	got := ev.Evaluate(snap) // first pass: quorum met, hysteresis timer starts
	da := got.Domains[0x1]
	if !da.QuorumMet || da.ShardBits != 0 {
		t.Fatalf("first pass: %+v (want quorum met, nothing adopted)", da)
	}

	*now = now.Add(2 * time.Second)
	got = ev.Evaluate(snap)
	da = got.Domains[0x1]
	if da.ShardBits != 12 || !da.SourceModeSSM || !da.QuorumMet || da.Divergent {
		t.Fatalf("after hysteresis: %+v (want bits 12, ssm, quorum, no divergence)", da)
	}
	if !got.QuorumMet["domain_1_shard_bits"] {
		t.Error("QuorumMet telemetry key missing")
	}
	// Top-level adoption proceeds independently of plane descriptors — the
	// entries' own ShardBits (8) adopts through the ordinary path.
	if got.ShardBits != 8 {
		t.Errorf("top-level ShardBits = %d, want 8 (independent of planes)", got.ShardBits)
	}
}

func TestDomainSubQuorum(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	snap := []*Entry{domEntry(1, beefDescriptor(12))}
	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	got := ev.Evaluate(snap)
	da := got.Domains[0x1]
	if da.QuorumMet || da.ShardBits != 0 {
		t.Fatalf("sub-quorum adopted: %+v", da)
	}
}

func TestDomainDivergence(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	snap := []*Entry{domEntry(1, beefDescriptor(12)), domEntry(2, beefDescriptor(10))}
	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	got := ev.Evaluate(snap)
	da := got.Domains[0x1]
	if !da.Divergent || da.QuorumMet || da.ShardBits != 0 {
		t.Fatalf("divergent announcers: %+v (want divergence, no adoption)", da)
	}
	found := false
	for _, f := range got.DivergenceFields {
		if f == "domain_1_shard_bits" {
			found = true
		}
	}
	if !found {
		t.Errorf("DivergenceFields = %v, want domain_1_shard_bits", got.DivergenceFields)
	}
}

func TestDomainZeroSkipped(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	d0 := frame.DomainDescriptor{DomainID: 0, ShardBits: 8, SlotSpan: 1}
	snap := []*Entry{domEntry(1, d0), domEntry(2, d0)}
	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	got := ev.Evaluate(snap)
	if _, ok := got.Domains[0]; ok {
		t.Fatal("domain 0 must stay governed by top-level fields")
	}
}

func TestDomainPinWins(t *testing.T) {
	ev, now := domainEvaluator(Pin{DomainShardBits: map[uint8]uint8{0x1: 6}})
	snap := []*Entry{domEntry(1, beefDescriptor(12)), domEntry(2, beefDescriptor(12))}
	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	got := ev.Evaluate(snap)
	da := got.Domains[0x1]
	if da.ShardBits != 6 || !da.QuorumMet {
		t.Fatalf("pin lost: %+v", da)
	}
	if !da.Divergent {
		t.Error("announcer disagreement with pin not surfaced as divergence")
	}
}

func TestDomainRetentionOnQuorumLoss(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	snap := []*Entry{domEntry(1, beefDescriptor(12)), domEntry(2, beefDescriptor(12))}
	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	ev.Evaluate(snap)

	*now = now.Add(time.Second)
	got := ev.Evaluate(nil) // every announcer expired
	da := got.Domains[0x1]
	if da.ShardBits != 12 {
		t.Fatalf("adopted view lost on quorum loss: %+v", da)
	}
	if da.QuorumMet {
		t.Error("QuorumMet should report false after loss")
	}
}

func TestDomainSuccessorAdoption(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	d := beefDescriptor(12)
	d.Flags |= frame.DomainFlagSuccessorValid
	d.Successor = &frame.SuccessorBlock{
		ShardBits:       13,
		Flags:           frame.SuccessorFlagSourceModeSSM,
		TransitionEpoch: 1_700_000_000,
	}
	for i := range d.Successor.GenerationID {
		d.Successor.GenerationID[i] = byte(0xA0 + i)
	}
	snap := []*Entry{domEntry(1, d), domEntry(2, d)}

	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	got := ev.Evaluate(snap)
	da := got.Domains[0x1]
	if da.ShardBits != 12 {
		t.Fatalf("bits not adopted: %+v", da)
	}
	// The successor's ±1 gate opens only once the plane's bits are adopted,
	// so its hysteresis window starts one pass later (top-level semantics).
	*now = now.Add(2 * time.Second)
	got = ev.Evaluate(snap)
	da = got.Domains[0x1]
	s := da.Successor
	if s == nil || s.ShardBits != 13 || !s.SourceModeSSM || s.TransitionEpoch != 1_700_000_000 {
		t.Fatalf("per-domain successor not adopted: %+v", s)
	}
}

func TestDomainsIndependent(t *testing.T) {
	ev, now := domainEvaluator(Pin{})
	d3 := frame.DomainDescriptor{DomainID: 0x3, ShardBits: 4, SlotSpan: 1, Flags: frame.DomainFlagActive}
	snap := []*Entry{
		domEntry(1, beefDescriptor(12), d3),
		domEntry(2, beefDescriptor(12), d3),
	}
	ev.Evaluate(snap)
	*now = now.Add(2 * time.Second)
	got := ev.Evaluate(snap)
	if got.Domains[0x1].ShardBits != 12 || got.Domains[0x3].ShardBits != 4 {
		t.Fatalf("independent planes not both adopted: %+v", got.Domains)
	}
	if got.Domains[0x3].SourceModeSSM {
		t.Error("domain 3 ssm adopted without the flag")
	}
}

func TestRegistryCarriesDomains(t *testing.T) {
	r := NewRegistry(0)
	m := &frame.ShardManifest{
		Flags:            frame.ShardManifestFlagAuthoritative | frame.ShardManifestFlagDomainsValid,
		InstanceID:       7,
		AnnounceInterval: 30,
		ShardBits:        8,
		Domains:          []frame.DomainDescriptor{beefDescriptor(12)},
	}
	e := r.Upsert(netip.MustParseAddr("fd00::1"), m)
	if len(e.Domains) != 1 || e.Domains[0].DomainID != 0x1 {
		t.Fatalf("Entry.Domains not carried: %+v", e.Domains)
	}
}
