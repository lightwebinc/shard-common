package manifest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/frame"
)

func makeEntries(t *testing.T, snap []*frame.ShardManifest, srcs []string) []*Entry {
	t.Helper()
	if len(snap) != len(srcs) {
		t.Fatalf("makeEntries: len(snap)=%d != len(srcs)=%d", len(snap), len(srcs))
	}
	r := NewRegistry(60 * time.Second)
	for i, m := range snap {
		r.Upsert(mustAddr(srcs[i]), m)
	}
	return r.Snapshot()
}

func TestEvaluator_QuorumGate(t *testing.T) {
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond, // effectively no delay for the test
		Clock:      func() time.Time { return now },
	})

	// One announcer ⇒ no quorum.
	e1 := makeEntries(t,
		[]*frame.ShardManifest{authoritativeManifest(1, 8, []uint16{0, 1, 2})},
		[]string{"fd20::1"},
	)
	got := ev.Evaluate(e1)
	if got.ShardBits != 0 {
		t.Errorf("with 1 announcer: ShardBits = %d, want 0 (no adopt)", got.ShardBits)
	}
	if got.QuorumMet["shard_bits"] {
		t.Errorf("with 1 announcer: QuorumMet[shard_bits] = true")
	}

	// Add a second matching authoritative announcer; advance clock past
	// hysteresis. First call records the first-quorum timestamp.
	e2 := makeEntries(t,
		[]*frame.ShardManifest{
			authoritativeManifest(1, 8, []uint16{0, 1, 2}),
			authoritativeManifest(2, 8, []uint16{3, 4}),
		},
		[]string{"fd20::1", "fd20::2"},
	)
	_ = ev.Evaluate(e2) // records first-quorum

	now = now.Add(1 * time.Second) // past 1ns hysteresis
	ev.cfg.Clock = func() time.Time { return now }
	got2 := ev.Evaluate(e2)
	if !got2.QuorumMet["shard_bits"] {
		t.Errorf("with 2 matching announcers: QuorumMet[shard_bits] = false")
	}
	if got2.ShardBits != 8 {
		t.Errorf("with 2 matching announcers: ShardBits = %d, want 8", got2.ShardBits)
	}
	if got2.PilotsKnown != 2 {
		t.Errorf("PilotsKnown = %d, want 2", got2.PilotsKnown)
	}
}

func TestEvaluator_HysteresisWindow(t *testing.T) {
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 600 * time.Second, // 10 min
		Clock:      func() time.Time { return now },
	})

	entries := makeEntries(t,
		[]*frame.ShardManifest{
			authoritativeManifest(1, 8, []uint16{0}),
			authoritativeManifest(2, 8, []uint16{0}),
		},
		[]string{"fd20::1", "fd20::2"},
	)

	// First evaluation records the timestamp; should NOT adopt.
	got := ev.Evaluate(entries)
	if got.ShardBits != 0 {
		t.Errorf("first call: ShardBits = %d, want 0 (hysteresis pending)", got.ShardBits)
	}

	// Advance clock half the hysteresis; still not adopted.
	now = now.Add(300 * time.Second)
	got = ev.Evaluate(entries)
	if got.ShardBits != 0 {
		t.Errorf("mid-hysteresis: ShardBits = %d, want 0", got.ShardBits)
	}

	// Advance past hysteresis; adoption should occur.
	now = now.Add(400 * time.Second) // total +700s > 600s
	got = ev.Evaluate(entries)
	if got.ShardBits != 8 {
		t.Errorf("post-hysteresis: ShardBits = %d, want 8", got.ShardBits)
	}
}

func TestEvaluator_PinOverridesAdoption(t *testing.T) {
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Pin:        Pin{ShardBits: 4, HasShardBitsPin: true},
		Clock:      func() time.Time { return now },
	})

	// Two announcers say 8, but pin is 4.
	entries := makeEntries(t,
		[]*frame.ShardManifest{
			authoritativeManifest(1, 8, []uint16{0}),
			authoritativeManifest(2, 8, []uint16{0}),
		},
		[]string{"fd20::1", "fd20::2"},
	)
	got := ev.Evaluate(entries)
	if got.ShardBits != 4 {
		t.Errorf("pin should win: ShardBits = %d, want 4", got.ShardBits)
	}
	// Divergence should be reported when pin disagrees with peers.
	if len(got.DivergenceFields) == 0 || got.DivergenceFields[0] != "shard_bits" {
		t.Errorf("divergence missing: %v", got.DivergenceFields)
	}
}

func TestEvaluator_NonAuthoritativeIgnoredForAdoption(t *testing.T) {
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Clock:      func() time.Time { return now },
	})

	// One authoritative + two non-authoritative. Only the auth one counts.
	authM := authoritativeManifest(1, 8, []uint16{0})
	nonAuth1 := authoritativeManifest(2, 8, []uint16{0})
	nonAuth1.Flags &^= frame.ShardManifestFlagAuthoritative
	nonAuth2 := authoritativeManifest(3, 8, []uint16{0})
	nonAuth2.Flags &^= frame.ShardManifestFlagAuthoritative

	entries := makeEntries(t,
		[]*frame.ShardManifest{authM, nonAuth1, nonAuth2},
		[]string{"fd20::1", "fd20::2", "fd20::3"},
	)
	got := ev.Evaluate(entries)
	if got.QuorumMet["shard_bits"] {
		t.Errorf("non-authoritative should not satisfy quorum")
	}
}

func TestEvaluator_SourceSetUnionIncludesNonAuthoritative(t *testing.T) {
	// Per BRC-139 §Source set: the source-set union is NOT gated by
	// Authoritative. Every currently-valid manifest contributes.
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Clock:      func() time.Time { return now },
	})

	src1 := mustAddr("fd20::10").As16()
	src2 := mustAddr("fd20::11").As16()
	authM := authoritativeManifest(1, 8, []uint16{0})
	authM.Flags |= frame.ShardManifestFlagSourcesValid
	authM.Sources = [][16]byte{src1}

	nonAuth := authoritativeManifest(2, 8, []uint16{0})
	nonAuth.Flags &^= frame.ShardManifestFlagAuthoritative
	nonAuth.Flags |= frame.ShardManifestFlagSourcesValid
	nonAuth.Sources = [][16]byte{src2}

	entries := makeEntries(t,
		[]*frame.ShardManifest{authM, nonAuth},
		[]string{"fd20::1", "fd20::2"},
	)
	got := ev.Evaluate(entries)
	if len(got.SourceSet) != 2 {
		t.Errorf("SourceSet len = %d, want 2 (union across all manifests)", len(got.SourceSet))
	}
	want := []netip.Addr{netip.AddrFrom16(src1), netip.AddrFrom16(src2)}
	for i := range want {
		if got.SourceSet[i] != want[i] {
			t.Errorf("SourceSet[%d] = %s, want %s", i, got.SourceSet[i], want[i])
		}
	}
}

func TestEvaluator_PilotGroupsRequirePilotOnly(t *testing.T) {
	// Only PilotOnly manifests contribute to PilotGroups (self-reporting
	// non-pilot authoritative announcers do not project their own joins).
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Clock:      func() time.Time { return now },
	})

	// Two pilots agree on groups {3, 4}; one authoritative non-pilot
	// reports {99, 100}. PilotGroups should be {3, 4}.
	pilot1 := authoritativeManifest(1, 8, []uint16{3, 4})
	pilot2 := authoritativeManifest(2, 8, []uint16{3, 4})
	nonPilot := authoritativeManifest(3, 8, []uint16{99, 100})
	nonPilot.Flags &^= frame.ShardManifestFlagPilotOnly

	entries := makeEntries(t,
		[]*frame.ShardManifest{pilot1, pilot2, nonPilot},
		[]string{"fd20::1", "fd20::2", "fd20::3"},
	)
	got := ev.Evaluate(entries)
	if len(got.PilotGroups) != 2 || got.PilotGroups[0] != 3 || got.PilotGroups[1] != 4 {
		t.Errorf("PilotGroups = %v, want [3 4]", got.PilotGroups)
	}
}

func TestEvaluator_SuccessorAdoption(t *testing.T) {
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Clock:      func() time.Time { return now },
	})

	// First adopt active ShardBits=8.
	active1 := authoritativeManifest(1, 8, []uint16{0})
	active2 := authoritativeManifest(2, 8, []uint16{0})
	entries := makeEntries(t,
		[]*frame.ShardManifest{active1, active2},
		[]string{"fd20::1", "fd20::2"},
	)
	_ = ev.Evaluate(entries)
	now = now.Add(time.Second)
	_ = ev.Evaluate(entries)

	// Now add Successor block (shardBits=9, +1 from active) on both pilots.
	for _, m := range []*frame.ShardManifest{active1, active2} {
		m.Flags |= frame.ShardManifestFlagSuccessorValid
		m.Successor = &frame.SuccessorBlock{
			ShardBits:       9,
			Flags:           frame.SuccessorFlagSourceModeSSM,
			TransitionEpoch: uint32(now.Add(600 * time.Second).Unix()),
		}
		copy(m.Successor.GenerationID[:], []byte("successor-gen-id"))
	}
	entries = makeEntries(t,
		[]*frame.ShardManifest{active1, active2},
		[]string{"fd20::1", "fd20::2"},
	)
	_ = ev.Evaluate(entries) // records first-quorum for successor
	now = now.Add(2 * time.Second)
	got := ev.Evaluate(entries)
	if got.Successor == nil {
		t.Fatalf("Successor not adopted")
	}
	if got.Successor.ShardBits != 9 {
		t.Errorf("Successor.ShardBits = %d, want 9", got.Successor.ShardBits)
	}
	if !got.Successor.SourceModeSSM {
		t.Errorf("Successor.SourceModeSSM = false, want true")
	}
}

func TestEvaluator_SuccessorRejectsShiftAboveOne(t *testing.T) {
	// The evaluator enforces ±1 between adopted ShardBits and Successor's.
	// We construct a snapshot where Successor.ShardBits=10 but active=8;
	// quorum says active=8, so |10-8|=2 should disqualify successor.
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Clock:      func() time.Time { return now },
	})

	mk := func(id uint32) *frame.ShardManifest {
		m := authoritativeManifest(id, 8, []uint16{0})
		m.Flags |= frame.ShardManifestFlagSuccessorValid
		// Note: frame.EncodeShardManifest would reject |10-8|=2; the
		// evaluator's own check is the second line of defence (covers
		// the case where a buggy encoder produces an invalid datagram
		// AND a buggy decoder lets it through).
		m.Successor = &frame.SuccessorBlock{
			ShardBits:       10,
			TransitionEpoch: uint32(now.Add(600 * time.Second).Unix()),
		}
		return m
	}
	entries := makeEntries(t,
		[]*frame.ShardManifest{mk(1), mk(2)},
		[]string{"fd20::1", "fd20::2"},
	)
	// Adopt active first.
	_ = ev.Evaluate(entries)
	now = now.Add(time.Second)
	got := ev.Evaluate(entries)
	if got.Successor != nil {
		t.Errorf("Successor should be rejected: got %+v", got.Successor)
	}
}

func TestEvaluator_PilotsLostRetainsLastAdopted(t *testing.T) {
	now := time.Unix(1746800000, 0)
	ev := NewEvaluator(EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
		Clock:      func() time.Time { return now },
	})

	// Adopt SB=8.
	entries := makeEntries(t,
		[]*frame.ShardManifest{
			authoritativeManifest(1, 8, []uint16{0}),
			authoritativeManifest(2, 8, []uint16{0}),
		},
		[]string{"fd20::1", "fd20::2"},
	)
	_ = ev.Evaluate(entries)
	now = now.Add(time.Second)
	got := ev.Evaluate(entries)
	if got.ShardBits != 8 {
		t.Fatalf("setup: ShardBits = %d", got.ShardBits)
	}

	// All pilots disappear.
	got2 := ev.Evaluate(nil)
	if got2.PilotsKnown != 0 {
		t.Errorf("PilotsKnown = %d, want 0", got2.PilotsKnown)
	}
	if got2.ShardBits != 8 {
		t.Errorf("ShardBits = %d after loss, want 8 (last adopted retained)", got2.ShardBits)
	}
	if got2.QuorumMet["shard_bits"] {
		t.Errorf("QuorumMet should be false after pilot loss")
	}
}
