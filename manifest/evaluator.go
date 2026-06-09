package manifest

import (
	"net/netip"
	"sort"
	"time"
)

// Adopted is the result of an [Evaluator] pass: the consumer's current
// view of the auto-configured fields. Fields are tagged with whether the
// value originated from the pilot view (adopted), from a manual operator
// pin (pinned), or from neither (zero values).
type Adopted struct {
	// ShardBits is the adopted shard-bit width. Set when either the
	// operator pinned it (Pin) or quorum has been satisfied and
	// hysteresis has elapsed.
	ShardBits uint8

	// SourceModeSSM reflects the adopted addressing model.
	SourceModeSSM bool

	// PilotGroups is the union of Flags.GroupsValid payloads from
	// authoritative manifests that satisfy quorum. Used by listeners
	// with auto-join enabled (the listener composes
	// union(static, PilotGroups)).
	PilotGroups []uint16

	// SourceSet is the deduplicated union of Flags.SourcesValid
	// payloads across ALL currently-valid manifests (not gated by
	// authoritative quorum, per BRC-139 §Source set).
	SourceSet []netip.Addr

	// Successor, when non-nil, is the operator-announced incoming
	// generation tuple. The bridging window runs from "first observed
	// with quorum" through TransitionEpoch.
	Successor *SuccessorView

	// PilotsKnown is the number of distinct authoritative announcers
	// currently within TTL. Reported for metrics.
	PilotsKnown int

	// QuorumMet maps field name to whether the field has enough
	// agreeing authoritative announcers to satisfy the configured
	// quorum. Useful for telemetry.
	QuorumMet map[string]bool

	// DivergenceFields lists fields where authoritative announcers
	// currently disagree (more than one candidate value seen). Used for
	// the divergence counter.
	DivergenceFields []string
}

// SuccessorView is the consumer-side projection of a BRC-139 Successor
// block. The fields mirror [frame.SuccessorBlock] plus the per-consumer
// observation timestamp used to compute bridging-window deadlines.
type SuccessorView struct {
	GenerationID    [16]byte
	ShardBits       uint8
	SourceModeSSM   bool
	TransitionEpoch uint32

	// FirstObservedQuorumAt is the local time the Successor first
	// satisfied quorum. Used by consumers that floor the bridging
	// window to `autoConfig.bridgingWindow` regardless of
	// TransitionEpoch.
	FirstObservedQuorumAt time.Time
}

// Pin captures operator-pinned values that MUST NOT be overridden by
// adoption. Zero-valued fields are not pinned. Use [WithShardBitsPin]
// and [WithSourceModePin] to construct pins inline.
type Pin struct {
	ShardBits        uint8 // 0 ⇒ not pinned
	HasShardBitsPin  bool
	SourceModeSSM    bool // meaningful only when HasSourceModePin
	HasSourceModePin bool
}

// EvaluatorConfig configures adoption gating.
type EvaluatorConfig struct {
	// Quorum is the minimum distinct authoritative announcers needed
	// for a candidate value to be eligible for adoption. Defaults to 2.
	Quorum int

	// Hysteresis is the duration a candidate value must hold quorum
	// before being adopted. Zero selects "2 × AnnounceInterval" of any
	// contributing manifest.
	Hysteresis time.Duration

	// Pin carries operator-pinned values that override adoption.
	Pin Pin

	// Clock returns the current time. Tests override; production
	// callers leave nil so time.Now is used.
	Clock func() time.Time
}

// Evaluator computes the [Adopted] view from a [Registry] snapshot.
// Hysteresis tracking is stored on the Evaluator across Evaluate calls,
// so it is NOT safe for concurrent use; serialise calls.
type Evaluator struct {
	cfg EvaluatorConfig

	// hysteresis tracks the earliest time each candidate satisfied
	// quorum, per field. Used to enforce the configured Hysteresis
	// window.
	hysteresis map[fieldKey]time.Time

	// adopted holds the last-adopted values so a transient quorum
	// loss does not erase them.
	adopted Adopted
}

// NewEvaluator constructs an Evaluator with the given config. Missing
// fields default per [EvaluatorConfig].
func NewEvaluator(cfg EvaluatorConfig) *Evaluator {
	if cfg.Quorum <= 0 {
		cfg.Quorum = 2
	}
	return &Evaluator{
		cfg:        cfg,
		hysteresis: make(map[fieldKey]time.Time),
	}
}

type fieldKey struct {
	field string
	value uint64 // hashed candidate value
}

func (e *Evaluator) now() time.Time {
	if e.cfg.Clock != nil {
		return e.cfg.Clock()
	}
	return time.Now()
}

// Evaluate computes the adopted view from snap. Pinned fields short-
// circuit quorum evaluation. The Successor block is treated as a unit;
// quorum is computed on the tuple (GenerationID, ShardBits, SourceModeSSM,
// TransitionEpoch).
//
// Successive calls are stateful: hysteresis timers carry over, and the
// last-adopted view is retained when quorum is lost. Callers MUST
// serialise Evaluate.
func (e *Evaluator) Evaluate(snap []*Entry) Adopted {
	now := e.now()
	out := Adopted{
		QuorumMet:        make(map[string]bool),
		DivergenceFields: nil,
	}

	// Count authoritative announcers per (field, value).
	shardBitsT := map[uint8]*tallyT{}
	sourceModeT := map[bool]*tallyT{}
	successorT := map[successorKey]*tallyT{}
	pilotGroups := map[uint16]struct{}{}
	allSources := map[netip.Addr]struct{}{}

	for _, en := range snap {
		// SourceSet is not gated by Authoritative.
		for _, s := range en.Sources {
			allSources[s] = struct{}{}
		}
		if !en.Authoritative() {
			continue
		}
		out.PilotsKnown++

		bumpUint8(shardBitsT, en.ShardBits, en)
		bumpBool(sourceModeT, en.SourceModeSSM(), en)

		// Pilot-only manifests contribute groups; non-pilot
		// authoritative manifests do not (their groups are a self-
		// report of what THEY joined, not what listeners should join).
		// We follow the same rule for non-PilotOnly authoritative
		// manifests to keep auto-join strictly pilot-driven.
		if en.PilotOnly() {
			for _, g := range en.Groups {
				pilotGroups[g] = struct{}{}
			}
		}

		if en.Successor != nil {
			sv := successorKey{
				gen:             en.Successor.GenerationID,
				shardBits:       en.Successor.ShardBits,
				transitionEpoch: en.Successor.TransitionEpoch,
				ssm:             en.Successor.Flags&0x01 != 0,
			}
			bumpSuccessor(successorT, sv, en)
		}
	}

	out.SourceSet = sortAddrs(allSources)
	out.PilotGroups = sortUint16s(pilotGroups)

	// ShardBits adoption.
	if e.cfg.Pin.HasShardBitsPin {
		out.ShardBits = e.cfg.Pin.ShardBits
		out.QuorumMet["shard_bits"] = true
		if hasNonPinDisagreement(shardBitsT, e.cfg.Pin.ShardBits) {
			out.DivergenceFields = append(out.DivergenceFields, "shard_bits")
		}
	} else if v, ok := bestCandidate(shardBitsT, e.cfg.Quorum); ok {
		out.QuorumMet["shard_bits"] = true
		key := fieldKey{field: "shard_bits", value: uint64(v)}
		if t := e.checkHysteresis(key, now, shardBitsT[v].exemplar); now.Sub(t) >= 0 {
			// hysteresis elapsed (or absent ⇒ first observation; we
			// require >= hysteresis to elapse, so reject on equality
			// to keep the timer monotonically forward-moving).
			if e.hysteresisElapsed(key, now, shardBitsT[v].exemplar) {
				out.ShardBits = v
				e.adopted.ShardBits = v
				e.adopted.QuorumMet = out.QuorumMet
			} else {
				out.ShardBits = e.adopted.ShardBits
			}
		} else {
			out.ShardBits = e.adopted.ShardBits
		}
		if hasMultipleCandidates(shardBitsT) {
			out.DivergenceFields = append(out.DivergenceFields, "shard_bits")
		}
	} else {
		// No quorum; retain last adopted.
		out.ShardBits = e.adopted.ShardBits
		out.QuorumMet["shard_bits"] = false
		if hasMultipleCandidates(shardBitsT) {
			out.DivergenceFields = append(out.DivergenceFields, "shard_bits")
		}
	}

	// SourceModeSSM adoption.
	if e.cfg.Pin.HasSourceModePin {
		out.SourceModeSSM = e.cfg.Pin.SourceModeSSM
		out.QuorumMet["source_mode"] = true
		if hasNonPinDisagreementBool(sourceModeT, e.cfg.Pin.SourceModeSSM) {
			out.DivergenceFields = append(out.DivergenceFields, "source_mode")
		}
	} else if v, ok := bestCandidateBool(sourceModeT, e.cfg.Quorum); ok {
		out.QuorumMet["source_mode"] = true
		key := fieldKey{field: "source_mode", value: boolToUint64(v)}
		if e.hysteresisElapsed(key, now, sourceModeT[v].exemplar) {
			out.SourceModeSSM = v
			e.adopted.SourceModeSSM = v
		} else {
			out.SourceModeSSM = e.adopted.SourceModeSSM
		}
		if hasMultipleCandidatesBool(sourceModeT) {
			out.DivergenceFields = append(out.DivergenceFields, "source_mode")
		}
	} else {
		out.SourceModeSSM = e.adopted.SourceModeSSM
		out.QuorumMet["source_mode"] = false
	}

	// Successor adoption (unit candidate). Hysteresis timer keyed by
	// the tuple so a new Successor restarts the timer.
	if sv, ok := bestSuccessor(successorT, e.cfg.Quorum); ok {
		// Enforce ±1 ShardBits-shift relative to current adopted view.
		if withinOneBit(out.ShardBits, sv.shardBits) {
			out.QuorumMet["successor"] = true
			key := fieldKey{field: "successor", value: successorHash(sv)}
			if e.hysteresisElapsed(key, now, successorT[sv].exemplar) {
				if e.adopted.Successor == nil || e.adopted.Successor.GenerationID != sv.gen {
					e.adopted.Successor = &SuccessorView{
						GenerationID:          sv.gen,
						ShardBits:             sv.shardBits,
						SourceModeSSM:         sv.ssm,
						TransitionEpoch:       sv.transitionEpoch,
						FirstObservedQuorumAt: now,
					}
				}
				out.Successor = e.adopted.Successor
			}
		}
	} else {
		e.adopted.Successor = nil
		out.Successor = nil
		// Reset hysteresis entries for any prior successor candidate.
		for k := range e.hysteresis {
			if k.field == "successor" {
				delete(e.hysteresis, k)
			}
		}
	}

	sort.Strings(out.DivergenceFields)
	return out
}

// hysteresisElapsed reports whether the candidate (field,value) has held
// quorum for at least the configured Hysteresis duration. On first call
// for a (field,value) tuple, it records the current time and returns
// false (the candidate must wait one full hysteresis window before
// adoption).
func (e *Evaluator) hysteresisElapsed(k fieldKey, now time.Time, exemplar *Entry) bool {
	first, ok := e.hysteresis[k]
	if !ok {
		e.hysteresis[k] = now
		return e.cfg.Hysteresis == 0 && exemplar.AnnounceInterval == 0
	}
	window := e.cfg.Hysteresis
	if window == 0 {
		window = 2 * time.Duration(exemplar.AnnounceInterval) * time.Second
	}
	return now.Sub(first) >= window
}

// checkHysteresis is a no-op accessor kept for symmetry; primary work
// happens in hysteresisElapsed. Exposed in case callers want to observe
// the first-quorum timestamp for telemetry.
func (e *Evaluator) checkHysteresis(k fieldKey, now time.Time, _ *Entry) time.Time {
	if t, ok := e.hysteresis[k]; ok {
		return t
	}
	return now
}

// successorKey is the discriminator for tallying Successor candidates.
type successorKey struct {
	gen             [16]byte
	shardBits       uint8
	transitionEpoch uint32
	ssm             bool
}

func successorHash(sk successorKey) uint64 {
	// Cheap fold for hysteresis-key uniqueness; collisions are
	// tolerable since the hysteresis map is per-(field,value) and we
	// only need stable identity per unique successorKey.
	var h uint64
	for i := 0; i < 16; i++ {
		h = h*131 + uint64(sk.gen[i])
	}
	h = h*131 + uint64(sk.shardBits)
	h = h*131 + uint64(sk.transitionEpoch)
	if sk.ssm {
		h = h*131 + 1
	}
	return h
}

func bumpUint8(m map[uint8]*tallyT, v uint8, e *Entry) {
	t, ok := m[v]
	if !ok {
		t = &tallyT{}
		m[v] = t
	}
	t.count++
	if t.exemplar == nil {
		t.exemplar = e
	}
}

func bumpBool(m map[bool]*tallyT, v bool, e *Entry) {
	t, ok := m[v]
	if !ok {
		t = &tallyT{}
		m[v] = t
	}
	t.count++
	if t.exemplar == nil {
		t.exemplar = e
	}
}

func bumpSuccessor(m map[successorKey]*tallyT, v successorKey, e *Entry) {
	t, ok := m[v]
	if !ok {
		t = &tallyT{}
		m[v] = t
	}
	t.count++
	if t.exemplar == nil {
		t.exemplar = e
	}
}

type tallyT struct {
	count    int
	exemplar *Entry
}

func bestCandidate(m map[uint8]*tallyT, quorum int) (uint8, bool) {
	var best uint8
	bestCount := 0
	for v, t := range m {
		if t.count > bestCount {
			best = v
			bestCount = t.count
		}
	}
	if bestCount < quorum {
		return 0, false
	}
	return best, true
}

func bestCandidateBool(m map[bool]*tallyT, quorum int) (bool, bool) {
	var best bool
	bestCount := 0
	for v, t := range m {
		if t.count > bestCount {
			best = v
			bestCount = t.count
		}
	}
	if bestCount < quorum {
		return false, false
	}
	return best, true
}

func bestSuccessor(m map[successorKey]*tallyT, quorum int) (successorKey, bool) {
	var best successorKey
	bestCount := 0
	for v, t := range m {
		if t.count > bestCount {
			best = v
			bestCount = t.count
		}
	}
	if bestCount < quorum {
		return successorKey{}, false
	}
	return best, true
}

func hasMultipleCandidates(m map[uint8]*tallyT) bool { return len(m) > 1 }
func hasMultipleCandidatesBool(m map[bool]*tallyT) bool {
	return len(m) > 1
}

func hasNonPinDisagreement(m map[uint8]*tallyT, pin uint8) bool {
	for v := range m {
		if v != pin {
			return true
		}
	}
	return false
}

func hasNonPinDisagreementBool(m map[bool]*tallyT, pin bool) bool {
	for v := range m {
		if v != pin {
			return true
		}
	}
	return false
}

func sortAddrs(m map[netip.Addr]struct{}) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func sortUint16s(m map[uint16]struct{}) []uint16 {
	out := make([]uint16, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func boolToUint64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// withinOneBit duplicates the helper from the frame package so the
// manifest package has no upward dependency on internal frame helpers
// and the adoption-side ±1 check can apply to the locally-adopted
// ShardBits (which is what the BRC-139 normative rule requires for
// auto-config consumers).
func withinOneBit(a, b uint8) bool {
	if a > b {
		return a-b <= 1
	}
	return b-a <= 1
}
