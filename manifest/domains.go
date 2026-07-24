// BRC-148 per-domain (object-plane) adoption. The BRC-139 normative
// consumer profile — authoritative quorum, hysteresis, manual-pin
// precedence, divergence telemetry, and Successor-block generation
// transitions — applies per DomainID, using the same tally machinery as the
// top-level fields. Domain 0x0 never adopts here: the top-level
// ShardBits/SourceModeSSM/Successor remain authoritative for the
// transaction plane (BRC-148 §Backward compatibility).

package manifest

import (
	"fmt"
	"time"

	"github.com/lightwebinc/shard-common/frame"
)

// DomainAdoption is the adopted view of one object plane (BRC-148),
// the per-domain analogue of the top-level Adopted fields.
type DomainAdoption struct {
	// ShardBits is the plane's adopted (or pinned) shard-bit width;
	// 0 = nothing adopted yet.
	ShardBits uint8

	// SourceModeSSM reflects the plane's adopted addressing model
	// (DomainFlagSourceModeSSM under quorum + hysteresis).
	SourceModeSSM bool

	// Successor, when non-nil, is the plane's in-flight generation
	// transition (per-descriptor Successor block under quorum).
	Successor *SuccessorView

	// QuorumMet reports whether the plane's shard-bits candidate currently
	// satisfies quorum (always true for a pinned domain).
	QuorumMet bool

	// Divergent reports whether authoritative announcers currently
	// disagree on the plane's shard-bits (or disagree with a pin).
	Divergent bool
}

func domainField(id uint8, field string) string {
	return fmt.Sprintf("domain_%d_%s", id, field)
}

// evaluateDomains folds the snapshot's per-plane descriptors into
// out.Domains, mirroring the top-level adoption rules per DomainID. It is
// called by [Evaluator.Evaluate]; the same serialisation requirement
// applies.
func (e *Evaluator) evaluateDomains(snap []*Entry, out *Adopted, now time.Time) {
	type domTally struct {
		bits map[uint8]*tallyT
		ssm  map[bool]*tallyT
		succ map[successorKey]*tallyT
	}
	tallies := map[uint8]*domTally{}

	for _, en := range snap {
		if !en.Authoritative() {
			continue
		}
		for i := range en.Domains {
			d := &en.Domains[i]
			if d.DomainID == 0 {
				continue // top-level fields govern the transaction plane
			}
			dt := tallies[d.DomainID]
			if dt == nil {
				dt = &domTally{
					bits: map[uint8]*tallyT{},
					ssm:  map[bool]*tallyT{},
					succ: map[successorKey]*tallyT{},
				}
				tallies[d.DomainID] = dt
			}
			bumpUint8(dt.bits, d.ShardBits, en)
			bumpBool(dt.ssm, d.Flags&frame.DomainFlagSourceModeSSM != 0, en)
			if d.Successor != nil {
				bumpSuccessor(dt.succ, successorKey{
					gen:             d.Successor.GenerationID,
					shardBits:       d.Successor.ShardBits,
					transitionEpoch: d.Successor.TransitionEpoch,
					ssm:             d.Successor.Flags&frame.SuccessorFlagSourceModeSSM != 0,
				}, en)
			}
		}
	}

	// Evaluate the union of currently-announced, pinned, and previously-
	// adopted domains (retention across transient quorum loss).
	ids := map[uint8]struct{}{}
	for id := range tallies {
		ids[id] = struct{}{}
	}
	for id := range e.cfg.Pin.DomainShardBits {
		if id != 0 {
			ids[id] = struct{}{}
		}
	}
	for id := range e.adopted.Domains {
		ids[id] = struct{}{}
	}
	if len(ids) == 0 {
		return
	}
	if e.adopted.Domains == nil {
		e.adopted.Domains = map[uint8]DomainAdoption{}
	}
	out.Domains = make(map[uint8]DomainAdoption, len(ids))

	for id := range ids {
		da := e.adopted.Domains[id] // zero value when new
		dt := tallies[id]
		bitsField := domainField(id, "shard_bits")

		if pin, pinned := e.cfg.Pin.DomainShardBits[id]; pinned {
			da.ShardBits = pin
			da.QuorumMet = true
			da.Divergent = dt != nil && hasNonPinDisagreement(dt.bits, pin)
		} else if dt != nil {
			if v, ok := bestCandidate(dt.bits, e.cfg.Quorum); ok {
				da.QuorumMet = true
				key := fieldKey{field: bitsField, value: uint64(v)}
				if e.hysteresisElapsed(key, now, dt.bits[v].exemplar) {
					da.ShardBits = v
				}
			} else {
				da.QuorumMet = false
			}
			da.Divergent = hasMultipleCandidates(dt.bits)

			if v, ok := bestCandidateBool(dt.ssm, e.cfg.Quorum); ok {
				key := fieldKey{field: domainField(id, "source_mode"), value: boolToUint64(v)}
				if e.hysteresisElapsed(key, now, dt.ssm[v].exemplar) {
					da.SourceModeSSM = v
				}
			}

			if sv, ok := bestSuccessor(dt.succ, e.cfg.Quorum); ok {
				if withinOneBit(da.ShardBits, sv.shardBits) {
					key := fieldKey{field: domainField(id, "successor"), value: successorHash(sv)}
					if e.hysteresisElapsed(key, now, dt.succ[sv].exemplar) {
						if da.Successor == nil || da.Successor.GenerationID != sv.gen {
							da.Successor = &SuccessorView{
								GenerationID:          sv.gen,
								ShardBits:             sv.shardBits,
								SourceModeSSM:         sv.ssm,
								TransitionEpoch:       sv.transitionEpoch,
								FirstObservedQuorumAt: now,
							}
						}
					}
				}
			} else if len(dt.succ) == 0 {
				da.Successor = nil
				succField := domainField(id, "successor")
				for k := range e.hysteresis {
					if k.field == succField {
						delete(e.hysteresis, k)
					}
				}
			}
		} else {
			// Neither announced nor pinned this pass: retain the adopted
			// view, report quorum lost.
			da.QuorumMet = false
			da.Divergent = false
		}

		if da.Divergent {
			out.DivergenceFields = append(out.DivergenceFields, bitsField)
		}
		out.QuorumMet[bitsField] = da.QuorumMet
		e.adopted.Domains[id] = da
		out.Domains[id] = da
	}
}
