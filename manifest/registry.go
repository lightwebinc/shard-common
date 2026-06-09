// Package manifest implements the BRC-139 shard-manifest consumer profile:
// a TTL-bounded registry of received manifests, a quorum + hysteresis
// evaluator that produces an adopted view of (ShardBits, SourceMode,
// Successor) fields, and a deduplicated source-set view.
//
// The package is transport-agnostic: callers feed decoded
// [github.com/lightwebinc/shard-common/frame.ShardManifest] values into
// [Registry.Upsert] along with the IPv6 source address from the datagram
// header. A separate [Applier] interface lets each component plug its own
// policy (restart vs. live re-shard, additive auto-join, etc.).
//
// All public types are safe for concurrent use unless noted.
package manifest

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/lightwebinc/shard-common/frame"
)

// Entry is one received manifest, keyed by (SrcIPv6, InstanceID), with
// observation metadata. Entries are evicted after their effective TTL
// (Epoch + TTL, or Epoch + 3 × AnnounceInterval when TTL=0).
type Entry struct {
	SrcIPv6    netip.Addr
	InstanceID uint32

	Flags            byte
	ShardBits        uint8
	RoleHint         uint8
	Epoch            uint32
	TTL              uint16
	AnnounceInterval uint16
	GenerationID     [16]byte

	Sources   []netip.Addr // deduplicated, ordered by string repr for stability
	Groups    []uint16     // expanded from list or bitmap form
	Successor *frame.SuccessorBlock

	receivedAt time.Time
	expiresAt  time.Time
}

// Authoritative reports whether the entry came from an Authoritative
// announcer.
func (e *Entry) Authoritative() bool {
	return e.Flags&frame.ShardManifestFlagAuthoritative != 0
}

// SourceModeSSM reports the announcer's declared data-plane addressing
// model (true ⇒ SSM, false ⇒ ASM).
func (e *Entry) SourceModeSSM() bool {
	return e.Flags&frame.ShardManifestFlagSourceModeSSM != 0
}

// PilotOnly reports whether the announcer is a pilot/assignment-only
// emitter (no own group joins claimed).
func (e *Entry) PilotOnly() bool {
	return e.Flags&frame.ShardManifestFlagPilotOnly != 0
}

// Registry is a TTL-bounded set of currently-valid BRC-139 manifests
// keyed by (SrcIPv6, InstanceID). It is safe for concurrent use.
type Registry struct {
	// DefaultTTL is the fallback TTL applied when a manifest carries
	// TTL=0. When zero (the default), 3 × AnnounceInterval is used per
	// the BRC-139 §Cadence guidance.
	DefaultTTL time.Duration

	// Clock returns the current time. Tests override this; production
	// callers leave it nil so time.Now is used.
	Clock func() time.Time

	mu      sync.RWMutex
	entries map[entryKey]*Entry
}

type entryKey struct {
	src        netip.Addr
	instanceID uint32
}

// NewRegistry returns an empty Registry with the given default TTL.
// Passing 0 selects the "3 × AnnounceInterval" fallback per BRC-139.
func NewRegistry(defaultTTL time.Duration) *Registry {
	return &Registry{
		DefaultTTL: defaultTTL,
		entries:    make(map[entryKey]*Entry),
	}
}

func (r *Registry) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

// Upsert inserts or refreshes an entry derived from m, observed from the
// IPv6 datagram source src. The caller is responsible for ManifestCRC
// verification (already done by [frame.DecodeShardManifest]) and for
// rejecting datagrams with malformed payloads.
//
// When m carries the Shutdown flag the corresponding entry is evicted
// immediately (BRC-139 §Flags).
func (r *Registry) Upsert(src netip.Addr, m *frame.ShardManifest) *Entry {
	k := entryKey{src: src.WithZone(""), instanceID: m.InstanceID}

	r.mu.Lock()
	defer r.mu.Unlock()

	if m.Flags&frame.ShardManifestFlagShutdown != 0 {
		delete(r.entries, k)
		return nil
	}

	now := r.now()
	ttl := time.Duration(m.TTL) * time.Second
	if ttl == 0 {
		ttl = r.DefaultTTL
		if ttl == 0 {
			ttl = 3 * time.Duration(m.AnnounceInterval) * time.Second
		}
	}

	e := &Entry{
		SrcIPv6:          k.src,
		InstanceID:       m.InstanceID,
		Flags:            m.Flags,
		ShardBits:        m.ShardBits,
		RoleHint:         m.RoleHint,
		Epoch:            m.Epoch,
		TTL:              m.TTL,
		AnnounceInterval: m.AnnounceInterval,
		GenerationID:     m.GenerationID,
		Sources:          dedupSources(m.Sources),
		Groups:           expandGroups(m),
		Successor:        m.Successor,
		receivedAt:       now,
		expiresAt:        now.Add(ttl),
	}
	r.entries[k] = e
	return e
}

// Evict removes any entries whose effective TTL has passed. Callers
// SHOULD invoke Evict on a 1 s tick (or thereabouts) so divergence
// metrics reflect the current view.
func (r *Registry) Evict() {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	for k, e := range r.entries {
		if !now.Before(e.expiresAt) {
			delete(r.entries, k)
		}
	}
}

// Snapshot returns a copy of every currently-valid entry. The returned
// slice is owned by the caller; entries' internal slice fields (Sources,
// Groups) are not deep-copied — treat them as read-only.
func (r *Registry) Snapshot() []*Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SrcIPv6 != out[j].SrcIPv6 {
			return out[i].SrcIPv6.Less(out[j].SrcIPv6)
		}
		return out[i].InstanceID < out[j].InstanceID
	})
	return out
}

// Len returns the number of currently-held entries.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// dedupSources returns a deduplicated, sorted slice of source IPv6
// addresses. The input is a slice of 16-byte arrays as carried in the
// wire format; the output is normalised to [netip.Addr] for downstream
// composition.
func dedupSources(in [][16]byte) []netip.Addr {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[netip.Addr]struct{}, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, b := range in {
		a := netip.AddrFrom16(b)
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// expandGroups returns the list of joined-group indices declared by m,
// derived from either list form (m.Groups) or bitmap form (m.Bitmap).
// Returns nil when GroupsValid=0 or when the payload is empty.
func expandGroups(m *frame.ShardManifest) []uint16 {
	if m.Flags&frame.ShardManifestFlagGroupsValid == 0 {
		return nil
	}
	if len(m.Groups) > 0 {
		out := make([]uint16, len(m.Groups))
		copy(out, m.Groups)
		return out
	}
	if len(m.Bitmap) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(m.Bitmap)*4) // ~25% density estimate
	for i, b := range m.Bitmap {
		if b == 0 {
			continue
		}
		for bit := 0; bit < 8; bit++ {
			if b&(1<<bit) != 0 {
				out = append(out, uint16(i*8+bit))
			}
		}
	}
	return out
}
