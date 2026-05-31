package manifest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/frame"
)

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func authoritativeManifest(instanceID uint32, shardBits uint8, groups []uint16) *frame.ShardManifest {
	m := &frame.ShardManifest{
		Flags:            frame.ShardManifestFlagAuthoritative | frame.ShardManifestFlagGroupsValid | frame.ShardManifestFlagPilotOnly,
		InstanceID:       instanceID,
		Epoch:            1746800000,
		AnnounceInterval: 300,
		ShardBits:        shardBits,
		RoleHint:         frame.RoleHintManifestOnly,
		Groups:           append([]uint16(nil), groups...),
	}
	return m
}

func TestRegistry_UpsertAndEvict(t *testing.T) {
	clock := time.Unix(1746800100, 0)
	r := NewRegistry(0)
	r.Clock = func() time.Time { return clock }

	m1 := authoritativeManifest(1, 8, []uint16{0, 1, 2})
	m1.TTL = 60
	r.Upsert(mustAddr("fd20::1"), m1)
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1", r.Len())
	}

	// Same key (same src + instanceID) overwrites.
	m1b := authoritativeManifest(1, 9, []uint16{3, 4})
	m1b.TTL = 60
	r.Upsert(mustAddr("fd20::1"), m1b)
	if r.Len() != 1 {
		t.Fatalf("Len = %d, want 1 after overwrite", r.Len())
	}

	// Different src → separate entry.
	r.Upsert(mustAddr("fd20::2"), m1b)
	if r.Len() != 2 {
		t.Fatalf("Len = %d, want 2", r.Len())
	}

	// Advance past TTL and evict.
	clock = clock.Add(120 * time.Second)
	r.Evict()
	if r.Len() != 0 {
		t.Fatalf("Len = %d, want 0 after evict", r.Len())
	}
}

func TestRegistry_ShutdownEvictsImmediately(t *testing.T) {
	r := NewRegistry(60 * time.Second)
	m := authoritativeManifest(1, 8, []uint16{0, 1})
	m.TTL = 600
	r.Upsert(mustAddr("fd20::1"), m)
	if r.Len() != 1 {
		t.Fatalf("setup: Len = %d", r.Len())
	}

	// Shutdown flag set ⇒ evict.
	m.Flags |= frame.ShardManifestFlagShutdown
	r.Upsert(mustAddr("fd20::1"), m)
	if r.Len() != 0 {
		t.Errorf("Shutdown flag should evict; Len = %d", r.Len())
	}
}

func TestRegistry_DefaultTTLFallback(t *testing.T) {
	clock := time.Unix(1746800000, 0)
	r := NewRegistry(0) // 0 ⇒ 3 × AnnounceInterval
	r.Clock = func() time.Time { return clock }

	m := authoritativeManifest(1, 8, []uint16{0})
	m.AnnounceInterval = 60
	m.TTL = 0
	r.Upsert(mustAddr("fd20::1"), m)

	clock = clock.Add(179 * time.Second) // still inside 3 × 60 = 180
	r.Evict()
	if r.Len() != 1 {
		t.Errorf("evicted too soon; Len = %d", r.Len())
	}

	clock = clock.Add(2 * time.Second) // now past 180
	r.Evict()
	if r.Len() != 0 {
		t.Errorf("should have evicted; Len = %d", r.Len())
	}
}

func TestRegistry_BitmapExpansion(t *testing.T) {
	r := NewRegistry(60 * time.Second)
	m := &frame.ShardManifest{
		Flags:            frame.ShardManifestFlagAuthoritative | frame.ShardManifestFlagGroupsValid,
		InstanceID:       1,
		Epoch:            1746800000,
		AnnounceInterval: 300,
		ShardBits:        4,
		Bitmap:           []byte{0b00010101, 0b10000000}, // groups 0,2,4,15
	}
	e := r.Upsert(mustAddr("fd20::1"), m)
	want := []uint16{0, 2, 4, 15}
	if len(e.Groups) != len(want) {
		t.Fatalf("Groups len = %d, want %d", len(e.Groups), len(want))
	}
	for i, g := range want {
		if e.Groups[i] != g {
			t.Errorf("Groups[%d] = %d, want %d", i, e.Groups[i], g)
		}
	}
}

func TestRegistry_SourcesDeduped(t *testing.T) {
	r := NewRegistry(60 * time.Second)
	a := mustAddr("fd20::5").As16()
	m := &frame.ShardManifest{
		Flags:            frame.ShardManifestFlagAuthoritative | frame.ShardManifestFlagSourcesValid,
		InstanceID:       1,
		Epoch:            1746800000,
		AnnounceInterval: 300,
		ShardBits:        4,
		Sources:          [][16]byte{a, a, a}, // duplicates
	}
	e := r.Upsert(mustAddr("fd20::1"), m)
	if len(e.Sources) != 1 {
		t.Errorf("Sources len = %d, want 1 after dedup", len(e.Sources))
	}
}
