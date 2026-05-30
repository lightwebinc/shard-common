package bootstrap

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// staticLookup returns a fixed table; missing names return ErrNotFound.
type staticLookup struct {
	mu    sync.Mutex
	table map[string][]netip.Addr
	calls atomic.Uint64
}

var errNotFound = errors.New("name not found")

func (s *staticLookup) Lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	addrs, ok := s.table[name]
	if !ok {
		return nil, errNotFound
	}
	out := make([]netip.Addr, len(addrs))
	copy(out, addrs)
	return out, nil
}

func (s *staticLookup) Set(name string, addrs []netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.table[name] = addrs
}

func TestResolver_LiteralOnly(t *testing.T) {
	t.Parallel()
	r := &Resolver{
		Entries: []string{"fd00::1", "fd00::2", "::1"},
		Refresh: time.Hour,
		Lookup:  (&staticLookup{table: map[string][]netip.Addr{}}).Lookup,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := r.Current()
	wantStrs := []string{"::1", "fd00::1", "fd00::2"}
	if len(got) != len(wantStrs) {
		t.Fatalf("Current len = %d, want %d (%v)", len(got), len(wantStrs), got)
	}
	for i, s := range wantStrs {
		if got[i].String() != s {
			t.Errorf("Current[%d] = %s, want %s", i, got[i], s)
		}
	}
}

func TestResolver_DNS(t *testing.T) {
	t.Parallel()
	lk := &staticLookup{table: map[string][]netip.Addr{
		"foo.example": {netip.MustParseAddr("fd20::5"), netip.MustParseAddr("fd20::6")},
		"bar.example": {netip.MustParseAddr("fd20::5")}, // dup with foo
	}}
	r := &Resolver{
		Entries: []string{"foo.example", "bar.example", "fd00::beef"},
		Refresh: time.Hour,
		Lookup:  lk.Lookup,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got := r.Current()
	want := []netip.Addr{
		netip.MustParseAddr("fd00::beef"),
		netip.MustParseAddr("fd20::5"),
		netip.MustParseAddr("fd20::6"),
	}
	sort.Slice(want, func(i, j int) bool { return want[i].Less(want[j]) })
	if len(got) != len(want) {
		t.Fatalf("Current = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Current[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestResolver_FailClosedOnEmpty(t *testing.T) {
	t.Parallel()
	lk := &staticLookup{table: map[string][]netip.Addr{}}
	r := &Resolver{
		Entries: []string{"nowhere.example"},
		Refresh: time.Hour,
		Lookup:  lk.Lookup,
	}
	err := r.Start(context.Background())
	if err == nil {
		t.Fatal("Start with all-empty resolution returned nil, want error")
	}
}

func TestResolver_NoEntries(t *testing.T) {
	t.Parallel()
	r := &Resolver{}
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("Start with no entries returned nil, want error")
	}
}

func TestResolver_RejectsIPv4Literal(t *testing.T) {
	t.Parallel()
	// "10.0.0.1" parses as IPv4 and is silently ignored (not added to
	// the set); if it's the only entry the resolver fails closed.
	r := &Resolver{
		Entries: []string{"10.0.0.1"},
		Refresh: time.Hour,
		Lookup:  (&staticLookup{table: map[string][]netip.Addr{}}).Lookup,
	}
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("Start with only-IPv4 literal returned nil, want fail-closed")
	}
}

func TestResolver_RefreshDiff(t *testing.T) {
	t.Parallel()
	lk := &staticLookup{table: map[string][]netip.Addr{
		"foo.example": {netip.MustParseAddr("fd00::1")},
	}}

	changes := make(chan struct{ added, removed []netip.Addr }, 8)
	r := &Resolver{
		Entries: []string{"foo.example"},
		Refresh: 20 * time.Millisecond,
		Lookup:  lk.Lookup,
		OnChange: func(added, removed []netip.Addr) {
			changes <- struct{ added, removed []netip.Addr }{added, removed}
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// First OnChange = initial set (added=[fd00::1]).
	select {
	case ch := <-changes:
		if len(ch.added) != 1 || ch.added[0].String() != "fd00::1" {
			t.Errorf("initial OnChange added = %v, want [fd00::1]", ch.added)
		}
		if len(ch.removed) != 0 {
			t.Errorf("initial OnChange removed = %v, want []", ch.removed)
		}
	case <-time.After(time.Second):
		t.Fatal("no initial OnChange")
	}

	// Mutate the table; the next refresh should diff.
	lk.Set("foo.example", []netip.Addr{
		netip.MustParseAddr("fd00::1"),
		netip.MustParseAddr("fd00::2"),
	})
	select {
	case ch := <-changes:
		if len(ch.added) != 1 || ch.added[0].String() != "fd00::2" {
			t.Errorf("diff OnChange added = %v, want [fd00::2]", ch.added)
		}
		if len(ch.removed) != 0 {
			t.Errorf("diff OnChange removed = %v, want []", ch.removed)
		}
	case <-time.After(time.Second):
		t.Fatal("no diff OnChange after table change")
	}

	// Now remove fd00::1; verify removal.
	lk.Set("foo.example", []netip.Addr{netip.MustParseAddr("fd00::2")})
	select {
	case ch := <-changes:
		if len(ch.removed) != 1 || ch.removed[0].String() != "fd00::1" {
			t.Errorf("removal OnChange removed = %v, want [fd00::1]", ch.removed)
		}
		if len(ch.added) != 0 {
			t.Errorf("removal OnChange added = %v, want []", ch.added)
		}
	case <-time.After(time.Second):
		t.Fatal("no removal OnChange")
	}
}

func TestResolver_RefreshFailureRetainsLastGood(t *testing.T) {
	t.Parallel()
	lk := &staticLookup{table: map[string][]netip.Addr{
		"foo.example": {netip.MustParseAddr("fd00::1")},
	}}

	r := &Resolver{
		Entries: []string{"foo.example"},
		Refresh: 20 * time.Millisecond,
		Lookup:  lk.Lookup,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Wipe the table so refresh resolves to empty.
	lk.Set("foo.example", nil)
	time.Sleep(100 * time.Millisecond)
	// Current set should still contain fd00::1 (last good retained).
	got := r.Current()
	if len(got) != 1 || got[0].String() != "fd00::1" {
		t.Errorf("Current after empty refresh = %v, want [fd00::1]", got)
	}
	if r.ResolveErrors() == 0 {
		t.Error("ResolveErrors = 0, want > 0 after empty refresh")
	}
}

func TestDiffSorted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		prev, next      []string
		wantAdd, wantRm []string
	}{
		{"no change", []string{"::1", "::2"}, []string{"::1", "::2"}, nil, nil},
		{"add tail", []string{"::1"}, []string{"::1", "::2"}, []string{"::2"}, nil},
		{"remove tail", []string{"::1", "::2"}, []string{"::1"}, nil, []string{"::2"}},
		{"swap", []string{"::1"}, []string{"::2"}, []string{"::2"}, []string{"::1"}},
		{"empty to set", nil, []string{"::1"}, []string{"::1"}, nil},
		{"set to empty", []string{"::1"}, nil, nil, []string{"::1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prev := parseAddrs(tc.prev)
			next := parseAddrs(tc.next)
			add, rm := diffSorted(prev, next)
			if !addrsEqual(add, parseAddrs(tc.wantAdd)) {
				t.Errorf("added = %v, want %v", add, tc.wantAdd)
			}
			if !addrsEqual(rm, parseAddrs(tc.wantRm)) {
				t.Errorf("removed = %v, want %v", rm, tc.wantRm)
			}
		})
	}
}

func parseAddrs(ss []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func addrsEqual(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
