// Package bootstrap maintains a live set of IPv6 source addresses resolved
// from a list of DNS names and/or IPv6 literals. It is intended to drive
// the per-control-group bootstrap source lists used for SSM joins on the
// beacon, manifest, and subtree-announce groups.
//
// Resolution semantics:
//
//   - Startup is fail-closed. [Resolver.Start] returns an error if no entry
//     resolves to at least one AAAA record.
//   - Subsequent refreshes are best-effort. Failures keep the last good set
//     and increment [Resolver.ResolveErrors]; the active source set never
//     spontaneously empties.
//   - A diff against the previous set is delivered via the OnChange
//     callback, suitable for issuing MCAST_JOIN_SOURCE_GROUP /
//     MCAST_LEAVE_SOURCE_GROUP calls.
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// LookupFunc resolves a DNS name to IPv6 addresses. The default is
// [net.DefaultResolver.LookupNetIP] filtered to IPv6. Override for tests.
type LookupFunc func(ctx context.Context, name string) ([]netip.Addr, error)

// DefaultLookup uses [net.DefaultResolver] to resolve a name to IPv6
// addresses, returning only AAAA results.
func DefaultLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", name)
	if err != nil {
		return nil, err
	}
	out := addrs[:0]
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}

// Resolver holds the configuration and live state for one bootstrap list
// (e.g. one of beacon / manifest / subtreeAnnounce).
type Resolver struct {
	// Entries is the list of DNS names and/or IPv6 literals. Required.
	Entries []string

	// Refresh is the periodic re-resolve interval. Defaults to 30s.
	Refresh time.Duration

	// Lookup resolves a DNS name to IPv6 addresses. Defaults to
	// [DefaultLookup]. Override for tests or for using a custom
	// resolver. Literal IPv6 entries bypass Lookup and are added
	// directly.
	Lookup LookupFunc

	// OnChange is invoked after every refresh that yields a different
	// set. It is called synchronously from the refresh goroutine while
	// the internal mutex is NOT held, so callbacks may issue join/leave
	// syscalls without deadlock risk. Optional.
	OnChange func(added, removed []netip.Addr)

	mu      sync.RWMutex
	current []netip.Addr // sorted ascending

	errs atomic.Uint64
}

// Start performs the initial resolution synchronously and starts the
// periodic refresh goroutine. The goroutine exits when ctx is cancelled.
// Returns an error if no entry resolves to >= 1 AAAA record.
func (r *Resolver) Start(ctx context.Context) error {
	if len(r.Entries) == 0 {
		return errors.New("bootstrap: no entries configured")
	}
	if r.Refresh <= 0 {
		r.Refresh = 30 * time.Second
	}
	if r.Lookup == nil {
		r.Lookup = DefaultLookup
	}

	set, err := r.resolveAll(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap: initial resolution: %w", err)
	}
	if len(set) == 0 {
		return errors.New("bootstrap: no IPv6 addresses resolved from any entry; fail-closed")
	}
	r.mu.Lock()
	r.current = set
	r.mu.Unlock()
	if r.OnChange != nil {
		r.OnChange(set, nil)
	}

	go r.loop(ctx)
	return nil
}

// Current returns a copy of the currently-resolved address set.
func (r *Resolver) Current() []netip.Addr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]netip.Addr, len(r.current))
	copy(out, r.current)
	return out
}

// ResolveErrors returns the cumulative count of failed refresh attempts.
// A non-zero value indicates DNS issues that did not (yet) empty the
// active set.
func (r *Resolver) ResolveErrors() uint64 {
	return r.errs.Load()
}

func (r *Resolver) loop(ctx context.Context) {
	t := time.NewTicker(r.Refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			next, err := r.resolveAll(ctx)
			if err != nil {
				r.errs.Add(1)
				continue
			}
			if len(next) == 0 {
				// Refresh would empty the set; retain last good
				// and surface as an error so the operator notices.
				r.errs.Add(1)
				continue
			}
			r.mu.Lock()
			added, removed := diffSorted(r.current, next)
			r.current = next
			r.mu.Unlock()
			if (len(added) > 0 || len(removed) > 0) && r.OnChange != nil {
				r.OnChange(added, removed)
			}
		}
	}
}

func (r *Resolver) resolveAll(ctx context.Context) ([]netip.Addr, error) {
	seen := make(map[netip.Addr]struct{})
	var anyErr error
	for _, e := range r.Entries {
		// IPv6 literal short-circuit.
		if a, err := netip.ParseAddr(e); err == nil {
			if a.Is6() && !a.Is4In6() {
				seen[a.Unmap()] = struct{}{}
			}
			continue
		}
		// DNS name.
		addrs, err := r.Lookup(ctx, e)
		if err != nil {
			anyErr = err
			continue
		}
		for _, a := range addrs {
			seen[a] = struct{}{}
		}
	}
	// If the result is empty AND every lookup failed, surface the error;
	// if at least one entry resolved or was a literal, anyErr is
	// suppressed because some addresses are present.
	if len(seen) == 0 && anyErr != nil {
		return nil, anyErr
	}
	out := make([]netip.Addr, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

// diffSorted returns the (added, removed) delta from prev to next; both
// inputs must be sorted ascending.
func diffSorted(prev, next []netip.Addr) (added, removed []netip.Addr) {
	i, j := 0, 0
	for i < len(prev) && j < len(next) {
		switch {
		case prev[i].Less(next[j]):
			removed = append(removed, prev[i])
			i++
		case next[j].Less(prev[i]):
			added = append(added, next[j])
			j++
		default:
			i++
			j++
		}
	}
	removed = append(removed, prev[i:]...)
	added = append(added, next[j:]...)
	return added, removed
}
