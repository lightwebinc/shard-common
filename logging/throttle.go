package logging

import (
	"sync"
	"time"
)

// Throttle implements the "log-once-then-count" discipline required for
// data-plane and repeated-error events (see the Log economy section of the
// unified-logging plan). The first occurrence of a key in a window returns
// emit=true with the count so far; subsequent occurrences within the window
// are suppressed and accumulated. When the window elapses, the next occurrence
// emits again and reports how many were suppressed.
//
// It allocates only on first sight of a key and never on the suppressed path
// beyond a map lookup + atomic-free counter increment under a short lock, so it
// is safe on warm paths (it is NOT intended for the zero-alloc per-packet hot
// path — those events stay at Debug and are gated by level).
type Throttle struct {
	window time.Duration
	mu     sync.Mutex
	state  map[string]*throttleEntry
	now    func() time.Time // injectable for tests
}

type throttleEntry struct {
	windowStart time.Time
	suppressed  uint64
}

// NewThrottle returns a Throttle that emits at most once per key per window.
func NewThrottle(window time.Duration) *Throttle {
	return &Throttle{
		window: window,
		state:  make(map[string]*throttleEntry),
		now:    time.Now,
	}
}

// Allow reports whether an event for key should be logged now. When emit is
// true, suppressed is the number of occurrences hidden since the last emit for
// this key (0 on the first ever emit).
func (t *Throttle) Allow(key string) (emit bool, suppressed uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	e, ok := t.state[key]
	if !ok {
		t.state[key] = &throttleEntry{windowStart: now}
		return true, 0
	}
	if now.Sub(e.windowStart) >= t.window {
		s := e.suppressed
		e.windowStart = now
		e.suppressed = 0
		return true, s
	}
	e.suppressed++
	return false, 0
}
