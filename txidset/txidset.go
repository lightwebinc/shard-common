// Package txidset implements a two-tier TxID claim store used by both the
// proxy ingress dedup gate and the listener per-deployment egress dedup gate.
//
// # Two-tier design
//
// Tier 1 is an in-process fixed-capacity set keyed by TxID. A hit short-circuits
// before Redis is touched. The set is goroutine-safe and uses a ring buffer
// plus map for O(1) inserts and FIFO eviction. Memory usage is bounded by the
// configured capacity (~48 B/entry).
//
// Tier 2 is an optional Redis SET NX EX claim. When Redis is configured, a
// tier-1 miss falls through to Redis. The winner of the SETNX race proceeds;
// losers are suppressed. Redis errors fail open: the caller proceeds and an
// error is reported via the returned err.
//
// # Two operations
//
//   - Claim(prefix, txid) — synchronous; gates the caller's forward decision.
//     Used by the proxy ingress path and the listener egress path. Errors are
//     surfaced so callers can record fail-open metrics.
//
//   - Mark(prefix, txid) — fire-and-forget; populates the network-set so the
//     proxy can later observe "TxID is already on the network". Used by the
//     listener's optional courtesy write to the proxy's ingress namespace.
//     Errors are reported via a Recorder callback supplied at construction.
//
// # Local-only fallback
//
// New("", ...) constructs a tier-1-only Store: Claim performs only the local
// set test, and Mark is a no-op against the local set. This is the single-
// server / Redis-down topology described in the design.
package txidset

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// DefaultLocalCapacity is the default capacity of the tier-1 local set when
// the caller does not specify one. Sized for ~10 minutes of peak TPS.
const DefaultLocalCapacity = 1 << 20 // ~1 M entries

// Recorder is the optional metrics callback interface. All methods must be
// safe to call concurrently. Passing nil disables metric recording.
type Recorder interface {
	// ClaimLocalHit reports a tier-1 short-circuit (no Redis call).
	ClaimLocalHit(prefix string)
	// ClaimWon reports a tier-2 SETNX win (frame proceeds).
	ClaimWon(prefix string)
	// ClaimLost reports a tier-2 SETNX loss (frame suppressed).
	ClaimLost(prefix string)
	// ClaimError reports a Redis error during Claim (fail-open: caller proceeds).
	ClaimError(prefix string)
	// MarkSet reports a successful async SETNX that set a new key.
	MarkSet(prefix string)
	// MarkExisted reports a successful async SETNX where the key was present.
	MarkExisted(prefix string)
	// MarkError reports a Redis error during async Mark (mark is best-effort).
	MarkError(prefix string)
	// MarkDropped reports an async Mark dropped because the work queue was full.
	MarkDropped(prefix string)
}

// Config holds the parameters used to construct a Store. RedisAddr empty
// disables Redis and forces tier-1-only operation.
type Config struct {
	RedisAddr      string
	TTL            time.Duration // Used for Claim and Mark when no per-op TTL is supplied
	LocalCapacity  int           // Tier-1 set capacity; <=0 uses DefaultLocalCapacity
	MarkQueueDepth int           // Buffered worker queue for async Mark; <=0 uses default 4096
	MarkWorkers    int           // Goroutines draining the Mark queue; <=0 uses default 2
	DialTimeout    time.Duration // Redis dial timeout; <=0 uses 200ms
	OpTimeout      time.Duration // Redis read/write timeout per op; <=0 uses 50ms
	Recorder       Recorder      // Optional metric callbacks; may be nil
}

// Store is a two-tier (local + optional Redis) TxID claim store.
//
// Construct with [New]. The zero value is unusable. Store is goroutine-safe
// and intended to be shared between worker goroutines.
type Store struct {
	rec          Recorder
	client       *redis.Client // nil = local-only mode
	defaultTTL   time.Duration
	opTimeout    time.Duration
	local        *localSet
	markCh       chan markJob
	markWG       sync.WaitGroup
	stopOnce     sync.Once
	stopped      chan struct{}
	closeRedisOK bool
}

type markJob struct {
	prefix string
	key    string
	ttl    time.Duration
}

// New constructs a Store. When cfg.RedisAddr is empty, the Store operates
// in tier-1-only mode: Claim performs only the local-set test and Mark is
// a no-op (Recorder still receives MarkDropped events for visibility).
//
// When cfg.RedisAddr is set, New attempts a Ping with a short retry window
// to tolerate co-started Redis containers. On Ping failure it returns the
// error rather than silently degrading; callers that want fail-open boot
// behaviour can choose to log-and-continue using New("", ...).
func New(cfg Config) (*Store, error) {
	if cfg.TTL <= 0 {
		return nil, fmt.Errorf("txidset: TTL must be > 0 (got %s)", cfg.TTL)
	}
	if cfg.LocalCapacity <= 0 {
		cfg.LocalCapacity = DefaultLocalCapacity
	}
	if cfg.MarkQueueDepth <= 0 {
		cfg.MarkQueueDepth = 4096
	}
	if cfg.MarkWorkers <= 0 {
		cfg.MarkWorkers = 2
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 200 * time.Millisecond
	}
	if cfg.OpTimeout <= 0 {
		cfg.OpTimeout = 50 * time.Millisecond
	}

	s := &Store{
		rec:        cfg.Recorder,
		defaultTTL: cfg.TTL,
		opTimeout:  cfg.OpTimeout,
		local:      newLocalSet(cfg.LocalCapacity, cfg.TTL),
		markCh:     make(chan markJob, cfg.MarkQueueDepth),
		stopped:    make(chan struct{}),
	}

	if cfg.RedisAddr != "" {
		client := redis.NewClient(&redis.Options{
			Addr:         cfg.RedisAddr,
			DialTimeout:  cfg.DialTimeout,
			ReadTimeout:  cfg.OpTimeout,
			WriteTimeout: cfg.OpTimeout,
			MaxRetries:   -1, // fail-open at the application layer
		})
		if err := pingWithRetry(client, 10*time.Second); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("txidset: redis ping %s: %w", cfg.RedisAddr, err)
		}
		s.client = client
		s.closeRedisOK = true
	}

	for i := 0; i < cfg.MarkWorkers; i++ {
		s.markWG.Add(1)
		go s.markLoop()
	}

	return s, nil
}

// Claim attempts to win a tier-1 + tier-2 claim for txid under prefix.
//
// Semantics:
//
//   - (true, nil)  — caller is the first to claim; proceed (forward / multicast).
//   - (false, nil) — another claimant already holds the key (local or Redis);
//     suppress.
//   - (true, err)  — Redis call failed; fail-open. Caller should proceed and
//     log/count the error. Local set is still updated so subsequent same-process
//     calls dedup correctly.
//
// The local set is updated on every code path so this Store also acts as a
// pure in-process LRU when Redis is unavailable.
func (s *Store) Claim(prefix string, txid [32]byte) (bool, error) {
	if s.local.SeenAndAdd(txid) {
		if s.rec != nil {
			s.rec.ClaimLocalHit(prefix)
		}
		return false, nil
	}
	if s.client == nil {
		// Local-only: first sight from this Store's perspective.
		if s.rec != nil {
			s.rec.ClaimWon(prefix)
		}
		return true, nil
	}

	key := prefix + hex.EncodeToString(txid[:])
	ctx, cancel := context.WithTimeout(context.Background(), s.opTimeout)
	defer cancel()
	ok, err := s.client.SetNX(ctx, key, 1, s.defaultTTL).Result()
	if err != nil {
		if s.rec != nil {
			s.rec.ClaimError(prefix)
		}
		return true, err
	}
	if s.rec != nil {
		if ok {
			s.rec.ClaimWon(prefix)
		} else {
			s.rec.ClaimLost(prefix)
		}
	}
	return ok, nil
}

// Mark performs a best-effort asynchronous SETNX of prefix+txid in Redis.
// The local set is updated synchronously so subsequent Claim calls in the
// same process short-circuit.
//
// When the work queue is full the Mark is dropped (counted via Recorder.MarkDropped)
// rather than blocking the caller — Mark is a courtesy signal, never on the
// critical path.
//
// In local-only mode (no Redis configured) Mark only updates the local set;
// the Recorder still receives a MarkDropped event so operators can observe
// that the mark was a no-op.
func (s *Store) Mark(prefix string, txid [32]byte) {
	// Always populate local set so subsequent Claim calls in this process
	// short-circuit deterministically.
	s.local.SeenAndAdd(txid)

	if s.client == nil {
		if s.rec != nil {
			s.rec.MarkDropped(prefix)
		}
		return
	}

	key := prefix + hex.EncodeToString(txid[:])
	job := markJob{prefix: prefix, key: key, ttl: s.defaultTTL}
	select {
	case s.markCh <- job:
	default:
		if s.rec != nil {
			s.rec.MarkDropped(prefix)
		}
	}
}

// Close shuts down the async Mark workers and releases the Redis client.
// Safe to call multiple times; only the first call has effect.
func (s *Store) Close() error {
	var err error
	s.stopOnce.Do(func() {
		close(s.stopped)
		close(s.markCh)
		s.markWG.Wait()
		if s.closeRedisOK && s.client != nil {
			err = s.client.Close()
		}
	})
	return err
}

// Healthy reports whether the Store has a working Redis connection. Returns
// true in local-only mode (no Redis was ever required). Calls Ping with the
// configured op-timeout. Intended for /readyz handlers, not the hot path.
func (s *Store) Healthy() bool {
	if s.client == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.opTimeout)
	defer cancel()
	return s.client.Ping(ctx).Err() == nil
}

func (s *Store) markLoop() {
	defer s.markWG.Done()
	for job := range s.markCh {
		ctx, cancel := context.WithTimeout(context.Background(), s.opTimeout)
		ok, err := s.client.SetNX(ctx, job.key, 1, job.ttl).Result()
		cancel()
		if s.rec == nil {
			continue
		}
		switch {
		case err != nil:
			s.rec.MarkError(job.prefix)
		case ok:
			s.rec.MarkSet(job.prefix)
		default:
			s.rec.MarkExisted(job.prefix)
		}
	}
}

func pingWithRetry(c *redis.Client, total time.Duration) error {
	deadline := time.Now().Add(total)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		lastErr = c.Ping(ctx).Err()
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return lastErr
}
