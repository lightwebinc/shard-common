// Package aerospike provides an Aerospike Community Edition [cache.Backend].
// It targets the largest fleets where a single Redis instance becomes a
// bottleneck: Aerospike auto-shards and rebalances across nodes and serves
// predictable sub-millisecond reads from a hybrid RAM/SSD store.
//
// # Semantics mapping
//
//   - SetNX → a CREATE_ONLY write; a KEY_EXISTS_ERROR result is reported as
//     (false, nil) (another claimant won).
//   - Set   → a default (UPDATE) write.
//   - Get   → single-bin read; a missing record is (nil, nil).
//   - Del   → record delete.
//
// # TTL granularity (load-bearing constraint)
//
// Aerospike expiration is expressed in WHOLE SECONDS with a floor of 1s.
// Sub-second TTLs are not representable; callers using this backend MUST use
// ttl >= 1s. All TTLs in the multicast stack (dedup 10m/60s, frame caches
// 60s–10m, retransmit dedup-window 60s) satisfy this. A ttl <= 0 stores the
// record with no expiry.
//
// # Provisioning
//
// Community Edition requires an operator-provisioned namespace; the package
// writes to [Options.Namespace]/[Options.Set]. CE has no XDR or
// rack-awareness — for multi-region replication choose a Redis-compatible
// backend or Enterprise Edition.
package aerospike

import (
	"context"
	"fmt"
	"math"
	"time"

	aero "github.com/aerospike/aerospike-client-go/v8"
	atypes "github.com/aerospike/aerospike-client-go/v8/types"
)

// binName is the single bin holding the opaque value.
const binName = "v"

// aeroNeverExpire is the WritePolicy.Expiration sentinel for "never expire".
const aeroNeverExpire = math.MaxUint32 // 0xFFFFFFFF

// Backend is an Aerospike-backed cache backend.
type Backend struct {
	client    *aero.Client
	namespace string
	set       string
	opTimeout time.Duration
}

// Options configures [New].
type Options struct {
	Hosts       []string // seed nodes, host:port
	Namespace   string
	Set         string
	DialTimeout time.Duration // <=0 → 200ms
	OpTimeout   time.Duration // <=0 → 50ms
}

// New connects to the Aerospike cluster seeded by opts.Hosts and verifies the
// connection. It returns an error if no seed node is reachable.
func New(opts Options) (*Backend, error) {
	if len(opts.Hosts) == 0 {
		return nil, fmt.Errorf("aerospike: at least one host required")
	}
	if opts.Namespace == "" {
		return nil, fmt.Errorf("aerospike: namespace required")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 200 * time.Millisecond
	}
	if opts.OpTimeout <= 0 {
		opts.OpTimeout = 50 * time.Millisecond
	}

	hosts := make([]*aero.Host, 0, len(opts.Hosts))
	for _, h := range opts.Hosts {
		host, err := parseHost(h)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	cp := aero.NewClientPolicy()
	cp.Timeout = opts.DialTimeout

	client, aerr := aero.NewClientWithPolicyAndHost(cp, hosts...)
	if aerr != nil {
		return nil, fmt.Errorf("aerospike: connect: %w", aerr)
	}
	return &Backend{
		client:    client,
		namespace: opts.Namespace,
		set:       opts.Set,
		opTimeout: opts.OpTimeout,
	}, nil
}

func (b *Backend) key(key []byte) (*aero.Key, error) {
	k, aerr := aero.NewKey(b.namespace, b.set, key)
	if aerr != nil {
		return nil, fmt.Errorf("aerospike: key: %w", aerr)
	}
	return k, nil
}

// expiration converts a ttl into Aerospike's whole-second expiration field.
func expiration(ttl time.Duration) uint32 {
	if ttl <= 0 {
		return aeroNeverExpire
	}
	secs := (ttl + time.Second - 1) / time.Second // round up to the second floor
	if secs < 1 {
		secs = 1
	}
	return uint32(secs)
}

func (b *Backend) writePolicy(ttl time.Duration, createOnly bool) *aero.WritePolicy {
	wp := aero.NewWritePolicy(0, expiration(ttl))
	wp.TotalTimeout = b.opTimeout
	if createOnly {
		wp.RecordExistsAction = aero.CREATE_ONLY
	}
	return wp
}

// SetNX performs a CREATE_ONLY write.
func (b *Backend) SetNX(_ context.Context, key, val []byte, ttl time.Duration) (bool, error) {
	k, err := b.key(key)
	if err != nil {
		return false, err
	}
	aerr := b.client.Put(b.writePolicy(ttl, true), k, aero.BinMap{binName: val})
	if aerr != nil {
		if aerr.Matches(atypes.KEY_EXISTS_ERROR) {
			return false, nil
		}
		return false, fmt.Errorf("aerospike: setnx: %w", aerr)
	}
	return true, nil
}

// Set performs a default (UPDATE) write.
func (b *Backend) Set(_ context.Context, key, val []byte, ttl time.Duration) error {
	k, err := b.key(key)
	if err != nil {
		return err
	}
	if aerr := b.client.Put(b.writePolicy(ttl, false), k, aero.BinMap{binName: val}); aerr != nil {
		return fmt.Errorf("aerospike: set: %w", aerr)
	}
	return nil
}

// Get reads the value bin, returning (nil, nil) on a missing record.
func (b *Backend) Get(_ context.Context, key []byte) ([]byte, error) {
	k, err := b.key(key)
	if err != nil {
		return nil, err
	}
	rp := aero.NewPolicy()
	rp.TotalTimeout = b.opTimeout
	rec, aerr := b.client.Get(rp, k, binName)
	if aerr != nil {
		if aerr.Matches(atypes.KEY_NOT_FOUND_ERROR) {
			return nil, nil
		}
		return nil, fmt.Errorf("aerospike: get: %w", aerr)
	}
	if rec == nil {
		return nil, nil
	}
	v, ok := rec.Bins[binName].([]byte)
	if !ok {
		return nil, nil
	}
	return v, nil
}

// Del removes the record.
func (b *Backend) Del(_ context.Context, key []byte) error {
	k, err := b.key(key)
	if err != nil {
		return err
	}
	wp := aero.NewWritePolicy(0, 0)
	wp.TotalTimeout = b.opTimeout
	if _, aerr := b.client.Delete(wp, k); aerr != nil {
		return fmt.Errorf("aerospike: del: %w", aerr)
	}
	return nil
}

// Healthy reports whether the client is connected to the cluster.
func (b *Backend) Healthy(_ context.Context) bool {
	return b.client.IsConnected()
}

// Close tears down the cluster connection.
func (b *Backend) Close() error {
	b.client.Close()
	return nil
}

// parseHost splits "host:port" into an *aero.Host (default port 3000).
func parseHost(hp string) (*aero.Host, error) {
	host, port, err := splitHostPort(hp)
	if err != nil {
		return nil, fmt.Errorf("aerospike: host %q: %w", hp, err)
	}
	return aero.NewHost(host, port), nil
}
