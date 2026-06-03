package cache

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the backend-agnostic construction parameters consumed by [Open].
// Each service builds one (typically via [RegisterFlags]) and passes it to
// Open. Only the fields relevant to the chosen Backend are read.
type Config struct {
	// Backend selects the implementation: BackendMemory, BackendRedis,
	// BackendAerospike, or BackendNone.
	Backend string

	// MemoryMaxKeys bounds the in-memory backend (0 = unbounded). Ignored by
	// other backends.
	MemoryMaxKeys int

	// RedisAddr is the host:port of a Redis-protocol server. Required when
	// Backend == BackendRedis.
	RedisAddr string

	// AeroHosts is the list of Aerospike seed nodes (host:port). Required when
	// Backend == BackendAerospike.
	AeroHosts []string
	// AeroNamespace is the Aerospike namespace records are written to.
	AeroNamespace string
	// AeroSet is the Aerospike set name within the namespace.
	AeroSet string

	// DialTimeout bounds initial connection establishment (<=0 → 200ms).
	DialTimeout time.Duration
	// OpTimeout bounds each individual operation (<=0 → 50ms). Kept short so
	// dedup callers fail open quickly on a slow backend.
	OpTimeout time.Duration
}

// RegisterFlags wires the standard cache flags onto fs using the given flag
// prefix (e.g. "" for the retry endpoint's frame cache, or "egress-dedup-" /
// "ingress-dedup-" for the listener's two stores) and env prefix
// (e.g. "CACHE_", "EGRESS_DEDUP_"). It returns a *Config populated as flags
// are parsed. Every flag has an UPPERCASE env-var equivalent, matching the
// project convention.
//
// Services that already own bespoke flag names (the retry endpoint's
// historical -cache-backend / -redis-addr) may instead build a Config
// directly; RegisterFlags is a convenience for new wiring (proxy/listener).
func RegisterFlags(fs *flag.FlagSet, flagPrefix, envPrefix string) *Config {
	c := &Config{}
	fs.StringVar(&c.Backend, flagPrefix+"cache-backend",
		envStr(envPrefix+"CACHE_BACKEND", BackendNone),
		"cache backend: memory|redis|aerospike|none")
	fs.IntVar(&c.MemoryMaxKeys, flagPrefix+"cache-memory-max-keys",
		envInt(envPrefix+"CACHE_MEMORY_MAX_KEYS", 0),
		"in-memory backend key cap (0 = unbounded)")
	fs.StringVar(&c.RedisAddr, flagPrefix+"redis-addr",
		envStr(envPrefix+"REDIS_ADDR", ""),
		"Redis-protocol server host:port (Redis/Valkey/Dragonfly); required when cache-backend=redis")
	fs.Var(&csvFlag{&c.AeroHosts}, flagPrefix+"aerospike-hosts",
		"Aerospike seed nodes host:port (comma-separated); required when cache-backend=aerospike")
	fs.StringVar(&c.AeroNamespace, flagPrefix+"aerospike-namespace",
		envStr(envPrefix+"AEROSPIKE_NAMESPACE", "cache"),
		"Aerospike namespace")
	fs.StringVar(&c.AeroSet, flagPrefix+"aerospike-set",
		envStr(envPrefix+"AEROSPIKE_SET", "bsv"),
		"Aerospike set name")
	fs.DurationVar(&c.DialTimeout, flagPrefix+"cache-dial-timeout",
		envDuration(envPrefix+"CACHE_DIAL_TIMEOUT", 200*time.Millisecond),
		"backend dial timeout")
	fs.DurationVar(&c.OpTimeout, flagPrefix+"cache-op-timeout",
		envDuration(envPrefix+"CACHE_OP_TIMEOUT", 50*time.Millisecond),
		"backend per-operation timeout")
	// Default AeroHosts from env when the flag is not passed.
	if v := os.Getenv(envPrefix + "AEROSPIKE_HOSTS"); v != "" && len(c.AeroHosts) == 0 {
		c.AeroHosts = splitCSV(v)
	}
	return c
}

// csvFlag is a flag.Value collecting a comma-separated list into a []string.
type csvFlag struct{ dst *[]string }

func (f *csvFlag) String() string {
	if f.dst == nil {
		return ""
	}
	return strings.Join(*f.dst, ",")
}

func (f *csvFlag) Set(v string) error {
	*f.dst = splitCSV(v)
	return nil
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
