// Package logging provides a single, uniform structured-logging entrypoint
// shared by every binary in the multicast fleet (shard-proxy, shard-listener,
// retry-endpoint, shard-manifest, subtx-generator).
//
// It owns slog initialisation so the previously divergent per-service setup
// sites collapse to one [Init] call. Every log line emitted after Init carries
// the same identity triple that OTLP metrics attach as resource attributes
// (service.name, service.instance.id, service.version), so logs and metrics
// join on shared dimensions in the backend.
//
// Output contract (see shard-common/docs/logging.md):
//   - FormatJSON writes one JSON object per line to stdout (12-factor; the
//     process emits, the collector ships).
//   - FormatText writes human-readable lines to stderr (interactive/dev default).
//
// The returned *slog.LevelVar lets an operator change the level at runtime
// (SIGHUP toggle via [InstallSIGHUPToggle] or an admin endpoint via
// [LevelHandler]) without a restart.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the output encoding.
type Format int

const (
	// FormatText is human-readable key=value output (default; stderr).
	FormatText Format = iota
	// FormatJSON is one JSON object per line (fleet/aggregation; stdout).
	FormatJSON
)

// ParseFormat maps a config string to a Format. Unknown values fall back to
// FormatText.
func ParseFormat(s string) Format {
	if strings.EqualFold(strings.TrimSpace(s), "json") {
		return FormatJSON
	}
	return FormatText
}

// ParseLevel maps a config string (debug|info|warn|error) to an slog.Level.
// Unknown values fall back to LevelInfo.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Options configures [Init].
type Options struct {
	// Service is the OTel service.name; MUST equal the metrics package's
	// ServiceName for the same binary so logs and metrics share identity.
	Service string
	// InstanceID is the OTel service.instance.id (hostname/pod name). Empty
	// falls back to os.Hostname().
	InstanceID string
	// Version is the build version (matches metrics.Version).
	Version string
	// Level is the initial log level.
	Level slog.Level
	// Format selects the encoding.
	Format Format
	// Output overrides the sink. When nil, FormatJSON uses stdout and
	// FormatText uses stderr.
	Output io.Writer
}

// Init installs a process-wide slog default with the identity triple
// pre-attached and returns a *slog.LevelVar whose level can be changed at
// runtime. It is safe to call before config parsing (the pre-config error path
// can rely on the slog default already being usable).
func Init(opts Options) *slog.LevelVar {
	lvl := &slog.LevelVar{}
	lvl.Set(opts.Level)

	out := opts.Output
	if out == nil {
		if opts.Format == FormatJSON {
			out = os.Stdout
		} else {
			out = os.Stderr
		}
	}

	hopts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if opts.Format == FormatJSON {
		h = slog.NewJSONHandler(out, hopts)
	} else {
		h = slog.NewTextHandler(out, hopts)
	}

	instanceID := opts.InstanceID
	if instanceID == "" {
		if hn, err := os.Hostname(); err == nil {
			instanceID = hn
		}
	}

	logger := slog.New(h).With(
		"service.name", opts.Service,
		"service.instance.id", instanceID,
		"service.version", opts.Version,
	)
	slog.SetDefault(logger)
	return lvl
}
