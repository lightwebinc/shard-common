# Unified Component Logging

- Scope: the **emit side**. The `logging`, `hostinfo`, and `tracing` packages
  are wired into every service binary (`shard-proxy`, `shard-listener`,
  `retry-endpoint`, `shard-manifest`, `subtx-generator`) and covered by the
  `multicast-test` e2e suite. Every component *produces* logs that are
  structured, self-identifying, and consistent.
- Transport: the shipping agent and log store live outside the application
  binaries. This document fixes the on-host output contract so that layer is
  configuration, not code; the transport standard (OTLP via a node-local
  collector into Loki) is in
  [Recommended transport](#recommended-transport-architecture).
- **Brevity is a hard requirement.** A data-plane node at scale must be nearly
  silent in steady state. Logs prioritize bandwidth/storage economy over
  chattiness; see [Log economy](#log-economy-brevity-is-a-requirement).
- Default behavior: human-readable text output for interactive/dev use; JSON
  is one flag away (`-log-format json`).

## Why

A multicast fabric of hundreds-to-thousands of proxies, listeners, and retry
endpoints cannot be operated by SSH-ing into hosts. Metrics give aggregate
counters with consistent identity (`service.name`, `service.instance.id`,
`service.version` resource attributes + per-group/worker labels). Logs are the
other half, the *per-event narrative* metrics can't carry: which group failed
to join, which errno a `sendmmsg` returned, which deprecated flag a host still
uses, why a frame was dropped. For that narrative to be usable at fleet scale
it must be consistent and attributed.

### Requirements

1. **One format.** A single parser works across the fleet: the output is text
   or JSON, never a per-service mix.
2. **Identity on every line.** The `service.name`/`instance.id`/`version`
   triple that OTLP metrics attach as resource attributes is on every log line,
   so a log ties back to the metric series for the same process.
3. **Runtime levels.** `debug`/`info`/`warn`/`error`, changeable without a
   restart (a restart hides the bug being chased).
4. **Keys match metric labels.** Attribute names are the metric label names
   (`group`, `worker`, `network.interface.name`), so logs and metrics join on
   shared dimensions.
5. **OS/NIC visibility.** Syscall sites that *observe* kernel conditions
   (`ENOBUFS` on `sendmmsg`/`recvmmsg`, `SO_RCVBUF` clamping,
   `MCAST_JOIN_SOURCE_GROUP` rejection when `mld_max_msf` is exceeded) log
   them with an errno, so the host's own kernel signals are visible.

## Message taxonomy

Every log line maps to one of these categories. The
category fixes the **level**, the **required attributes**, and the **hot-path
discipline**. Each new call site has an obvious home.

| # | Category | Default level | Hot path? | Examples | Required attrs |
|---|----------|---------------|-----------|------------------------------|----------------|
| 0 | **Host inventory** *(one-shot)* | Info | no | `host.inventory`, emitted once at startup | host/os/cpu/mem/nic/sysctl (see §4) |
| 1 | **Lifecycle** | Info | no | `shard-proxy starting`, `received signal, starting drain`, `drain complete`, `all workers stopped`, `shutdown complete` | base only |
| 2 | **Config / capability** | Info | no | the capability summary as **one** `startup.config` event, not one line per feature | capabilities as attrs (see [§Log economy](#log-economy-brevity-is-a-requirement)) |
| 3 | **Config warnings** | Warn | no | `deprecated -txid-dedup-* flags in use`, `unknown cache backend, using memory`, `redis dedup unavailable` | the offending value + fallback |
| 4 | **Auto-config / adoption** | Info / Warn | no | `auto-config adopted new ShardBits (restart mode)`, `auto-join applied`, `live-resharding: bridging engine installed` | `shard_bits`, `mc_group_id`, `source_mode`, `epoch`, quorum |
| 5 | **Fatal startup** | Error → exit | no | `configuration error`, `multicast interface not found`, `metrics init failed`, `invalid bind-source` | `error`, offending input |
| 6 | **Runtime subsystem error** | Error | no | `worker exited with error`, `beacon listener error`, `sender exited with error`, `TCP ingress exited with error` | `error`, subsystem id (`worker`, `iface`, `group`) |
| 7 | **Protocol / data-plane event** | Debug (Warn on anomaly) | **yes** | `subtree_group_announce: decode error`, `… sender rejected by filter`, `… datagram too short`; gap-detected, NACK-sent, retransmit | `group`, `seq`, `txid`, `frame_type`, `proto`; **rate-limited/sampled** |
| 8 | **OS / NIC / host** | Warn / Error | partly | `ENOBUFS` on egress, `SO_RCVBUF`/`SO_SNDBUF` clamp, MLD source-filter exhausted, IPv6 join failure | `errno`, `network.interface.name`, `group`, syscall name |

**Rule:** categories 1–6 are unconditional. Category 7 is the only one allowed
on the zero-alloc hot path and **must** be rate-limited or gated behind Debug;
a per-packet log at line rate is a self-inflicted outage. Category 8 is
described in §3.

## Design

### 1. One shared emitter: `shard-common/logging`

A single small package, imported by every binary (`shard-common` is the
universal dependency). It owns initialization, so each binary has one setup
call.

```go
// package logging
type Options struct {
    Service    string      // "shard-proxy"; MUST equal metrics.ServiceName
    InstanceID string      // == OTLP service.instance.id (hostname fallback)
    Version    string      // == metrics.Version (ldflags)
    Level      slog.Level  // initial level
    Format     Format      // FormatText (default) | FormatJSON
    Output     io.Writer   // optional sink override (nil: stdout for JSON, stderr for text)
}

// Init installs a process-wide slog default with base attributes pre-attached
// and returns a *slog.LevelVar so the level can be changed at runtime. Safe to
// call before config parsing.
func Init(Options) *slog.LevelVar
```

What it guarantees, fleet-wide:

- **Format:** `FormatJSON` writes one JSON object per line to **stdout**
  (12-factor: the process emits, the platform routes). `FormatText` is the
  default so interactive use and systemd/journald reading stay readable. A
  deployment selects JSON with `LOG_FORMAT=json`, with **no call site changes.**
- **Identity on every line:** `Init` does `slog.New(handler).With(
  "service.name", …, "service.instance.id", …, "service.version", …)` so every
  call site inherits the exact identity triple OTLP metrics use.
  This is what makes log↔metric correlation possible with zero call-site edits.
- **Runtime level:** the returned `*slog.LevelVar` is wired to a `SIGHUP`
  toggle (`InstallSIGHUPToggle`) and to `GET`/`PUT`/`POST /loglevel` on the
  metrics listener (`LevelHandler`), so an operator can drop one hot host to
  Debug without a restart (and restore it).
- **Keys match metric labels:** the package documents and (where helpful)
  provides helpers for the shared attribute vocabulary so logs and metrics join.

### 2. Standard attribute vocabulary

The names are those of the metrics layer, so a Grafana pivot from a metric
series to its logs is a label match, not a translation table.

| Key | Source of truth | Notes |
|-----|-----------------|-------|
| `service.name` | `metrics.ServiceName` | OTel semconv |
| `service.instance.id` | OTLP `service.instance.id` | hostname/pod fallback |
| `service.version` | `metrics.Version` | ldflags |
| `deployment.id` | dedup `<deployment-id>` | groups replicas of one logical deploy |
| `network.interface.name` | metrics `ifaceAttr` | OTel semconv; already used |
| `group` | metrics group label (`%04x`) | shard / control group idx |
| `worker` | metrics worker label | proxy worker id |
| `frame_type` / `flow` | metrics labels | BRC frame discriminator |
| `seq`, `txid` | protocol | data-plane events only |
| `err` | Go error | Error/Warn lines; never interpolate into msg |
| `errno`, `syscall` | category-8 only | OS/NIC conditions |

Convention: the message string is a **stable, low-cardinality identifier**
(for example `"auto-join applied"`), and all variables go in
attributes. This keeps messages groupable and aggregation-friendly.

### 3. OS / NIC / host visibility (the telemetry gap)

Telemetry exposes aggregate drop *counts* (`bsp_packets_dropped_total`,
listener gaps). What it cannot explain is the **kernel-level cause**. The split
is what the component can see vs. what only the host can see; the component
owns the former and node_exporter the latter.

**(a) In-process, app-attributed.** The proxy and listener are the only things
that know *which group/iface/worker* a kernel error belongs to. Category-8 logs
sit at the syscall sites that observe the error:

- `WriteBatch`/`sendmmsg` returning `ENOBUFS`/`EAGAIN` → Warn with `errno`,
  `network.interface.name`, batch size, count dropped. (This is the kernel
  socket buffer / qdisc backpressure that metrics show only as a counter.)
- `ReadBatch`/`recvmmsg` short reads / errors → Warn with `errno`.
- `SO_RCVBUF`/`SO_SNDBUF` requested-vs-granted mismatch at startup → Warn with
  requested/actual (the kernel silently clamps to `net.core.rmem_max`).
- `netjoin.Join` failure, especially `ENOBUFS` from exceeding `mld_max_msf`
  source filters (SSM) → Error with `group`, `errno`, `syscall`. This is the
  exact failure mode the SSM design warns about.

These are cheap (error paths, not the success hot path) and turn opaque drops
into actionable, host-attributed events.

**(b) Out-of-process, *continuous* host telemetry: the open-source standard,
not a reimplementation.** NIC ring drops (`ethtool -S`), `/proc/net/snmp6`,
`/proc/net/softnet_stat`, conntrack table fill, per-queue counters,
`dmesg`/kernel-facility messages, FreeBSD `netstat -i` / kern syslog. These are
*high-frequency time series*, not events; they belong in the metrics plane, and
**[node_exporter](https://github.com/prometheus/node_exporter)** (Prometheus,
Apache-2.0) already exposes nearly all of them (`node_netstat_*`,
`node_softnet_*`, `node_network_*`, and the `ethtool` collector for ring/driver
counters). Reimplementing this inside the Go binaries would be large, brittle,
and platform-divergent for zero benefit. **node_exporter is deployed
*alongside* each component (host service or k8s DaemonSet), never bundled into
or invoked by the application binary.** The code has **zero dependency** on it;
node_exporter being absent only loses continuous host telemetry; the application's own `host.inventory` and §3(a) event logs are
unaffected. The application's job is the *one-shot startup inventory* below and
the *app-attributed event* logs in §3(a), the two things node_exporter cannot
do. (Collector deployment is covered in
[Recommended transport](#recommended-transport-architecture).)

### 4. Host inventory at startup (one-shot, near-zero cost)

When a component comes online it emits **one** structured `host.inventory`
event (category 1, Info) capturing the static facts of the machine. One line per
process lifetime (no ongoing cost, no hot-path impact), and it answers "what was
this box?" for every node in the fleet without SSH, and it is the join key that
makes a later node_exporter series interpretable ("which of the 2000 proxies is
on the slow NIC / old kernel / undersized rmem").

**Fields** (single event, nested attrs):

| Group | Fields | Source |
|-------|--------|--------|
| `host` | hostname, boot time, uptime, virtualization role | gopsutil `host` |
| `os` | GOOS, platform + version, kernel version | gopsutil `host` |
| `cpu` | model, physical/logical core count, MHz | gopsutil `cpu` + `runtime.NumCPU` |
| `mem` | total RAM | gopsutil `mem` |
| `net.<iface>` | name, MAC, MTU, oper state, link speed/duplex, driver, **IPv4 and IPv6 addrs** | `net` package + Linux sysfs (see below) |
| `sysctl` | `net.core.rmem_max`, `wmem_max`, `netdev_max_backlog`, `optmem_max`, `net.ipv6.conf.all.mc_forwarding`, the MLDv1 unsolicited report interval: the knobs that gate multicast throughput | `/proc/sys` read (Linux only) |
| `build` | service, version, go version, build vcs rev | ldflags + `runtime/debug` |

**Implementation, by portability tier (minimal dependency surface):**

1. **Portable facts** (host/os/cpu/mem):
   **[gopsutil](https://github.com/shirou/gopsutil)** (v4, BSD-3, **pure Go, no
   cgo**, so it respects the `CGO_ENABLED=0` rule, and supports Linux **and**
   FreeBSD). One call at startup. Interface name, MAC, MTU and addresses come
   from the standard library `net` package. **Both IPv4 and IPv6** addresses are
   recorded per interface: boundary nodes that bridge to non-multicast networks
   carry IPv4, so the inventory is not v6-only.
2. **Deep NIC facts** (oper state, link speed/duplex, driver): read from Linux
   sysfs (`/sys/class/net/<iface>`); no `exec`, no cgo. Empty on other
   platforms.
3. **sysctls:** direct `/proc/sys` reads on Linux; empty on other platforms.

If a field can't be read on a platform, it is omitted: the inventory is
best-effort and never blocks or fails startup. gopsutil is the only dependency
`hostinfo` adds, and it lives in `shard-common/hostinfo` so every binary
inherits it identically.

**Why a log and not a metric:** these are high-cardinality *strings* (CPU model,
kernel release, NIC driver), and the descriptive payload belongs in a log event.
Each component also publishes a slim `<prefix>_host_info` info-gauge (value 1;
labels: hostname, kernel version, logical cores, memory bytes, `rmem_max`,
primary NIC and its link speed, version) for dashboard joins. The log is the
source of truth.

## Recommended transport architecture

The transport is fixed so the emit-side contract is built against it.

```text
  app process                node-local collector             backend (later)
  ───────────                ────────────────────             ───────────────
  slog JSON ──▶ stdout ──▶  Grafana Alloy / OTel Collector ──OTLP──▶ Loki
                            (DaemonSet on k8s; systemd unit          (OTLP-native
                             on VMs; tails journald/stdout)           ingest, 3.x)
```

**OTLP is the wire standard; a node-local collector produces it; the app does
not.** Rationale, in priority order:

1. **Performance (the hard constraint).** The data-plane binaries
   (`shard-proxy`, `shard-listener`) must never block on log transport. An
   **in-process** OTLP gRPC exporter adds a batch queue + periodic network flush
   inside the hot binary; if the collector or network stalls, that backpressure
   reaches the process. Writing JSON to **stdout** is a buffered local write with
   no network, no TLS, no retry queue: the minimal-impact path "no matter
   what." The OTLP/batching/retry cost is paid **out-of-process** by the
   collector, which can stall, restart, or backpressure without touching the
   data plane.
2. **Standard + future-proof.** OTLP is the CNCF vendor-neutral standard; the
   collector can fan out to Loki, ELK, ClickHouse, or an OTLP SaaS with a config
   change and no app rebuild. Loki 3.x accepts OTLP natively, so the path is
   direct.
3. **One agent, three signals.** Grafana Alloy (or the OTel Collector) carries
   logs **and** the existing Prometheus metrics **and** node_exporter host
   telemetry (§3b) through one pipeline, with the same resource attributes, so
   logs, metrics, and host facts join on `service.instance.id` in one place.

**Collector: Grafana Alloy** (Apache-2.0). It fits the Prometheus/Grafana
stack and speaks OTLP + Loki + Prometheus + traces natively in one agent.
Deployed alongside the components as a systemd unit (VMs) or DaemonSet (k8s);
it also runs/relabels node_exporter scrapes (§3b). The application stays
collector-agnostic; Alloy is a deployment choice, not a code dependency.

**Why not in-process OTLP at all?** For the non-hot binaries (`shard-manifest`,
`subtx-generator`) an in-process slog→OTLP bridge would be harmless, but mixing
two transport models across the fleet costs more in operational consistency than
it saves. Uniform "JSON to stdout, collector ships it" is simpler to reason
about at thousands of nodes.

## Distributed tracing (control-plane only, never the packet hot path)

Maximum tracing is desired **subject to the hard rule that the data-plane hot
path is never touched.** Per-packet spans on a billion-tx/s forwarder are
impossible; so tracing is applied to the **control- and request-scoped flows**,
which are low-frequency and where causality across processes is the actual
operability win:

| Traced flow | Spans across | Why |
|-------------|--------------|-----|
| NACK → ACK/MISS → retransmit | listener → retry-endpoint → (multicast) | the canonical cross-process recovery path |
| Manifest adoption / auto-config | shard-manifest → proxy/listener appliers | quorum/hysteresis transitions are multi-step |
| Startup / drain lifecycle | within a process | bounds the inventory + config + ready sequence |
| Subtree/group join + leave | listener appliers | the `mld_max_msf`/join failures from §3(a) get span context |

Design constraints:

- **A `shard-common/tracing` package** mirrors the metrics OTLP pattern exactly:
  an OTel `TracerProvider` with an **opt-in** OTLP/gRPC span exporter behind the
  same `OTLP_ENDPOINT` (`-trace-sampling` / `TRACE_SAMPLING` ratio, default
  `0` = off). When disabled it installs a **no-op tracer** (zero allocation,
  zero cost), so a build with tracing compiled in but unconfigured pays
  nothing.
- **The forwarder receive/send loops, the per-flow SeqNum map, and reassembly
  hot paths take no span and no context**, enforced by keeping the tracer out of
  those packages entirely. Spans live only in control-plane packages
  (`nack`, `retransmit`, `beacon`, `manifest`, `server`, lifecycle in `main`).
- **Trace context rides existing protocol where it already exists** (NACK/ACK
  carry no spare bytes, so cross-process linkage uses
  `trace.id`/`span.id` attributes logged on both ends and joined in the backend;
  a future BRC field could carry W3C `traceparent` if warranted).
- **Export is out-of-process via Alloy** (OTLP traces), same isolation argument
  as logs: an exporter stall cannot reach the data plane because the traced
  flows are not on it.

This gives "maximum tracing" where it is safe and meaningful, and **none** where
it would cost throughput.

## Out of scope

- The shipping agent, collector, and log store are deployment concerns outside
  the application repos; the architecture above fixes what they receive.
- No in-process OTLP **log** export (see rationale above). The metrics OTLP
  path is separate.
- No reimplementation of host/kernel telemetry; node_exporter owns it (§3b).

The output contract (JSON-to-stdout, identity-attributed, low-cardinality
messages, metric-aligned keys, one-shot host inventory) is fixed so that
collector rollout is configuration, not application code.

## Log economy (brevity is a requirement)

At thousands of nodes, every steady-state log line is multiplied by the fleet and
paid for in NIC bandwidth, collector CPU, and store retention. Brevity is a
design constraint, not a style preference. Rules:

1. **Steady-state silence.** A healthy component emits its startup sequence
   (`starting` → `host.inventory` → capability summary → `ready`) and then
   **nothing** until a state change or anomaly. Liveness is the metrics plane's
   job, not a heartbeat log. No periodic "still alive" / "processed N" lines.
2. **No per-event logging on the data plane at Info.** Category-7 events are
   Debug and **sampled/rate-limited** (e.g. log-once-then-count: first ENOBUFS
   logged, subsequent ones counted and summarized on a timer). A per-packet log
   at line rate is an outage.
3. **Collapse boot chatter.** Capability lines go into **one** structured
   `startup.config` event with the capabilities as boolean/value attributes,
   not a dozen separate "X enabled" lines.
4. **Short, stable keys; no prose.** Message = low-cardinality identifier;
   variables in attributes; never restate base identity (it is auto-attached);
   never interpolate values into the message string.
5. **Errors deduplicate.** Repeated identical errors (a flapping iface, a down
   Redis) are rate-limited with an occurrence count, not emitted per failure.
6. **Right level by default.** `info` ships lifecycle + config + warnings +
   errors only, a near-empty stream in steady state. `debug` (opt-in, per-host,
   runtime-togglable via the LevelVar) is the only verbose mode.

These rules make JSON's per-line overhead irrelevant: the win is **far fewer
lines**, and the collector compresses what remains on the wire.

## Config surface

Every flag has an UPPERCASE env equivalent, in the per-repo `config/` package.

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `-log-format` | `LOG_FORMAT` | `text` | `text` \| `json`. `json` is the fleet/aggregation format. Exception: `shard-manifest` defaults to `json`. |
| `-log-level` | `LOG_LEVEL` | `info` | `debug`\|`info`\|`warn`\|`error`. Supersedes the boolean `-debug` (kept as alias = `debug`). |
| `-trace-sampling` | `TRACE_SAMPLING` | `0` | Span sampling ratio `0.0`–`1.0`; `0` = tracing off (no-op tracer). Exports via `OTLP_ENDPOINT` when > 0. |

`-debug` is a deprecated alias that forces `debug` level. Tracing reuses
`OTLP_ENDPOINT`; with `-trace-sampling 0` the tracer is a no-op and costs nothing.

## Decisions

1. **Collector**: Grafana Alloy (Apache-2.0, OTLP into Loki), chosen over the
   upstream OpenTelemetry Collector for stack affinity. See
   [Recommended transport](#recommended-transport-architecture).
2. **Cross-process trace context propagation**: NACK/ACK frames carry no spare
   bytes for a W3C `traceparent`, so linkage is via logged
   `trace.id`/`span.id` attributes joined in the backend. A future BRC field
   could carry `traceparent` natively. See
   [Distributed tracing](#distributed-tracing-control-plane-only-never-the-packet-hot-path).
3. **`host_info` mirror gauge**: each component publishes a slim
   `<prefix>_host_info` info-gauge (value 1, low-cardinality labels, carrying
   the same `service.instance.id`) for dashboard joins; the descriptive payload
   stays in the `host.inventory` log event.
