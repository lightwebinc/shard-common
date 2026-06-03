//go:build linux

package hostinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sysctlPaths are the kernel knobs that gate multicast throughput, read from
// procfs. Keys are the dotted sysctl names; values are the procfs paths.
var sysctlPaths = map[string]string{
	"net.core.rmem_max":               "/proc/sys/net/core/rmem_max",
	"net.core.wmem_max":               "/proc/sys/net/core/wmem_max",
	"net.core.netdev_max_backlog":     "/proc/sys/net/core/netdev_max_backlog",
	"net.core.optmem_max":             "/proc/sys/net/core/optmem_max",
	"net.ipv6.conf.all.mc_forwarding": "/proc/sys/net/ipv6/conf/all/mc_forwarding",
}

func readSysctls() map[string]string {
	out := make(map[string]string, len(sysctlPaths))
	for name, path := range sysctlPaths {
		if v, err := os.ReadFile(path); err == nil {
			out[name] = strings.TrimSpace(string(v))
		}
	}
	// mld_max_msf is per-interface under conf/<iface>; report the default.
	if v, err := os.ReadFile("/proc/sys/net/ipv6/conf/default/mldv1_unsolicited_report_interval"); err == nil {
		out["net.ipv6.conf.default.mldv1_unsolicited_report_interval"] = strings.TrimSpace(string(v))
	}
	return out
}

// augmentInterface fills link speed, duplex, oper state and driver from sysfs.
func augmentInterface(e *Interface) {
	base := filepath.Join("/sys/class/net", e.Name)
	if v, err := os.ReadFile(filepath.Join(base, "operstate")); err == nil {
		if s := strings.TrimSpace(string(v)); s != "" {
			e.OperState = s
		}
	}
	if v, err := os.ReadFile(filepath.Join(base, "speed")); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil && n > 0 {
			e.SpeedMbps = n
		}
	}
	if v, err := os.ReadFile(filepath.Join(base, "duplex")); err == nil {
		e.Duplex = strings.TrimSpace(string(v))
	}
	if link, err := os.Readlink(filepath.Join(base, "device", "driver")); err == nil {
		e.Driver = filepath.Base(link)
	}
}
