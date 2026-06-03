// Package hostinfo gathers a one-shot snapshot of the static facts of the
// machine a component runs on (OS, CPU, memory, NICs incl. both IPv4 and IPv6
// addresses, and the kernel knobs that gate multicast throughput) for emission
// as a single host.inventory log event at startup.
//
// It is best-effort: any field that cannot be read on the current platform is
// omitted rather than failing. Gather is called once per process lifetime, so
// it is not performance-sensitive and never touches a data-plane hot path.
//
// Portability: portable facts come from gopsutil (pure Go, Linux + FreeBSD);
// interface addresses come from the standard library net package (both address
// families); deep NIC facts (link speed, driver, oper state) and sysctls are
// read from Linux sysfs/procfs and degrade to empty elsewhere.
package hostinfo

import (
	"log/slog"
	"net"
	"runtime"
	"runtime/debug"
	"sort"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

// Interface describes one network interface. SpeedMbps, Duplex, Driver and
// OperState are populated only where the platform exposes them (Linux sysfs).
type Interface struct {
	Name      string
	MAC       string
	MTU       int
	OperState string
	SpeedMbps int
	Duplex    string
	Driver    string
	IPv4      []string
	IPv6      []string
}

// Inventory is the full host snapshot.
type Inventory struct {
	Hostname       string
	BootTime       uint64
	Uptime         uint64
	Virtualization string

	OS              string
	Platform        string
	PlatformVersion string
	KernelVersion   string

	CPUModel    string
	CPUPhysical int
	CPULogical  int
	CPUMHz      float64

	MemTotalBytes uint64

	Interfaces []Interface
	Sysctl     map[string]string

	Service     string
	Version     string
	GoVersion   string
	VCSRevision string
}

// Gather collects the inventory. service and version identify the build.
func Gather(service, version string) Inventory {
	inv := Inventory{
		OS:        runtime.GOOS,
		Service:   service,
		Version:   version,
		GoVersion: runtime.Version(),
		Sysctl:    readSysctls(),
	}

	if info, err := host.Info(); err == nil {
		inv.Hostname = info.Hostname
		inv.BootTime = info.BootTime
		inv.Uptime = info.Uptime
		inv.Virtualization = info.VirtualizationSystem
		inv.Platform = info.Platform
		inv.PlatformVersion = info.PlatformVersion
		inv.KernelVersion = info.KernelVersion
	}

	if cpus, err := cpu.Info(); err == nil && len(cpus) > 0 {
		inv.CPUModel = cpus[0].ModelName
		inv.CPUMHz = cpus[0].Mhz
	}
	if n, err := cpu.Counts(false); err == nil {
		inv.CPUPhysical = n
	}
	inv.CPULogical = runtime.NumCPU()

	if vm, err := mem.VirtualMemory(); err == nil {
		inv.MemTotalBytes = vm.Total
	}

	inv.Interfaces = gatherInterfaces()

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				inv.VCSRevision = s.Value
			}
		}
	}
	return inv
}

// gatherInterfaces uses the standard library for portable address/MTU/MAC
// facts (both IPv4 and IPv6) and augments with platform-specific link details.
func gatherInterfaces() []Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		e := Interface{
			Name: ifc.Name,
			MAC:  ifc.HardwareAddr.String(),
			MTU:  ifc.MTU,
		}
		if ifc.Flags&net.FlagUp != 0 {
			e.OperState = "up"
		} else {
			e.OperState = "down"
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipn.IP.To4() != nil {
				e.IPv4 = append(e.IPv4, ipn.String())
			} else {
				e.IPv6 = append(e.IPv6, ipn.String())
			}
		}
		augmentInterface(&e)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LogValue implements slog.LogValuer so an Inventory logs as nested groups.
func (inv Inventory) LogValue() slog.Value {
	hostG := slog.Group("host",
		"hostname", inv.Hostname,
		"boot_time", inv.BootTime,
		"uptime_s", inv.Uptime,
		"virtualization", inv.Virtualization,
	)
	osG := slog.Group("os",
		"goos", inv.OS,
		"platform", inv.Platform,
		"platform_version", inv.PlatformVersion,
		"kernel_version", inv.KernelVersion,
	)
	cpuG := slog.Group("cpu",
		"model", inv.CPUModel,
		"physical", inv.CPUPhysical,
		"logical", inv.CPULogical,
		"mhz", inv.CPUMHz,
	)
	memG := slog.Group("mem", "total_bytes", inv.MemTotalBytes)
	buildG := slog.Group("build",
		"service", inv.Service,
		"version", inv.Version,
		"go_version", inv.GoVersion,
		"vcs_revision", inv.VCSRevision,
	)

	netAttrs := make([]any, 0, len(inv.Interfaces))
	for _, ifc := range inv.Interfaces {
		netAttrs = append(netAttrs, slog.Group(ifc.Name,
			"mac", ifc.MAC,
			"mtu", ifc.MTU,
			"oper_state", ifc.OperState,
			"speed_mbps", ifc.SpeedMbps,
			"duplex", ifc.Duplex,
			"driver", ifc.Driver,
			"ipv4", ifc.IPv4,
			"ipv6", ifc.IPv6,
		))
	}

	sysAttrs := make([]any, 0, len(inv.Sysctl))
	keys := make([]string, 0, len(inv.Sysctl))
	for k := range inv.Sysctl {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sysAttrs = append(sysAttrs, slog.String(k, inv.Sysctl[k]))
	}

	return slog.GroupValue(
		hostG, osG, cpuG, memG, buildG,
		slog.Group("net", netAttrs...),
		slog.Group("sysctl", sysAttrs...),
	)
}
