package hostinfo

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"runtime"
	"testing"
)

func TestGatherBasics(t *testing.T) {
	inv := Gather("shard-proxy", "v1.2.3")
	if inv.Service != "shard-proxy" || inv.Version != "v1.2.3" {
		t.Errorf("build identity not set: %+v", inv)
	}
	if inv.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", inv.OS, runtime.GOOS)
	}
	if inv.CPULogical != runtime.NumCPU() {
		t.Errorf("CPULogical = %d, want %d", inv.CPULogical, runtime.NumCPU())
	}
	if inv.GoVersion == "" {
		t.Error("GoVersion empty")
	}
}

func TestInventoryLogValueJSON(t *testing.T) {
	inv := Inventory{
		Hostname:      "h1",
		OS:            "linux",
		CPULogical:    8,
		MemTotalBytes: 1 << 30,
		Service:       "shard-proxy",
		Version:       "v1",
		Interfaces: []Interface{{
			Name: "eth0", MAC: "00:11:22:33:44:55", MTU: 9000,
			OperState: "up", SpeedMbps: 10000, Driver: "ena",
			IPv4: []string{"192.0.2.10/24"},
			IPv6: []string{"2001:db8::10/64"},
		}},
		Sysctl: map[string]string{"net.core.rmem_max": "212992"},
	}

	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("host.inventory", "inventory", inv)

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	root, ok := rec["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("inventory not nested object: %v", rec["inventory"])
	}
	netG, ok := root["net"].(map[string]any)
	if !ok {
		t.Fatalf("net group missing: %v", root)
	}
	eth0, ok := netG["eth0"].(map[string]any)
	if !ok {
		t.Fatalf("eth0 missing: %v", netG)
	}
	// Both address families must be present.
	if eth0["ipv4"] == nil || eth0["ipv6"] == nil {
		t.Errorf("expected both ipv4 and ipv6 on eth0: %v", eth0)
	}
	if got := eth0["speed_mbps"]; got != float64(10000) {
		t.Errorf("speed_mbps = %v, want 10000", got)
	}
}
