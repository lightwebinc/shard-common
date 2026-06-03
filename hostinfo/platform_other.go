//go:build !linux

package hostinfo

// readSysctls returns no sysctls on non-Linux platforms (best-effort; the
// inventory degrades gracefully rather than failing).
func readSysctls() map[string]string { return map[string]string{} }

// augmentInterface is a no-op on non-Linux platforms; the portable facts
// (name, MAC, MTU, addrs, up/down) are still populated by the caller.
func augmentInterface(_ *Interface) {}
