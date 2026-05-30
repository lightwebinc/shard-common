package shard

import "fmt"

// SourceMode selects the multicast addressing model (RFC 4607 SSM vs ASM).
// SSM is the preferred mode; ASM is supported for legacy / compatibility
// deployments. RFC 8815 deprecates inter-domain ASM, so [ScopeGlobal]
// combined with [SourceModeASM] is rejected by [Prefix].
type SourceMode uint8

const (
	// SourceModeASM is any-source multicast: receivers join (*, G) and
	// the network forwards from any source. Requires PIM-SM with an RP
	// in the fabric.
	SourceModeASM SourceMode = iota

	// SourceModeSSM is source-specific multicast (RFC 4607): receivers
	// join (S, G) and the network forwards only from S. Requires
	// PIM-SSM in the fabric and MLDv2 on the L2 segment.
	SourceModeSSM
)

// String returns a stable lowercase label used in config and metrics.
func (m SourceMode) String() string {
	switch m {
	case SourceModeASM:
		return "asm"
	case SourceModeSSM:
		return "ssm"
	default:
		return fmt.Sprintf("sourcemode(%d)", uint8(m))
	}
}

// ParseSourceMode parses "asm" or "ssm" (case-insensitive).
func ParseSourceMode(s string) (SourceMode, error) {
	switch s {
	case "asm", "ASM":
		return SourceModeASM, nil
	case "ssm", "SSM":
		return SourceModeSSM, nil
	default:
		return 0, fmt.Errorf("shard: unknown sourceMode %q (want asm|ssm)", s)
	}
}

// Scope selects the IPv6 multicast scope. Site scope keeps traffic within
// one administrative domain; global scope crosses domain boundaries.
type Scope uint8

const (
	// ScopeSite is intra-domain (IPv6 multicast scope nibble 0x5).
	ScopeSite Scope = iota

	// ScopeGlobal is inter-domain (IPv6 multicast scope nibble 0xE).
	// Per RFC 8815, only SSM is permitted at global scope.
	ScopeGlobal
)

// String returns a stable lowercase label used in config and metrics.
func (s Scope) String() string {
	switch s {
	case ScopeSite:
		return "site"
	case ScopeGlobal:
		return "global"
	default:
		return fmt.Sprintf("scope(%d)", uint8(s))
	}
}

// ParseScope parses "site" or "global" (case-insensitive).
func ParseScope(s string) (Scope, error) {
	switch s {
	case "site", "SITE":
		return ScopeSite, nil
	case "global", "GLOBAL":
		return ScopeGlobal, nil
	default:
		return 0, fmt.Errorf("shard: unknown scope %q (want site|global)", s)
	}
}

// Prefix returns the IPv6 multicast prefix (upper 16 bits) for the given
// addressing mode and scope, suitable for passing as the mcPrefix argument
// to [New] or [GroupAddr].
//
//	(ASM,  site)   → 0xFF05
//	(ASM,  global) → unsupported (RFC 8815 deprecates inter-domain ASM)
//	(SSM,  site)   → 0xFF35
//	(SSM,  global) → 0xFF3E
//
// An error is returned for (ASM, global). All other combinations are
// supported.
func Prefix(mode SourceMode, scope Scope) (uint16, error) {
	switch {
	case mode == SourceModeASM && scope == ScopeSite:
		return 0xFF05, nil
	case mode == SourceModeSSM && scope == ScopeSite:
		return 0xFF35, nil
	case mode == SourceModeSSM && scope == ScopeGlobal:
		return 0xFF3E, nil
	case mode == SourceModeASM && scope == ScopeGlobal:
		return 0, fmt.Errorf("shard: ASM at global scope is deprecated by RFC 8815; use SSM for inter-domain delivery")
	default:
		return 0, fmt.Errorf("shard: unsupported (mode=%s, scope=%s) combination", mode, scope)
	}
}
