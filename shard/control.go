package shard

import (
	"encoding/binary"
	"net"
)

// Network service group index constants (BRC-129 Multicast Group Address
// Assignments). Network services occupy 0xF800–0xFFFF (2,048 indices);
// current assignments are allocated from the top of that range.
const (
	// CtrlGroupBlockHeader is the reserved group index for the block header
	// egress channel. Listeners emit stripped block headers (80-byte BSV
	// headers in BRC-131 framing) to this group for SPV consumers.
	CtrlGroupBlockHeader uint16 = 0xFFFA

	// CtrlGroupSubtreeAnnounce is the reserved group index for the BRC-127
	// subtree announcement control channel (Merkle subtree roll-ups).
	CtrlGroupSubtreeAnnounce uint16 = 0xFFFB

	// CtrlGroupSubtreeGroupAnnounce is the reserved group index for the BRC-127
	// subtree group announcement control channel.
	CtrlGroupSubtreeGroupAnnounce uint16 = 0xFFFC

	// CtrlGroupBeacon is the reserved group index for the ADVERT beacon group.
	// Used at both site (FF05) and global (FF0E) scope.
	CtrlGroupBeacon uint16 = 0xFFFD

	// CtrlGroupControl is the reserved group index for the future control
	// channel (block templates, producer-broadcast data).
	CtrlGroupControl uint16 = 0xFFFE
)

// ControlGroupAddr constructs a 16-byte IPv6 multicast address for a
// control-plane group. This is a standalone helper (not bound to [Engine])
// because control groups may use a different scope prefix than the data-plane
// engine (e.g. both FF05 and FF0E for beacon groups).
//
// scopePrefix is the two-byte IPv6 multicast prefix (e.g. 0xFF05 or 0xFF0E).
// groupID is the 16-bit IANA group-id occupying bytes 12–13 of the address
// (default [DefaultGroupID] = 0x000B for Bitcoin).
// index is the control-plane group index (e.g. [CtrlGroupBeacon]).
func ControlGroupAddr(scopePrefix uint16, groupID uint16, index uint16) net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint16(ip[0:2], scopePrefix)
	// bytes 2..11 remain zero (IANA 96-bit boundary)
	binary.BigEndian.PutUint16(ip[12:14], groupID)
	binary.BigEndian.PutUint16(ip[14:16], index)
	return ip
}
