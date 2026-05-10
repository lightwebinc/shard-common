package shard

import (
	"encoding/binary"
	"net"
)

// Control-plane group index constants (BRC-TBD-addressing).
// These occupy the top of the 24-bit index space, ensuring orthogonality
// with all practical shard configurations (shardBits ≤ 23).
const (
	// CtrlGroupSubtreeAnnounce is the reserved group index for the BRC-127
	// subtree group announcement control channel.
	CtrlGroupSubtreeAnnounce uint32 = 0xFFFFFC

	// CtrlGroupBeacon is the reserved group index for the ADVERT beacon group.
	// Used at both site (FF05) and global (FF0E) scope.
	CtrlGroupBeacon uint32 = 0xFFFFFD

	// CtrlGroupControl is the reserved group index for the future control
	// channel (block templates, producer-broadcast data).
	CtrlGroupControl uint32 = 0xFFFFFE
)

// ControlGroupAddr constructs a 16-byte IPv6 multicast address for a
// control-plane group. This is a standalone helper (not bound to [Engine])
// because control groups may use a different scope prefix than the data-plane
// engine (e.g. both FF05 and FF0E for beacon groups).
//
// scopePrefix is the two-byte IPv6 multicast prefix (e.g. 0xFF05 or 0xFF0E).
// middleBytes are bytes 2–12 of the IPv6 address (operator prefix from -mc-base-addr).
// index is the control-plane group index (e.g. [CtrlGroupBeacon]).
func ControlGroupAddr(scopePrefix uint16, middleBytes [11]byte, index uint32) net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint16(ip[0:2], scopePrefix)
	copy(ip[2:13], middleBytes[:])
	ip[13] = byte(index >> 16)
	ip[14] = byte(index >> 8)
	ip[15] = byte(index)
	return ip
}
