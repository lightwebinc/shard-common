package shard

import (
	"encoding/binary"
	"fmt"
	"net"
)

// GroupIdx is a 16-bit IANA multicast group index occupying the last two
// bytes of a BRC-129 multicast address (bytes 14..15). Network-service
// groups are allocated from the top of the 0xF800–0xFFFF range; shard
// groups occupy the low end.
type GroupIdx uint16

// Network-service group indices (BRC-129 Multicast Group Address
// Assignments). Network services occupy 0xF800–0xFFFF (2,048 indices);
// current assignments are allocated from the top of that range.
const (
	// GroupBlockHeader is the egress channel for stripped BSV block
	// headers (BRC-135) sent to SPV consumers. Note: this is a
	// data-egress channel, not control-plane.
	GroupBlockHeader GroupIdx = 0xFFFA

	// GroupSubtreeDataAnnounce carries BRC-132 subtree data frames
	// (Merkle subtree contents). Distinct from the BRC-127 subtree
	// group-announce channel (GroupSubtreeGroupAnnounce, 0xFFFC).
	GroupSubtreeDataAnnounce GroupIdx = 0xFFFB

	// GroupSubtreeGroupAnnounce carries BRC-127 subtree group
	// announcements — SubtreeID↔GroupID bindings advertising logical
	// groupings of subtrees for downstream filtering.
	GroupSubtreeGroupAnnounce GroupIdx = 0xFFFC

	// GroupBeacon is the ADVERT beacon and BRC-139 shard-manifest
	// group. Used at site (FF05), org (FF08), and global (FF0E) scopes.
	GroupBeacon GroupIdx = 0xFFFD

	// GroupBlockBroadcast is the global control channel for
	// producer-broadcast block data: BRC-131 block announces, BRC-133
	// coinbase frames, and BRC-134 anchor frames. Mandatory FF0E scope.
	GroupBlockBroadcast GroupIdx = 0xFFFE
)

// Virtual group indices. Several BRCs share the GroupBlockBroadcast wire
// address but must form independent flows so each carries its own
// monotonic SeqNum counter on the proxy. The proxy's flow key is
// (senderIPv6, groupIdx, subtreeID); to keep these flows separate while
// emitting to the same multicast destination, the proxy substitutes a
// distinct virtual groupIdx into the HashKey computation. These virtual
// indices never appear in an actual IPv6 multicast address; they exist
// only as inputs to XXH64-based HashKey derivation.
const (
	// GroupCoinbaseFlow is the virtual index for BRC-133 coinbase
	// HashKey derivation. Coinbase frames egress to GroupBlockBroadcast
	// but must not share a SeqNum counter with BRC-131 block announces.
	GroupCoinbaseFlow GroupIdx = 0xFFF8

	// GroupAnchorFlow is the virtual index for BRC-134 anchor HashKey
	// derivation. Anchor frames egress to GroupBlockBroadcast but must
	// not share a SeqNum counter with BRC-131 / BRC-133 frames.
	GroupAnchorFlow GroupIdx = 0xFFF9
)

// String returns a stable snake_case label used in metrics and logs.
func (g GroupIdx) String() string {
	switch g {
	case GroupBlockHeader:
		return "block_header"
	case GroupSubtreeDataAnnounce:
		return "subtree_data_announce"
	case GroupSubtreeGroupAnnounce:
		return "subtree_group_announce"
	case GroupBeacon:
		return "beacon"
	case GroupBlockBroadcast:
		return "block_broadcast"
	case GroupCoinbaseFlow:
		return "coinbase_flow"
	case GroupAnchorFlow:
		return "anchor_flow"
	default:
		return fmt.Sprintf("0x%04x", uint16(g))
	}
}

// GroupAddr constructs a 16-byte IPv6 multicast address for a network-service
// group. This is a standalone helper (not bound to [Engine]) because these
// groups may use a different scope prefix than the data-plane engine
// (e.g. both FF05 and FF0E for beacon groups).
//
// scopePrefix is the two-byte IPv6 multicast prefix (e.g. 0xFF05 or 0xFF0E).
// groupID is the 16-bit IANA group-id occupying bytes 12–13 of the address
// (default [DefaultGroupID] = 0x000B for Bitcoin).
// idx is the group index (e.g. [GroupBeacon]).
func GroupAddr(scopePrefix uint16, groupID uint16, idx GroupIdx) net.IP {
	ip := make(net.IP, 16)
	binary.BigEndian.PutUint16(ip[0:2], scopePrefix)
	// bytes 2..11 remain zero (IANA 96-bit boundary)
	binary.BigEndian.PutUint16(ip[12:14], groupID)
	binary.BigEndian.PutUint16(ip[14:16], uint16(idx))
	return ip
}
