// Package interest implements the topic interest protocol: the signal by
// which a consumer of overlay topics tells the network which topics it wants
// now.
//
// An interest names a TopicID (SHA-256 of the UTF-8 topic name) with a
// lifetime. It travels upward hop by hop, from the host that wants the topic,
// through any relays, to the multicast delivery edge that serves the
// consumer, and it stops there. The fabric never carries it. State is soft:
// an interest expires unless refreshed.
//
// # Draft status
//
// The wire implemented here is version 0, a draft. It is not frozen and may
// change without notice until the protocol is specified in a BRC. A receiver
// answers a message of another version with [ResultVersion] and applies
// nothing.
//
// # Roles
//
// Three roles exist, and this package provides the two halves they are built
// from:
//
//   - An announcer wants topics. It is a [Client].
//   - A terminus is where interest ends: the delivery edge. It is a
//     [Receiver] with a [Policy] that knows the consumer's bound and the
//     groups its tunnel delivers.
//   - A relay has announcers below it and speaks upward for them. It is a
//     [Receiver] whose union feeds a [Client].
//
// The same four datagrams are used at every hop, so a host whose own machine
// holds the tunnel talks to the edge directly and a relay is never required.
//
// # Messages
//
// One UDP datagram per message, never larger than [MaxDatagram]:
//
//   - ANNOUNCE carries delta records: a topic with a lifetime, or with
//     lifetime zero to withdraw it.
//   - DIGEST carries the count and digest of the sender's whole set. A match
//     refreshes every entry at once; a mismatch makes the sender replay.
//   - ACK answers either, with the token the sender must echo, the digest of
//     the set the receiver holds, the lifetimes it enforces, a status for
//     each record it did not simply accept, and the groups it delivers.
//   - RESYNC is a poke from a receiver: check in now. It is not
//     authenticated, so a sender acts on one at most once a second, and all
//     it causes is datagrams to that receiver. A sender that had stopped
//     hearing from the receiver starts its timeouts over and says everything
//     again at once: a standby edge that takes a consumer over pokes it.
//
// A sender accepts answers only from the address it sends to. On Linux,
// [ServeReceiver] therefore answers from the address each datagram was sent
// to, which a socket bound to a wildcard address on a host with several
// addresses would not otherwise do. Elsewhere, bind a receiver to the address
// its senders use.
//
// # Correctness under loss
//
// A receiver applies a message only if its sequence number is higher than
// the last one it applied for that sender, so nothing is ever applied out of
// order. A sender never retransmits a datagram: what was not acknowledged is
// still dirty and is sent again, as it stands now, under a new sequence
// number. The digest in every ACK lets the sender see drift and repair it by
// replaying its set and then sending a DIGEST that sweeps what the replay did
// not mention.
//
// The token is issued by the receiver and bound to the sender's address. A
// message without the right token is not applied, which proves the sender
// can receive at the address it claims, and makes a receiver restart visible:
// a new token means the receiver holds nothing and the sender replays.
//
// # Use without sockets
//
// [Receiver] and [Client] do no I/O and read no clock. They are driven with
// datagrams and timestamps, which makes them deterministic under test.
// [ServeReceiver] and [RunClient] bind them to UDP sockets.
package interest
