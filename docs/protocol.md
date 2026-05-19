# BSV Shard — Wire Protocol Specification

## 1. Overview

The BSV sharding pipeline transports raw BSV transactions over IPv6 UDP (or TCP
for reliable delivery) using a compact binary frame format. Every frame begins
with the BSV mainnet P2P network magic so that standard firewall rules and
network monitors already configured for BSV traffic classify shard datagrams
correctly.

## 2. BRC-124 Frame Format (current)

**Header size:** 92 bytes.  
**Byte order:** big-endian for all multi-byte integers.

```text
Offset  Size  Align  Field                 Value / notes
------  ----  -----  -----                 -------------
     0     4   —     Network magic         0xE3E1F3E8 (BSV mainnet P2P magic)
     4     2   —     Protocol ver          0x02BF = 703
     6     1   —     Frame version         0x02 (BRC-124/BRC-128)
     7     1   —     Reserved              0x00
     8    32   8B    Transaction ID        raw 256-bit txid (internal byte order)
    40     8   8B    HashKey               XXH64 per-flow identifier; 0 = unstamped
    48     8   8B    SeqNum                monotonic per-flow counter; 0 = unstamped
    56    32   8B    Subtree ID            32-byte batch identifier; zeros = unset
    88     4   8B    Payload length        uint32; max 10 MiB
    92     *   —     BSV tx payload        raw serialised transaction bytes (BRC-12 or BRC-30 Extended Format for BRC-128)
```

**Alignment verification:**
| Field | Offset | Offset % 8 |
|-----------|--------|------------|
| TXID | 8 | 0 ✓ |
| HashKey | 40 | 0 ✓ |
| SeqNum | 48 | 0 ✓ |
| SubtreeID | 56 | 0 ✓ |
| PayLen | 88 | 0 ✓ |

### 2.1 Fields

**Network magic (0:4)** — `0xE3E1F3E8`. The BSV mainnet P2P network magic.
Frames that do not start with this value are rejected.

**Protocol version (4:6)** — `0x02BF` (703). The BSV node protocol version
baseline that introduced the large-block policy. This field is informational;
receivers do not validate it.

**Frame version (6)** — `0x02` for BRC-124/BRC-128, `0x01` for BRC-12 (legacy, see §3). Any other
value is rejected. Both BRC-12 and BRC-124/BRC-128 frames are forwarded verbatim.

**Reserved (7)** — Must be `0x00`. Reserved for future use.

**Transaction ID (8:40)** — 32 bytes. The raw 256-bit txid in internal byte
order as used in the BSV P2P protocol — **not** the reversed display order
shown by block explorers. The top bits of `txid[0:4]` are used by the shard
engine to derive the multicast group index.

**HashKey (40:48)** — `uint64` big-endian. Stable per-flow identifier computed
as `XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID)`. Identifies the unique
`(sender, group, subtree)` flow. Set either by the sender or stamped in-place
by the proxy (see §6). A value of `0` means unstamped.

**SeqNum (48:56)** — `uint64` big-endian. Monotonic per-flow counter, starting
at 1. Each new frame in a flow increments this value. Set either by the sender
or stamped in-place by the proxy (see §6). A value of `0` means unstamped.
Receivers track the last-seen SeqNum per HashKey; a jump of more than 1
indicates a gap that triggers NACK-based retransmission.

**Subtree ID (56:88)** — 32 bytes. An opaque batch identifier assigned by the
transaction processor. All-zero bytes mean the field is unset. Passed through
unchanged by the proxy.

**Payload length (88:92)** — `uint32` big-endian. The number of payload bytes
immediately following the header. The application determines the maximum accepted size.

**Payload (92+)** — Raw serialised BSV transaction (BRC-12) or BRC-30 Extended
Format (EF) transaction (BRC-128). Same format as the BSV P2P `tx` message
payload (version LE32 + inputs + outputs + locktime LE32) for BRC-12, or the
EF serialisation for BRC-30. No P2P message envelope wraps it. BRC-128 payloads
are self-identifying via a 6-byte marker at payload bytes 4–9
(`0x000000000000EF`); infrastructure components are payload-agnostic.

---

## 3. Legacy BRC-12 Frame Format

Legacy BRC-12 frames use a 44-byte header and carry no BRC-124 fields.
The proxy accepts them and forwards them verbatim without modification.

```text
Offset  Size  Field
------  ----  -----
     0     4  Network magic    0xE3E1F3E8
     4     2  Protocol ver     0x02BF
     6     1  Frame version    0x01
     7     1  Reserved         0x00
     8    32  Transaction ID
    40     4  Payload length
    44     *  Payload
```

**TCP ingress:** the TCP reader reads 44 bytes first to detect the version, then
completes the header read if BRC-124/BRC-128 (48 more bytes). No separate port is needed
for BRC-12 and BRC-124/BRC-128 — both formats share the same listener.

---

## 4. Subtree Model

A *subtree* is an ordered set of related transactions sharing a common batch
context. The `SubtreeID` field allows downstream subscribers to associate
frames with a named batch:

- **`SubtreeID`** — 32-byte opaque batch identifier; all-zero means unset.

This field is optional. The proxy passes it through unchanged.

---

## 5. Shard Derivation

The multicast group for a frame is derived from its `TxID`:

```
groupIndex = (txid[0:4] as uint32 BE) >> (32 - shardBits)
```

where `shardBits` is the configured `-shard-bits` value (default 2, range
1–15). The group index maps to an IPv6 multicast address:

```
[FFsc::groupIndex]
```

where `sc` is the two-nibble scope code (e.g. `FF05` for site-local). The
IANA group-id occupies bytes 12–13 (default `0x000B` = IANA Bitcoin
allocation `FF0X::B`); the 16-bit shard index occupies bytes 14–15.

**Consistent-hashing property:** increasing `shardBits` by 1 splits every
existing group into exactly two child groups. Subscribers need only join
additional groups; no existing subscriptions become invalid.

---

## 6. Proxy Forward Rules

The proxy processes each incoming datagram in two steps:

1. **Decode** — parse the frame header (BRC-12 or BRC-124/BRC-128); drop with a debug log on
   bad magic, unsupported version, oversized payload, or truncated datagram.
   The TxID is extracted to derive the destination multicast group.

2. **Forward** — for BRC-124 frames, if `SeqNum` (`raw[48:56]`) is **non-zero**
   the sender has pre-stamped the frame and it is forwarded verbatim. If `SeqNum`
   is zero the proxy stamps `HashKey` at `raw[40:48]` and `SeqNum` at `raw[48:56]`
   in-place: `HashKey = XXH64(senderIPv6 ∥ groupIdx ∥ subtreeID)` and `SeqNum`
   is the next monotonic counter for that flow. `SubtreeID` is read from
   `raw[56:88]` (zeros if unset). Write the raw bytes to every configured egress
   interface via `IPV6_MULTICAST_IF`. BRC-12 frames are always forwarded verbatim
   without modification.

---

## 7. TCP Ingress

When `-tcp-listen-port` is non-zero, the proxy also accepts TCP connections for
reliable frame delivery. The TCP wire format is identical to UDP: BRC-12, BRC-124, or BRC-128
frames concatenated end-to-end with no additional envelope.

**Read sequence per frame:**
1. Read 44 bytes (minimum header, sufficient for both BRC-12 and the start of BRC-124/BRC-128).
2. Inspect `FrameVer` at byte 6.
   - **BRC-12:** header is complete; `PayLen` is at bytes 40–43.
   - **BRC-124/BRC-128:** read 48 more bytes to complete the 92-byte header;
     `PayLen` is at bytes 88–91.
3. Read exactly `PayLen` bytes (the payload).
4. Forward the reassembled raw bytes (HashKey/SeqNum stamped at 40–55 if SeqNum was zero, before processing).

The proxy closes the TCP connection on any protocol violation (bad magic,
unsupported version byte, or read error).

---

## 8. Error Handling

| Condition | UDP | TCP |
|----------------------------------------|----------------------------------|----------------------------------|
| Bad magic | datagram silently dropped | connection closed |
| Unknown frame version (not BRC-12/BRC-124)      | datagram silently dropped | connection closed                |
| Truncated datagram                     | datagram silently dropped | read error → connection closed   |
| Egress write error | logged; next interface attempted | logged; next interface attempted |

All drops are counted in the `bsp_packets_dropped_total` Prometheus metric with
a `reason` label (`decode_error`, `write_error`, or `truncated`).

---

## 9. Constants Reference

| Name | Value | Notes |
|--------------------|--------------|---------------------------------------------|
| `MagicBSV` | `0xE3E1F3E8` | BSV mainnet P2P magic |
| `ProtoVer` | `0x02BF` | Protocol version 703 |
| `FrameVerV1` | `0x01` | Legacy BRC-12; accepted, forwarded verbatim |
| `FrameVerV2` | `0x02` | BRC-124/BRC-128 transaction frames |
| `FrameVerV3` | `0x03` | BRC-130 fragment frames (104-byte header) |
| `FrameVerV4` | `0x04` | BRC-131 block control frames |
| `FrameVerV5` | `0x05` | BRC-132 subtree data frames |
| `HeaderSizeLegacy` | `44` | Legacy BRC-12 header bytes |
| `HeaderSize` | `92` | BRC-124/128/131/132 header bytes |
| `HeaderSizeV3` | `104` | BRC-130 fragment header bytes |
| `MsgTypeSubtreeAnnounce` | `0x30` | BRC-127 SubtreeAnnounce datagram type |
| `SubtreeAnnounceSize` | `64` | Fixed SubtreeAnnounce datagram size |
| `CtrlGroupSubtreeAnnounce` | `0xFFFB` | Control-plane subtree data group |
| `CtrlGroupSubtreeGroupAnnounce` | `0xFFFC` | Control-plane subtree announce group |
| `CtrlGroupBeacon` | `0xFFFD` | Control-plane ADVERT beacon group |
| `CtrlGroupControl` | `0xFFFE` | Block control channel |
| `DefaultGroupID` | `0x000B` | IANA Bitcoin multicast group-id (`FF0X::B`) |
