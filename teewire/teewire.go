// Package teewire implements the loopback tee envelope: a 24-byte header
// prepended to a raw fabric datagram when a co-resident process (shard-listener,
// shard-proxy) mirrors received or egressed frames into a retry-endpoint's
// tee-ingest socket over loopback UDP.
//
// # Why an envelope exists
//
// A mirrored datagram is sent from a local socket, so the receiving cache sees
// a loopback source address ("::1") instead of the frame's fabric source. The
// retry-endpoint's per-source cache counters (bre_cache_stored_total{source=…})
// are an alerting contract — a source whose frames stop being cached must read
// as a ZERO RATE on its own label, not vanish into a shared "::1" label. The
// envelope carries the original datagram source so a tee-fed cache preserves
// per-source attribution exactly as a multicast-joined one does.
//
// # Trust model (operational invariant)
//
// The envelope asserts a source address, so it MUST only be accepted on a
// socket bound to a loopback address. A receiver that unwrapped envelopes
// arriving from the network would let a remote sender forge per-source
// attribution. Writers target loopback; readers bind loopback.
//
// # Layout (network byte order)
//
//	Offset  Size  Field
//	 0      4     Magic 0x54454531 ("TEE1"; distinct from the fabric frame
//	              magic, so raw frames and envelopes share a socket safely)
//	 4      1     Version (0x01)
//	 5      1     Flags (reserved; writers MUST send 0, readers MUST ignore)
//	 6      16    Original source IPv6 address
//	22      2     Original source UDP port
//	24      …     Original datagram bytes, verbatim
//
// Zone/scope identifiers on the source address are not carried: fabric sources
// are global or ULA /128s, never link-local.
package teewire

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	// Magic identifies a tee envelope. It differs from the fabric frame
	// magic (frame.MagicBSV, 0xE3E1F3E8) in the first byte, so a receiver
	// can branch envelope-vs-raw on the leading 4 bytes alone.
	Magic uint32 = 0x54454531 // "TEE1"

	// Version is the current envelope version.
	Version byte = 0x01

	// HeaderSize is the fixed envelope header length in bytes.
	HeaderSize = 24
)

var (
	// ErrTooShort is returned when a datagram is shorter than HeaderSize.
	ErrTooShort = errors.New("teewire: datagram shorter than envelope header")

	// ErrBadMagic is returned when the leading 4 bytes are not Magic.
	ErrBadMagic = errors.New("teewire: invalid envelope magic")

	// ErrBadVersion is returned for an unsupported envelope version.
	ErrBadVersion = errors.New("teewire: unsupported envelope version")
)

// IsEncap reports whether b begins with the tee envelope magic. It is the
// cheap branch test for receivers whose socket carries both enveloped and
// raw datagrams; Decap performs full validation.
func IsEncap(b []byte) bool {
	return len(b) >= 4 && binary.BigEndian.Uint32(b[0:4]) == Magic
}

// AppendEncap appends an envelope for payload with original source src to
// dst and returns the extended slice. Callers on a hot path pass dst[:0] of
// a reused buffer to avoid per-datagram allocation.
func AppendEncap(dst []byte, src netip.AddrPort, payload []byte) []byte {
	var hdr [HeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], Magic)
	hdr[4] = Version
	hdr[5] = 0 // flags: reserved
	a16 := src.Addr().As16()
	copy(hdr[6:22], a16[:])
	binary.BigEndian.PutUint16(hdr[22:24], src.Port())
	dst = append(dst, hdr[:]...)
	return append(dst, payload...)
}

// Decap validates the envelope in b and returns the original datagram source
// and the payload. The payload aliases b — it is valid only as long as b is.
func Decap(b []byte) (src netip.AddrPort, payload []byte, err error) {
	if len(b) < HeaderSize {
		return netip.AddrPort{}, nil, ErrTooShort
	}
	if binary.BigEndian.Uint32(b[0:4]) != Magic {
		return netip.AddrPort{}, nil, ErrBadMagic
	}
	if b[4] != Version {
		return netip.AddrPort{}, nil, ErrBadVersion
	}
	var a16 [16]byte
	copy(a16[:], b[6:22])
	addr := netip.AddrFrom16(a16)
	port := binary.BigEndian.Uint16(b[22:24])
	return netip.AddrPortFrom(addr, port), b[HeaderSize:], nil
}
