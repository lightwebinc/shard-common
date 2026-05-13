package frame

import "bytes"

// efMarker is the 6-byte BRC-30 Extended Format marker that appears at payload
// offset 4 (immediately after the 4-byte little-endian version field) of a
// BRC-128 frame payload.
var efMarker = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xEF}

// IsEF reports whether payload is a BRC-30 Extended Format (BRC-128) BSV
// transaction. It inspects bytes 4–9 of the payload for the 6-byte EF marker
// (00 00 00 00 00 EF) that follows the 4-byte LE version field.
//
// Returns false for any payload shorter than 10 bytes or without the marker
// (in which case the payload is treated as a BRC-12 raw transaction).
//
// IsEF is a pure function on the payload bytes; it does not allocate.
func IsEF(payload []byte) bool {
	if len(payload) < 10 {
		return false
	}
	return bytes.Equal(payload[4:10], efMarker)
}
