package objfmt

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

// efMarker is the 6-byte BRC-30 Extended Format marker that follows the
// 4-byte version. It cannot collide with a standard transaction: the first
// marker byte would be an input-count VarInt of 0x00, and a zero-input
// transaction is invalid.
var efMarker = [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xEF}

// IsEF reports whether tx begins a BRC-30 Extended Format transaction
// (marker at bytes 4–9). It returns false when tx is too short to tell.
func IsEF(tx []byte) bool {
	if len(tx) < 10 {
		return false
	}
	for i, b := range efMarker {
		if tx[4+i] != b {
			return false
		}
	}
	return true
}

// varInt decodes a Bitcoin compact-size integer at buf[off:]. It returns the
// value and the number of bytes consumed, ErrShort when buf ends inside the
// VarInt, and ErrMalformed on a non-canonical width prefix overrunning bounds.
func varInt(buf []byte, off int) (uint64, int, error) {
	if off >= len(buf) {
		return 0, 0, ErrShort
	}
	first := buf[off]
	switch {
	case first < 0xFD:
		return uint64(first), 1, nil
	case first == 0xFD:
		if off+3 > len(buf) {
			return 0, 0, ErrShort
		}
		return uint64(binary.LittleEndian.Uint16(buf[off+1:])), 3, nil
	case first == 0xFE:
		if off+5 > len(buf) {
			return 0, 0, ErrShort
		}
		return uint64(binary.LittleEndian.Uint32(buf[off+1:])), 5, nil
	default: // 0xFF
		if off+9 > len(buf) {
			return 0, 0, ErrShort
		}
		return binary.LittleEndian.Uint64(buf[off+1:]), 9, nil
	}
}

// advance adds n bytes to off, guarding against overflow and reporting
// ErrShort when the result runs past buf.
func advance(buf []byte, off int, n uint64) (int, error) {
	if n > math.MaxInt32 || off > math.MaxInt32 {
		return 0, fmt.Errorf("%w: length overflow", ErrMalformed)
	}
	next := off + int(n)
	if next > len(buf) {
		return 0, ErrShort
	}
	return next, nil
}

// TxSize returns the total serialized length of the BSV transaction at the
// start of buf, walking the transaction structure: version, optional BRC-30
// EF marker, input vector (with per-input EF extensions when the marker is
// present), output vector, locktime.
//
// This is the ClassTx stream delimiter: back-to-back transactions on a byte
// stream are split by repeated TxSize calls, no outer framing needed.
//
// Returns [ErrShort] when buf is a valid but incomplete prefix and
// [ErrMalformed] when the bytes cannot be a valid transaction (zero inputs
// or outputs, overflowing lengths).
func TxSize(buf []byte) (int, error) {
	off, err := advance(buf, 0, 4) // version
	if err != nil {
		return 0, err
	}

	ef := IsEF(buf)
	if !ef && len(buf) >= 5 && buf[4] == 0x00 {
		// A standard tx cannot have input-count VarInt 0x00; the only
		// legal reading of a 0x00 at offset 4 is an EF marker we cannot
		// yet see in full.
		if len(buf) < 10 {
			return 0, ErrShort
		}
		return 0, fmt.Errorf("%w: zero input count", ErrMalformed)
	}
	if ef {
		off += 6 // marker
	}

	inCount, n, err := varInt(buf, off)
	if err != nil {
		return 0, err
	}
	off += n
	if inCount == 0 {
		return 0, fmt.Errorf("%w: zero input count", ErrMalformed)
	}

	for i := uint64(0); i < inCount; i++ {
		if off, err = advance(buf, off, 36); err != nil { // prev txid + index
			return 0, err
		}
		sLen, n, err := varInt(buf, off)
		if err != nil {
			return 0, err
		}
		off += n
		if off, err = advance(buf, off, sLen); err != nil { // unlocking script
			return 0, err
		}
		if off, err = advance(buf, off, 4); err != nil { // sequence
			return 0, err
		}
		if ef {
			if off, err = advance(buf, off, 8); err != nil { // spent value
				return 0, err
			}
			lLen, n, err := varInt(buf, off)
			if err != nil {
				return 0, err
			}
			off += n
			if off, err = advance(buf, off, lLen); err != nil { // spent locking script
				return 0, err
			}
		}
	}

	outCount, n, err := varInt(buf, off)
	if err != nil {
		return 0, err
	}
	off += n
	if outCount == 0 {
		return 0, fmt.Errorf("%w: zero output count", ErrMalformed)
	}

	for i := uint64(0); i < outCount; i++ {
		if off, err = advance(buf, off, 8); err != nil { // value
			return 0, err
		}
		sLen, n, err := varInt(buf, off)
		if err != nil {
			return 0, err
		}
		off += n
		if off, err = advance(buf, off, sLen); err != nil { // locking script
			return 0, err
		}
	}

	if off, err = advance(buf, off, 4); err != nil { // locktime
		return 0, err
	}
	return off, nil
}

// ToStandard returns the standard (BRC-12) serialization of tx. A BRC-30 EF
// transaction has its marker and per-input extensions removed; a standard
// transaction is returned as-is (no copy). The result is the serialization
// TxID is computed over.
func ToStandard(tx []byte) ([]byte, error) {
	n, err := TxSize(tx)
	if err != nil {
		return nil, err
	}
	tx = tx[:n]
	if !IsEF(tx) {
		return tx, nil
	}

	out := make([]byte, 0, len(tx)-10)
	out = append(out, tx[0:4]...) // version
	off := 10                     // skip marker

	inCount, n2, err := varInt(tx, off)
	if err != nil {
		return nil, err
	}
	out = append(out, tx[off:off+n2]...)
	off += n2

	for i := uint64(0); i < inCount; i++ {
		start := off
		off += 36 // prev txid + index
		sLen, n3, err := varInt(tx, off)
		if err != nil {
			return nil, err
		}
		off += n3 + int(sLen) + 4 // script + sequence
		out = append(out, tx[start:off]...)

		off += 8 // skip spent value
		lLen, n4, err := varInt(tx, off)
		if err != nil {
			return nil, err
		}
		off += n4 + int(lLen) // skip spent locking script
	}

	out = append(out, tx[off:]...) // outputs + locktime, verbatim
	return out, nil
}

// TxID returns the transaction ID — SHA256d over the standard serialization,
// internal byte order — of the transaction at the start of tx. For a BRC-30
// EF transaction the ID is computed with the EF extras excluded, matching
// how every consumer derives it.
func TxID(tx []byte) ([32]byte, error) {
	std, err := ToStandard(tx)
	if err != nil {
		return [32]byte{}, err
	}
	first := sha256.Sum256(std)
	return sha256.Sum256(first[:]), nil
}
