package frame

import (
	"encoding/binary"
	"errors"
	"testing"
)

func makeShardManifest() *ShardManifest {
	m := &ShardManifest{
		Flags:            ShardManifestFlagGroupsValid | ShardManifestFlagAuthoritative,
		InstanceID:       0xDEADBEEF,
		Epoch:            1746800000,
		TTL:              900,
		AnnounceInterval: 300,
		ShardBits:        4,
		RoleHint:         RoleHintProxy,
		Groups:           []uint16{0, 3, 5, 15},
	}
	for i := range m.SrcIPv6 {
		m.SrcIPv6[i] = byte(i + 1)
	}
	for i := range m.GenerationID {
		m.GenerationID[i] = byte(0xC0 + i)
	}
	return m
}

func TestShardManifest_RoundTrip_List(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	n, err := EncodeShardManifest(m, buf)
	if err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	if n != ShardManifestSize(m) {
		t.Fatalf("n = %d, want %d", n, ShardManifestSize(m))
	}
	if n != ShardManifestHeaderSize+2*len(m.Groups) {
		t.Fatalf("size mismatch: got %d", n)
	}

	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("DecodeShardManifest: %v", err)
	}
	if got.Flags != m.Flags {
		t.Errorf("Flags = 0x%02X, want 0x%02X", got.Flags, m.Flags)
	}
	if got.SrcIPv6 != m.SrcIPv6 {
		t.Errorf("SrcIPv6 mismatch")
	}
	if got.InstanceID != m.InstanceID {
		t.Errorf("InstanceID = 0x%08X, want 0x%08X", got.InstanceID, m.InstanceID)
	}
	if got.Epoch != m.Epoch || got.TTL != m.TTL || got.AnnounceInterval != m.AnnounceInterval {
		t.Errorf("time fields mismatch: %+v vs %+v", got, m)
	}
	if got.ShardBits != m.ShardBits || got.RoleHint != m.RoleHint {
		t.Errorf("shardbits/role mismatch")
	}
	if got.GenerationID != m.GenerationID {
		t.Errorf("GenerationID mismatch")
	}
	if len(got.Groups) != len(m.Groups) {
		t.Fatalf("Groups len = %d, want %d", len(got.Groups), len(m.Groups))
	}
	for i, g := range m.Groups {
		if got.Groups[i] != g {
			t.Errorf("Groups[%d] = %d, want %d", i, got.Groups[i], g)
		}
	}
	if len(got.Bitmap) != 0 {
		t.Errorf("Bitmap should be empty, got %d bytes", len(got.Bitmap))
	}
}

func TestShardManifest_RoundTrip_Bitmap(t *testing.T) {
	m := makeShardManifest()
	m.Groups = nil
	m.Bitmap = []byte{0b00010101, 0b10000000} // groups 0,2,4,15
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}

	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("DecodeShardManifest: %v", err)
	}
	if len(got.Bitmap) != len(m.Bitmap) {
		t.Fatalf("Bitmap len = %d, want %d", len(got.Bitmap), len(m.Bitmap))
	}
	for i, b := range m.Bitmap {
		if got.Bitmap[i] != b {
			t.Errorf("Bitmap[%d] = 0x%02X, want 0x%02X", i, got.Bitmap[i], b)
		}
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups should be empty, got %d", len(got.Groups))
	}
}

func TestShardManifest_IdentityOnly(t *testing.T) {
	m := makeShardManifest()
	m.Flags = 0
	m.Groups = nil
	m.Bitmap = nil
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	if len(buf) != ShardManifestHeaderSize {
		t.Errorf("size = %d, want %d", len(buf), ShardManifestHeaderSize)
	}
	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("DecodeShardManifest: %v", err)
	}
	if got.Flags != 0 {
		t.Errorf("Flags = 0x%02X, want 0", got.Flags)
	}
	if len(got.Groups) != 0 || len(got.Bitmap) != 0 {
		t.Errorf("expected empty payload, got %d groups / %d bitmap bytes", len(got.Groups), len(got.Bitmap))
	}
}

func TestShardManifest_WireLayout(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	if buf[6] != MsgTypeShardManifest {
		t.Errorf("buf[6] = 0x%02X, want 0x%02X", buf[6], MsgTypeShardManifest)
	}
	if buf[42] != 0 || buf[43] != 0 {
		t.Errorf("reserved bytes [42:44] non-zero")
	}
	// CRC field should not be zero (extremely unlikely for non-trivial data).
	if binary.BigEndian.Uint32(buf[44:48]) == 0 {
		t.Errorf("ManifestCRC unexpectedly zero")
	}
}

func TestShardManifest_BadMagic(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	buf[0] = 0
	_, err := DecodeShardManifest(buf)
	if !errors.Is(err, ErrBadMagic) {
		t.Errorf("want ErrBadMagic, got %v", err)
	}
}

func TestShardManifest_BadMsgType(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	buf[6] = 0x20
	_, err := DecodeShardManifest(buf)
	if !errors.Is(err, ErrShardManifestBadMsgType) {
		t.Errorf("want ErrShardManifestBadMsgType, got %v", err)
	}
}

func TestShardManifest_TooShort(t *testing.T) {
	_, err := DecodeShardManifest(make([]byte, ShardManifestHeaderSize-1))
	if !errors.Is(err, ErrShardManifestTooShort) {
		t.Errorf("want ErrShardManifestTooShort, got %v", err)
	}
}

func TestShardManifest_Truncated(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	// Drop the trailing payload while keeping the header (which still claims
	// GroupCount > 0).
	_, err := DecodeShardManifest(buf[:ShardManifestHeaderSize])
	if !errors.Is(err, ErrShardManifestTruncated) {
		t.Errorf("want ErrShardManifestTruncated, got %v", err)
	}
}

func TestShardManifest_BadCRC(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	buf[ShardManifestHeaderSize] ^= 0xFF // corrupt payload byte
	_, err := DecodeShardManifest(buf)
	if !errors.Is(err, ErrShardManifestBadCRC) {
		t.Errorf("want ErrShardManifestBadCRC, got %v", err)
	}
}

func TestShardManifest_OversizeShardBits(t *testing.T) {
	m := makeShardManifest()
	m.ShardBits = MaxShardBits + 1
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestSize(m)))
	if !errors.Is(err, ErrShardManifestBadShardBits) {
		t.Errorf("encode: want ErrShardManifestBadShardBits, got %v", err)
	}

	m.ShardBits = 0
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	buf[36] = MaxShardBits + 1
	// Recompute CRC so we test the ShardBits check, not CRC.
	buf[44] = 0
	buf[45] = 0
	buf[46] = 0
	buf[47] = 0
	if _, err := DecodeShardManifest(buf); !errors.Is(err, ErrShardManifestBadShardBits) {
		t.Errorf("decode: want ErrShardManifestBadShardBits, got %v", err)
	}
}

func TestShardManifest_BadEncoding_BothPayloads(t *testing.T) {
	m := makeShardManifest()
	m.Bitmap = []byte{0x01}
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestSize(m)+8))
	if !errors.Is(err, ErrShardManifestBadEncoding) {
		t.Errorf("want ErrShardManifestBadEncoding, got %v", err)
	}
}

func TestShardManifest_BadEncoding_GroupsValidNoPayload(t *testing.T) {
	m := makeShardManifest()
	m.Groups = nil
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestHeaderSize))
	if !errors.Is(err, ErrShardManifestBadEncoding) {
		t.Errorf("want ErrShardManifestBadEncoding, got %v", err)
	}
}

func TestShardManifest_BadEncoding_PayloadWithoutFlag(t *testing.T) {
	m := makeShardManifest()
	m.Flags = 0
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestSize(m)))
	if !errors.Is(err, ErrShardManifestBadEncoding) {
		t.Errorf("want ErrShardManifestBadEncoding, got %v", err)
	}
}

func TestShardManifest_BadEncoding_UnsortedList(t *testing.T) {
	m := makeShardManifest()
	m.Groups = []uint16{5, 3, 1}
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestSize(m)))
	if !errors.Is(err, ErrShardManifestBadEncoding) {
		t.Errorf("want ErrShardManifestBadEncoding, got %v", err)
	}
}

func TestShardManifest_IsShardManifest(t *testing.T) {
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	if !IsShardManifest(buf) {
		t.Errorf("IsShardManifest = false, want true")
	}
	if IsShardManifest(buf[:ShardManifestHeaderSize-1]) {
		t.Errorf("IsShardManifest on short buffer = true")
	}
	bad := make([]byte, ShardManifestHeaderSize)
	if IsShardManifest(bad) {
		t.Errorf("IsShardManifest on zero buffer = true")
	}
}
