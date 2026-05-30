package frame

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
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
	// SourceCount at [42:44] is zero when the manifest carries no sources.
	if buf[42] != 0 || buf[43] != 0 {
		t.Errorf("SourceCount bytes [42:44] = %v, want zero (no sources)", buf[42:44])
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

func makeSrc(b byte) [16]byte {
	var s [16]byte
	s[0] = 0xFD
	s[1] = 0x20
	s[15] = b
	return s
}

func TestShardManifest_RoundTrip_WithSources(t *testing.T) {
	m := makeShardManifest()
	m.Flags |= ShardManifestFlagSourcesValid | ShardManifestFlagSourceModeSSM
	m.Sources = [][16]byte{makeSrc(0x01), makeSrc(0x02), makeSrc(0x03)}

	buf := make([]byte, ShardManifestSize(m))
	n, err := EncodeShardManifest(m, buf)
	if err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	want := ShardManifestHeaderSize + 2*len(m.Groups) + 16*len(m.Sources)
	if n != want {
		t.Fatalf("encoded size = %d, want %d", n, want)
	}

	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("DecodeShardManifest: %v", err)
	}
	if got.Flags != m.Flags {
		t.Errorf("Flags = 0x%02X, want 0x%02X", got.Flags, m.Flags)
	}
	if len(got.Sources) != len(m.Sources) {
		t.Fatalf("Sources len = %d, want %d", len(got.Sources), len(m.Sources))
	}
	for i := range m.Sources {
		if got.Sources[i] != m.Sources[i] {
			t.Errorf("Sources[%d] = %x, want %x", i, got.Sources[i], m.Sources[i])
		}
	}
}

func TestShardManifest_WireLayout_SourceCount(t *testing.T) {
	m := makeShardManifest()
	m.Flags |= ShardManifestFlagSourcesValid
	m.Sources = [][16]byte{makeSrc(0x01), makeSrc(0x02)}

	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	got := binary.BigEndian.Uint16(buf[42:44])
	if got != 2 {
		t.Errorf("SourceCount at [42:44] = %d, want 2", got)
	}
}

func TestShardManifest_BadSources_FlagWithoutPayload(t *testing.T) {
	m := makeShardManifest()
	m.Flags |= ShardManifestFlagSourcesValid // no Sources set
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestSize(m)))
	if !errors.Is(err, ErrShardManifestBadSources) {
		t.Errorf("want ErrShardManifestBadSources, got %v", err)
	}
}

func TestShardManifest_BadSources_PayloadWithoutFlag(t *testing.T) {
	m := makeShardManifest()
	m.Sources = [][16]byte{makeSrc(0x01)}
	_, err := EncodeShardManifest(m, make([]byte, ShardManifestSize(m)+16))
	if !errors.Is(err, ErrShardManifestBadSources) {
		t.Errorf("want ErrShardManifestBadSources, got %v", err)
	}
}

func TestShardManifest_Decode_RejectsSourcesValidWithZeroCount(t *testing.T) {
	// Encode a valid manifest, then mutate Flags to set SourcesValid while
	// SourceCount remains 0, recompute CRC, and verify decode rejects.
	m := makeShardManifest()
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	buf[7] |= ShardManifestFlagSourcesValid
	// Recompute CRC with zeroed CRC field.
	buf[44], buf[45], buf[46], buf[47] = 0, 0, 0, 0
	recomputeCRC(buf)

	_, err := DecodeShardManifest(buf)
	if !errors.Is(err, ErrShardManifestBadSources) {
		t.Errorf("want ErrShardManifestBadSources, got %v", err)
	}
}

func TestShardManifest_Decode_RejectsSourcesWithoutValidFlag(t *testing.T) {
	m := makeShardManifest()
	m.Flags |= ShardManifestFlagSourcesValid
	m.Sources = [][16]byte{makeSrc(0x42)}
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	// Clear the SourcesValid flag while keeping SourceCount > 0.
	buf[7] &^= ShardManifestFlagSourcesValid
	buf[44], buf[45], buf[46], buf[47] = 0, 0, 0, 0
	recomputeCRC(buf)

	_, err := DecodeShardManifest(buf)
	if !errors.Is(err, ErrShardManifestBadSources) {
		t.Errorf("want ErrShardManifestBadSources, got %v", err)
	}
}

func TestShardManifest_SourceModeSSM_FlagOnly(t *testing.T) {
	// SourceModeSSM is independent of SourcesValid: a manifest may declare
	// the data plane uses SSM without contributing any sources of its own.
	m := makeShardManifest()
	m.Flags |= ShardManifestFlagSourceModeSSM
	buf := make([]byte, ShardManifestSize(m))
	if _, err := EncodeShardManifest(m, buf); err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("DecodeShardManifest: %v", err)
	}
	if got.Flags&ShardManifestFlagSourceModeSSM == 0 {
		t.Errorf("SourceModeSSM flag lost in round-trip")
	}
	if len(got.Sources) != 0 {
		t.Errorf("Sources = %v, want empty", got.Sources)
	}
}

func recomputeCRC(buf []byte) {
	tmp := make([]byte, len(buf))
	copy(tmp, buf)
	tmp[44], tmp[45], tmp[46], tmp[47] = 0, 0, 0, 0
	crc := crc32.Checksum(tmp, crc32.MakeTable(crc32.Castagnoli))
	binary.BigEndian.PutUint32(buf[44:48], crc)
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
