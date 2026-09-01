package teewire

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	src := netip.MustParseAddrPort("[fd00:50:0:2::1]:9001")
	payload := []byte{0xE3, 0xE1, 0xF3, 0xE8, 0x00, 0x00, 0x02, 0x00, 0xAA, 0xBB}

	enc := AppendEncap(nil, src, payload)
	if len(enc) != HeaderSize+len(payload) {
		t.Fatalf("encap length = %d, want %d", len(enc), HeaderSize+len(payload))
	}
	if !IsEncap(enc) {
		t.Fatal("IsEncap = false for enveloped datagram")
	}

	gotSrc, gotPayload, err := Decap(enc)
	if err != nil {
		t.Fatalf("Decap: %v", err)
	}
	if gotSrc != src {
		t.Fatalf("source = %s, want %s", gotSrc, src)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %x, want %x", gotPayload, payload)
	}
}

func TestEmptyPayloadRoundTrips(t *testing.T) {
	src := netip.MustParseAddrPort("[::1]:1234")
	enc := AppendEncap(nil, src, nil)
	gotSrc, gotPayload, err := Decap(enc)
	if err != nil {
		t.Fatalf("Decap: %v", err)
	}
	if gotSrc != src || len(gotPayload) != 0 {
		t.Fatalf("got (%s, %d bytes), want (%s, 0 bytes)", gotSrc, len(gotPayload), src)
	}
}

func TestAppendReusesBuffer(t *testing.T) {
	src := netip.MustParseAddrPort("[fd00::1]:9001")
	payload := make([]byte, 100)
	buf := make([]byte, 0, 4096)

	enc := AppendEncap(buf, src, payload)
	if &enc[0] != &buf[:1][0] {
		t.Fatal("AppendEncap reallocated despite sufficient capacity")
	}
}

func TestDecapErrors(t *testing.T) {
	src := netip.MustParseAddrPort("[::1]:9001")
	good := AppendEncap(nil, src, []byte{1, 2, 3})

	short := good[:HeaderSize-1]
	if _, _, err := Decap(short); err != ErrTooShort {
		t.Fatalf("short datagram: err = %v, want ErrTooShort", err)
	}

	badMagic := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(badMagic[0:4], 0xE3E1F3E8) // fabric frame magic
	if _, _, err := Decap(badMagic); err != ErrBadMagic {
		t.Fatalf("bad magic: err = %v, want ErrBadMagic", err)
	}
	if IsEncap(badMagic) {
		t.Fatal("IsEncap = true for fabric-magic datagram")
	}

	badVer := append([]byte(nil), good...)
	badVer[4] = 0x7F
	if _, _, err := Decap(badVer); err != ErrBadVersion {
		t.Fatalf("bad version: err = %v, want ErrBadVersion", err)
	}
}

func TestFlagsByteIgnoredOnRead(t *testing.T) {
	src := netip.MustParseAddrPort("[fd00::2]:9001")
	enc := AppendEncap(nil, src, []byte{9})
	enc[5] = 0xFF // future writer setting flags must not break this reader
	if _, _, err := Decap(enc); err != nil {
		t.Fatalf("Decap with non-zero flags: %v", err)
	}
}

func Test4To6MappedSourceSurvives(t *testing.T) {
	// A datagram received over an IPv4-mapped socket presents ::ffff:a.b.c.d.
	// The envelope carries the 16-byte form verbatim.
	src := netip.MustParseAddrPort("[::ffff:10.0.0.1]:9001")
	enc := AppendEncap(nil, src, []byte{1})
	gotSrc, _, err := Decap(enc)
	if err != nil {
		t.Fatalf("Decap: %v", err)
	}
	if gotSrc.Addr().As16() != src.Addr().As16() || gotSrc.Port() != src.Port() {
		t.Fatalf("source = %s, want %s", gotSrc, src)
	}
}
