package frame

import (
	"testing"
)

func makeSubtreeGroupAnnounce() *SubtreeGroupAnnounce {
	a := &SubtreeGroupAnnounce{
		Epoch: 1746800000,
		TTL:   300,
	}
	for i := range a.SubtreeID {
		a.SubtreeID[i] = byte(i + 1)
	}
	for i := range a.GroupID {
		a.GroupID[i] = byte(0xA0 + i)
	}
	return a
}

func TestSubtreeGroupAnnounce_RoundTrip(t *testing.T) {
	a := makeSubtreeGroupAnnounce()
	buf := make([]byte, SubtreeGroupAnnounceSize)
	n, err := EncodeSubtreeGroupAnnounce(a, buf)
	if err != nil {
		t.Fatalf("EncodeSubtreeGroupAnnounce: %v", err)
	}
	if n != SubtreeGroupAnnounceSize {
		t.Fatalf("n = %d, want %d", n, SubtreeGroupAnnounceSize)
	}

	got, err := DecodeSubtreeGroupAnnounce(buf)
	if err != nil {
		t.Fatalf("DecodeSubtreeGroupAnnounce: %v", err)
	}
	if got.SubtreeID != a.SubtreeID {
		t.Errorf("SubtreeID mismatch")
	}
	if got.GroupID != a.GroupID {
		t.Errorf("GroupID mismatch")
	}
	if got.Epoch != a.Epoch {
		t.Errorf("Epoch = %d, want %d", got.Epoch, a.Epoch)
	}
	if got.TTL != a.TTL {
		t.Errorf("TTL = %d, want %d", got.TTL, a.TTL)
	}
}

func TestSubtreeGroupAnnounce_WireLayout(t *testing.T) {
	a := makeSubtreeGroupAnnounce()
	buf := make([]byte, SubtreeGroupAnnounceSize)
	if _, err := EncodeSubtreeGroupAnnounce(a, buf); err != nil {
		t.Fatalf("EncodeSubtreeGroupAnnounce: %v", err)
	}

	if buf[6] != MsgTypeSubtreeGroupAnnounce {
		t.Errorf("buf[6] MsgType = 0x%02X, want 0x%02X", buf[6], MsgTypeSubtreeGroupAnnounce)
	}
	if buf[7] != 0x00 {
		t.Errorf("buf[7] Flags = 0x%02X, want 0x00", buf[7])
	}
	if buf[62] != 0x00 || buf[63] != 0x00 {
		t.Errorf("reserved bytes [62:64] non-zero: 0x%02X 0x%02X", buf[62], buf[63])
	}
}

func TestSubtreeGroupAnnounce_TTLZero(t *testing.T) {
	a := makeSubtreeGroupAnnounce()
	a.TTL = 0
	buf := make([]byte, SubtreeGroupAnnounceSize)
	if _, err := EncodeSubtreeGroupAnnounce(a, buf); err != nil {
		t.Fatalf("EncodeSubtreeGroupAnnounce: %v", err)
	}
	got, err := DecodeSubtreeGroupAnnounce(buf)
	if err != nil {
		t.Fatalf("DecodeSubtreeGroupAnnounce: %v", err)
	}
	if got.TTL != 0 {
		t.Errorf("TTL = %d, want 0", got.TTL)
	}
}

func TestSubtreeGroupAnnounce_BadMagic(t *testing.T) {
	a := makeSubtreeGroupAnnounce()
	buf := make([]byte, SubtreeGroupAnnounceSize)
	if _, err := EncodeSubtreeGroupAnnounce(a, buf); err != nil {
		t.Fatalf("EncodeSubtreeGroupAnnounce: %v", err)
	}
	buf[0] = 0x00 // corrupt magic
	_, err := DecodeSubtreeGroupAnnounce(buf)
	if err != ErrBadMagic {
		t.Errorf("want ErrBadMagic, got %v", err)
	}
}

func TestSubtreeGroupAnnounce_TooShort(t *testing.T) {
	_, err := DecodeSubtreeGroupAnnounce(make([]byte, SubtreeGroupAnnounceSize-1))
	if err != ErrSubtreeGroupAnnounceTooShort {
		t.Errorf("want ErrSubtreeGroupAnnounceTooShort, got %v", err)
	}
}

func TestSubtreeGroupAnnounce_EncodeBufTooSmall(t *testing.T) {
	a := makeSubtreeGroupAnnounce()
	_, err := EncodeSubtreeGroupAnnounce(a, make([]byte, SubtreeGroupAnnounceSize-1))
	if err == nil {
		t.Error("want error for small buffer, got nil")
	}
}
