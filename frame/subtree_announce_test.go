package frame

import (
	"testing"
)

func makeSubtreeAnnounce() *SubtreeAnnounce {
	a := &SubtreeAnnounce{
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

func TestSubtreeAnnounce_RoundTrip(t *testing.T) {
	a := makeSubtreeAnnounce()
	buf := make([]byte, SubtreeAnnounceSize)
	n, err := EncodeSubtreeAnnounce(a, buf)
	if err != nil {
		t.Fatalf("EncodeSubtreeAnnounce: %v", err)
	}
	if n != SubtreeAnnounceSize {
		t.Fatalf("n = %d, want %d", n, SubtreeAnnounceSize)
	}

	got, err := DecodeSubtreeAnnounce(buf)
	if err != nil {
		t.Fatalf("DecodeSubtreeAnnounce: %v", err)
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

func TestSubtreeAnnounce_WireLayout(t *testing.T) {
	a := makeSubtreeAnnounce()
	buf := make([]byte, SubtreeAnnounceSize)
	EncodeSubtreeAnnounce(a, buf)

	if buf[6] != MsgTypeSubtreeAnnounce {
		t.Errorf("buf[6] MsgType = 0x%02X, want 0x%02X", buf[6], MsgTypeSubtreeAnnounce)
	}
	if buf[7] != 0x00 {
		t.Errorf("buf[7] Flags = 0x%02X, want 0x00", buf[7])
	}
	if buf[62] != 0x00 || buf[63] != 0x00 {
		t.Errorf("reserved bytes [62:64] non-zero: 0x%02X 0x%02X", buf[62], buf[63])
	}
}

func TestSubtreeAnnounce_TTLZero(t *testing.T) {
	a := makeSubtreeAnnounce()
	a.TTL = 0
	buf := make([]byte, SubtreeAnnounceSize)
	EncodeSubtreeAnnounce(a, buf)
	got, err := DecodeSubtreeAnnounce(buf)
	if err != nil {
		t.Fatalf("DecodeSubtreeAnnounce: %v", err)
	}
	if got.TTL != 0 {
		t.Errorf("TTL = %d, want 0", got.TTL)
	}
}

func TestSubtreeAnnounce_BadMagic(t *testing.T) {
	a := makeSubtreeAnnounce()
	buf := make([]byte, SubtreeAnnounceSize)
	EncodeSubtreeAnnounce(a, buf)
	buf[0] = 0x00 // corrupt magic
	_, err := DecodeSubtreeAnnounce(buf)
	if err != ErrBadMagic {
		t.Errorf("want ErrBadMagic, got %v", err)
	}
}

func TestSubtreeAnnounce_TooShort(t *testing.T) {
	_, err := DecodeSubtreeAnnounce(make([]byte, SubtreeAnnounceSize-1))
	if err != ErrSubtreeAnnounceTooShort {
		t.Errorf("want ErrSubtreeAnnounceTooShort, got %v", err)
	}
}

func TestSubtreeAnnounce_EncodeBufTooSmall(t *testing.T) {
	a := makeSubtreeAnnounce()
	_, err := EncodeSubtreeAnnounce(a, make([]byte, SubtreeAnnounceSize-1))
	if err == nil {
		t.Error("want error for small buffer, got nil")
	}
}
