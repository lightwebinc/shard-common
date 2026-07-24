package objfmt

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/lightwebinc/shard-common/frame"
)

// beefObj is a minimal BEEF-family object: BRC-62 marker + arbitrary body.
// The codec never parses past the marker.
var beefObj = []byte{0x01, 0x00, 0xBE, 0xEF, 0xAA, 0xBB, 0xCC}

func TestBEEFVersionWordAndMarker(t *testing.T) {
	cases := []struct {
		name string
		obj  []byte
		word uint32
		isB  bool
	}{
		{"beef v1", []byte{0x01, 0x00, 0xBE, 0xEF}, BEEFMarkerV1, true},
		{"beef v2", []byte{0x02, 0x00, 0xBE, 0xEF}, BEEFMarkerV2, true},
		{"atomic", []byte{0x01, 0x01, 0x01, 0x01}, AtomicBEEFMarker, true},
		{"future beef version", []byte{0xFF, 0x00, 0xBE, 0xEF}, 0xEFBE00FF, true},
		{"low word zero not beef", []byte{0x00, 0x00, 0xBE, 0xEF}, 0xEFBE0000, false},
		{"raw tx version", []byte{0x01, 0x00, 0x00, 0x00}, 1, false},
		{"garbage", []byte{0xDE, 0xAD, 0xBE, 0xAA}, 0xAABEADDE, false},
	}
	for _, c := range cases {
		w, ok := BEEFVersionWord(c.obj)
		if !ok || w != c.word {
			t.Errorf("%s: BEEFVersionWord = %X/%v, want %X/true", c.name, w, ok, c.word)
		}
		if got := IsBEEFObject(c.obj); got != c.isB {
			t.Errorf("%s: IsBEEFObject = %v, want %v", c.name, got, c.isB)
		}
	}
	if _, ok := BEEFVersionWord([]byte{0x01}); ok {
		t.Error("BEEFVersionWord ok for 1-byte object")
	}
	if IsBEEFObject(nil) {
		t.Error("IsBEEFObject(nil) = true")
	}
}

// Vectors computed independently (sha256sum).
func TestTopicIDAndContentIDVectors(t *testing.T) {
	wantTopic, _ := hex.DecodeString("4bd434d6d645caec7ddb531c86d2ed2011e6b5f65929a9a82bc554ab5af5e0a5")
	got := TopicID("tm_uhrp_files")
	if !bytes.Equal(got[:], wantTopic) {
		t.Errorf("TopicID(tm_uhrp_files) = %x, want %x", got, wantTopic)
	}

	wantContent, _ := hex.DecodeString("9cd613e07509e7e15d79d4b44be791a546db73d6ae71e9cae64e9b246b725572")
	gotC := ContentID(beefObj)
	if !bytes.Equal(gotC[:], wantContent) {
		t.Errorf("ContentID = %x, want %x", gotC, wantContent)
	}
}

func TestBEEFRecordRoundTrip(t *testing.T) {
	topics := []string{"tm_uhrp_files", "tm_test_b"}
	rec, err := EncodeBEEFRecord(topics, beefObj)
	if err != nil {
		t.Fatalf("EncodeBEEFRecord: %v", err)
	}

	// The record leads with the 0xBEEF tag — grammar-distinct from a framed
	// datagram (0xE3) and a bare tx (byte[1] == 0x00).
	if rec[0] != 0xBE || rec[1] != 0xEF {
		t.Fatalf("record tag bytes = %02X %02X, want BE EF", rec[0], rec[1])
	}

	n, err := BEEFRecordSize(rec)
	if err != nil || n != len(rec) {
		t.Fatalf("BEEFRecordSize = %d/%v, want %d/nil", n, err, len(rec))
	}
	if sz, err := Size(ClassBEEF, rec); err != nil || sz != len(rec) {
		t.Fatalf("Size(ClassBEEF) = %d/%v, want %d/nil", sz, err, len(rec))
	}

	d, consumed, err := DecodeBEEFRecord(rec)
	if err != nil || consumed != len(rec) {
		t.Fatalf("DecodeBEEFRecord: %v (consumed %d)", err, consumed)
	}
	if len(d.Topics) != 2 || d.Topics[0] != topics[0] || d.Topics[1] != topics[1] {
		t.Errorf("topics = %v, want %v", d.Topics, topics)
	}
	if !bytes.Equal(d.Object, beefObj) {
		t.Errorf("object not verbatim")
	}
}

func TestBEEFRecordSizeShortAndMalformed(t *testing.T) {
	rec, _ := EncodeBEEFRecord([]string{"tm_a"}, beefObj)

	// Every strict prefix is ErrShort (valid-but-incomplete), never malformed.
	for i := 1; i < len(rec); i++ {
		if _, err := BEEFRecordSize(rec[:i]); !errors.Is(err, ErrShort) {
			t.Fatalf("prefix %d: err = %v, want ErrShort", i, err)
		}
	}

	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), rec...)
		f(b)
		return b
	}
	cases := []struct {
		name string
		buf  []byte
	}{
		{"bad tag", mut(func(b []byte) { b[0] = 0x01 })},
		{"bad record ver", mut(func(b []byte) { b[2] = 0x02 })},
		{"zero topics", mut(func(b []byte) { b[3] = 0 })},
		{"too many topics", mut(func(b []byte) { b[3] = BEEFMaxTopics + 1 })},
		{"zero topic len", mut(func(b []byte) { b[4] = 0 })},
		{"oversize topic len", mut(func(b []byte) { b[4] = BEEFMaxTopicLen + 1 })},
		{"zero object len", mut(func(b []byte) { copy(b[len(b)-len(beefObj)-4:], []byte{0, 0, 0, 0}) })},
	}
	for _, c := range cases {
		if _, err := BEEFRecordSize(c.buf); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", c.name, err)
		}
	}
}

func TestEncodeBEEFRecordValidation(t *testing.T) {
	if _, err := EncodeBEEFRecord(nil, beefObj); !errors.Is(err, ErrMalformed) {
		t.Error("no topics accepted")
	}
	if _, err := EncodeBEEFRecord([]string{"tm_a"}, nil); !errors.Is(err, ErrMalformed) {
		t.Error("empty object accepted")
	}
	if _, err := EncodeBEEFRecord([]string{""}, beefObj); !errors.Is(err, ErrMalformed) {
		t.Error("empty topic accepted")
	}
	if _, err := EncodeBEEFRecord([]string{string([]byte{0xFF, 0xFE})}, beefObj); !errors.Is(err, ErrMalformed) {
		t.Error("invalid UTF-8 topic accepted")
	}
}

func TestBEEFRecordReaderStream(t *testing.T) {
	r1, _ := EncodeBEEFRecord([]string{"tm_a"}, beefObj)
	r2, _ := EncodeBEEFRecord([]string{"tm_b", "tm_c"}, append(beefObj, 0xDD))
	stream := append(append([]byte(nil), r1...), r2...)

	rd := NewReader(bytes.NewReader(stream), ClassBEEF)
	o1, err := rd.Next()
	if err != nil || !bytes.Equal(o1, r1) {
		t.Fatalf("first record: %v", err)
	}
	o2, err := rd.Next()
	if err != nil || !bytes.Equal(o2, r2) {
		t.Fatalf("second record: %v", err)
	}
	if _, err := rd.Next(); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestBEEFDeliveryRoundTrip(t *testing.T) {
	topic := TopicID("tm_uhrp_files")
	rec := EncodeBEEFDelivery(topic, beefObj)

	n, err := BEEFDeliverySize(rec)
	if err != nil || n != len(rec) {
		t.Fatalf("BEEFDeliverySize = %d/%v", n, err)
	}
	gotTopic, obj, consumed, err := DecodeBEEFDelivery(rec)
	if err != nil || consumed != len(rec) {
		t.Fatalf("DecodeBEEFDelivery: %v", err)
	}
	if gotTopic != topic || !bytes.Equal(obj, beefObj) {
		t.Error("delivery record fields mismatch")
	}

	if _, err := BEEFDeliverySize(rec[:10]); !errors.Is(err, ErrShort) {
		t.Errorf("short: %v", err)
	}
}

func TestBEEFMulticastBytesAndStrip(t *testing.T) {
	topic := TopicID("tm_uhrp_files")
	mcast, err := BEEFMulticastBytes(topic, beefObj)
	if err != nil {
		t.Fatalf("BEEFMulticastBytes: %v", err)
	}
	if !frame.IsBEEFFrame(mcast) {
		t.Fatal("not a V9 frame")
	}

	bf, err := frame.DecodeBEEF(mcast)
	if err != nil {
		t.Fatalf("DecodeBEEF: %v", err)
	}
	if bf.TopicID != topic {
		t.Error("TopicID not carried")
	}
	if bf.ContentID != ContentID(beefObj) {
		t.Error("ContentID mismatch")
	}
	if bf.HashKey != 0 || bf.SeqNum != 0 {
		t.Error("frame not unstamped")
	}

	// Strip round-trip: StripBytes(ClassBEEF, wrap(obj)) == obj.
	stripped, err := StripBytes(ClassBEEF, mcast)
	if err != nil || !bytes.Equal(stripped, beefObj) {
		t.Fatalf("StripBytes round-trip failed: %v", err)
	}
}
