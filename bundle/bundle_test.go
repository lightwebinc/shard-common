package bundle

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lightwebinc/shard-common/frame"
)

// stdTx returns a non-EF payload of length n with a recognisable fill byte.
func stdTx(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

// efTx returns a BRC-30 Extended Format payload (4B version + 6B marker + body).
func efTx(body string) []byte {
	p := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEF}
	return append(p, []byte(body)...)
}

func sample(withTxID bool) *Bundle {
	b := &Bundle{
		SubtreeID: [32]byte{0xAB, 0xCD},
		HashKey:   0x1122334455667788,
		SeqNum:    7,
		GroupIdx:  5,
		ShardBits: 4,
		Members: []Member{
			{Tx: stdTx(20, 0x11)},
			{Tx: efTx("hello-ef")},
			{Tx: stdTx(40, 0x22)},
		},
	}
	if withTxID {
		b.Flags |= FlagTxIDsPresent
		for i := range b.Members {
			b.Members[i].TxID = [32]byte{byte(i + 1)}
		}
	}
	return b
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, withTxID := range []bool{false, true} {
		in := sample(withTxID)
		buf, err := in.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		out, err := Decode(buf)
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if out.Flags != in.Flags || out.HashKey != in.HashKey || out.SeqNum != in.SeqNum ||
			out.GroupIdx != in.GroupIdx || out.ShardBits != in.ShardBits || out.SubtreeID != in.SubtreeID {
			t.Fatalf("header mismatch (withTxID=%v): %+v vs %+v", withTxID, out, in)
		}
		if len(out.Members) != len(in.Members) {
			t.Fatalf("member count %d != %d", len(out.Members), len(in.Members))
		}
		for i := range in.Members {
			if !bytes.Equal(out.Members[i].Tx, in.Members[i].Tx) {
				t.Errorf("member %d tx mismatch", i)
			}
			if withTxID && out.Members[i].TxID != in.Members[i].TxID {
				t.Errorf("member %d txid mismatch", i)
			}
		}
	}
}

func TestEFMarkerPreserved(t *testing.T) {
	in := sample(false)
	buf, _ := in.Encode()
	out, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if frame.IsEF(out.Members[0].Tx) {
		t.Error("member 0 should not be EF")
	}
	if !frame.IsEF(out.Members[1].Tx) {
		t.Error("member 1 should be EF (marker lost through codec)")
	}
}

func TestDecodeRejectsViaFrame(t *testing.T) {
	// frame.Decode must hand bundles off rather than mis-parse them.
	buf, _ := sample(true).Encode()
	if !frame.IsBundle(buf) {
		t.Error("frame.IsBundle should recognise a bundle datagram")
	}
	if _, err := frame.Decode(buf); !errors.Is(err, frame.ErrBadVer) {
		t.Errorf("frame.Decode(bundle) = %v, want ErrBadVer", err)
	}
}

func TestDecodeErrors(t *testing.T) {
	good, _ := sample(true).Encode()

	if _, err := Decode(good[:HeaderSize-1]); !errors.Is(err, ErrTooShort) {
		t.Errorf("short: got %v", err)
	}
	bad := append([]byte(nil), good...)
	bad[0] ^= 0xFF
	if _, err := Decode(bad); !errors.Is(err, ErrBadMagic) {
		t.Errorf("magic: got %v", err)
	}
	ver := append([]byte(nil), good...)
	ver[6] = frame.FrameVerV2
	if _, err := Decode(ver); !errors.Is(err, ErrBadVer) {
		t.Errorf("ver: got %v", err)
	}
	if _, err := Decode(good[:len(good)-3]); !errors.Is(err, ErrTruncated) {
		t.Errorf("truncated: got %v", err)
	}
}

func TestMemberTooBig(t *testing.T) {
	b := &Bundle{Members: []Member{{Tx: make([]byte, MaxMemberTx+1)}}}
	if _, err := b.Encode(); !errors.Is(err, ErrMemberBig) {
		t.Errorf("got %v, want ErrMemberBig", err)
	}
}
