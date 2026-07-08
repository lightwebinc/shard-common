package objfmt

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lightwebinc/shard-common/frame"
)

func TestStripTxRoundTrip(t *testing.T) {
	for _, tx := range [][]byte{
		buildTx(t, 107, 25),
		buildEF(t, buildTx(t, 107, 25), 25),
		buildTx(t, 0, 0),
	} {
		raw, err := MulticastBytes(ClassTx, tx)
		if err != nil {
			t.Fatal(err)
		}
		got, err := StripBytes(ClassTx, raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, tx) {
			t.Fatal("tx strip round-trip mismatch")
		}
	}
}

func TestStripSubtreeRoundTrip(t *testing.T) {
	for _, count := range []int{1, 4, 33} {
		st := buildSubtree(t, count)
		raw, err := MulticastBytes(ClassSubtree, st)
		if err != nil {
			t.Fatal(err)
		}
		got, err := StripBytes(ClassSubtree, raw)
		if err != nil {
			t.Fatalf("count %d: %v", count, err)
		}
		if !bytes.Equal(got, st) {
			t.Fatalf("count %d: subtree strip round-trip mismatch", count)
		}
	}
}

func TestStripBlockRoundTrip(t *testing.T) {
	for _, rb := range [][2]int{{0, 0}, {2, 32}, {3, 40}} {
		blk := buildBlock(t, rb[0], rb[1])
		raw, err := MulticastBytes(ClassBlock, blk)
		if err != nil {
			t.Fatal(err)
		}
		got, err := StripBytes(ClassBlock, raw)
		if err != nil {
			t.Fatalf("%v: %v", rb, err)
		}
		if !bytes.Equal(got, blk) {
			t.Fatalf("%v: block strip round-trip mismatch", rb)
		}
	}
}

func TestStripBlockRejectsNonBlock(t *testing.T) {
	// A BRC-131 frame whose payload is not a whole BRC-144 body (here a plain
	// tx, standing in for a lossy native BlockAnnounce) is not deliverable.
	bf := &frame.BlockFrame{MsgType: frame.BlockMsgAnnounce, Payload: buildTx(t, 20, 25)}
	buf := make([]byte, frame.HeaderSize+len(bf.Payload))
	n, err := frame.EncodeBlock(bf, buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StripBytes(ClassBlock, buf[:n]); !errors.Is(err, ErrNotStrippable) {
		t.Fatalf("err = %v, want ErrNotStrippable", err)
	}
}

func TestStripBadInput(t *testing.T) {
	// Garbage / bad magic surfaces the frame decode error, never a panic.
	if _, err := StripBytes(ClassSubtree, []byte{0x01, 0x02, 0x03}); err == nil {
		t.Fatal("want error on garbage subtree frame")
	}
	if _, err := StripBytes(ClassBlock, bytes.Repeat([]byte{0x00}, 92)); err == nil {
		t.Fatal("want error on bad-magic block frame")
	}
}
