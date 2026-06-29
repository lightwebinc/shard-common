package bundle

import (
	"bytes"
	"testing"

	"github.com/lightwebinc/shard-common/frame"
	"github.com/lightwebinc/shard-common/shard"
)

const shardBits = 4

func engine() *shard.Engine { return shard.New(0xFF05, shard.DefaultGroupID, shardBits) }

// mkFrame builds a BRC-124 frame whose group is set by topNibble (top 4 bits of
// TxID, since shardBits=4) and whose subtree is set by subByte. seq makes the
// TxID unique so decoalesced frames can be matched to originals.
func mkFrame(topNibble, subByte, seq byte, payload []byte) *frame.Frame {
	f := &frame.Frame{Version: frame.FrameVerV2, Payload: payload}
	f.TxID[0] = topNibble << 4
	f.TxID[1] = subByte
	f.TxID[2] = seq
	f.SubtreeID[0] = subByte
	return f
}

func TestCoalesceDecoalesceRoundTrip(t *testing.T) {
	eng := engine()
	var sender [16]byte
	c := NewCoalescer(eng, 9000, 1000, true /*carryTxID*/)

	var in []*frame.Frame
	want := make(map[[32]byte][]byte)
	seq := byte(0)
	for _, g := range []byte{1, 2} {
		for _, s := range []byte{0xA, 0xB} {
			for k := 0; k < 5; k++ {
				seq++
				p := stdTx(30+k, byte(g*16+s))
				f := mkFrame(g, s, seq, p)
				in = append(in, f)
				want[f.TxID] = p
			}
		}
	}

	bundles := c.Coalesce(sender, in)

	flowSeq := make(map[[2]byte]uint64)
	for _, b := range bundles {
		key := [2]byte{byte(b.GroupIdx), b.SubtreeID[0]}
		flowSeq[key]++
		if b.SeqNum != flowSeq[key] {
			t.Errorf("flow %v: SeqNum %d, want %d", key, b.SeqNum, flowSeq[key])
		}
		for _, m := range b.Members {
			if uint16(eng.GroupIndex(&m.TxID)) != b.GroupIdx {
				t.Errorf("member group != bundle group %d", b.GroupIdx)
			}
			if m.TxID[1] != b.SubtreeID[0] {
				t.Errorf("member subtree != bundle subtree")
			}
		}
	}

	got := make(map[[32]byte][]byte)
	for _, b := range bundles {
		for _, f := range Decoalesce(b) {
			got[f.TxID] = f.Payload
		}
	}
	if len(got) != len(want) {
		t.Fatalf("recovered %d txs, want %d", len(got), len(want))
	}
	for id, p := range want {
		if !bytes.Equal(got[id], p) {
			t.Errorf("tx %x payload mismatch", id[:4])
		}
	}
}

func TestSubtreeSeparation(t *testing.T) {
	c := NewCoalescer(engine(), 9000, 1000, true)
	in := []*frame.Frame{
		mkFrame(1, 0xA, 1, stdTx(20, 1)),
		mkFrame(1, 0xB, 2, stdTx(20, 2)), // same group, different subtree
		mkFrame(1, 0xA, 3, stdTx(20, 3)),
	}
	if got := len(c.Coalesce([16]byte{}, in)); got != 2 {
		t.Fatalf("got %d bundles, want 2 (one per subtree)", got)
	}
}

func TestSizeBound(t *testing.T) {
	memberSize := 100
	maxBytes := HeaderSize + 2*(MemberOverhead(false)+memberSize) + 10
	c := NewCoalescer(engine(), maxBytes, 1000, false)

	var in []*frame.Frame
	for k := 0; k < 7; k++ {
		in = append(in, mkFrame(3, 0xC, byte(k), stdTx(memberSize, byte(k))))
	}
	bundles := c.Coalesce([16]byte{}, in)
	if len(bundles) < 3 {
		t.Fatalf("expected ≥3 bundles from size splitting, got %d", len(bundles))
	}
	total := 0
	for _, b := range bundles {
		buf, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if len(buf) > maxBytes {
			t.Errorf("bundle %d bytes exceeds maxBytes %d", len(buf), maxBytes)
		}
		total += len(b.Members)
	}
	if total != len(in) {
		t.Errorf("packed %d members, want %d", total, len(in))
	}
}

func TestRecomputeTxIDPath(t *testing.T) {
	// carryTxID=false: decoalesce recomputes the TxID, which matches the
	// original only when the frame's TxID is the real double-SHA256.
	c := NewCoalescer(engine(), 9000, 1000, false)
	p := stdTx(64, 0x5A)
	f := &frame.Frame{Version: frame.FrameVerV2, Payload: p, TxID: TxID(p)}

	bundles := c.Coalesce([16]byte{}, []*frame.Frame{f})
	out := Decoalesce(bundles[0])
	if len(out) != 1 {
		t.Fatalf("got %d frames", len(out))
	}
	if out[0].TxID != f.TxID {
		t.Errorf("recomputed TxID %x != original %x", out[0].TxID[:4], f.TxID[:4])
	}
	if !bytes.Equal(out[0].Payload, p) {
		t.Error("payload mismatch")
	}
}

func TestEFRoundTripThroughCoalesce(t *testing.T) {
	c := NewCoalescer(engine(), 9000, 1000, true)
	in := []*frame.Frame{
		mkFrame(2, 0xD, 1, efTx("alpha")),
		mkFrame(2, 0xD, 2, stdTx(30, 0x33)),
		mkFrame(2, 0xD, 3, efTx("beta")),
	}
	var ef, std int
	for _, b := range c.Coalesce([16]byte{}, in) {
		for _, f := range Decoalesce(b) {
			if frame.IsEF(f.Payload) {
				ef++
			} else {
				std++
			}
		}
	}
	if ef != 2 || std != 1 {
		t.Errorf("EF=%d std=%d, want EF=2 std=1", ef, std)
	}
}

// TestRebucketSplitsToChildGroups: a bundle built at shardBits=4 (parent group 1)
// whose members span the two shardBits=5 children (groups 2 and 3) must
// re-bucket into exactly those two child-group bundles.
func TestRebucketSplitsToChildGroups(t *testing.T) {
	eng5 := shard.New(0xFF05, shard.DefaultGroupID, 5)

	src := &Bundle{
		Flags:     FlagTxIDsPresent,
		GroupIdx:  1,
		ShardBits: 4,
		SubtreeID: [32]byte{0xAA, 0xBB},
	}
	mk := func(top, seq byte) Member {
		var id [32]byte
		id[0] = top // top4 (>>4)=1 at sb4; top5 (>>3) selects the child at sb5
		id[1] = seq
		return Member{TxID: id, Tx: stdTx(50, seq)}
	}
	// 0x10>>3 = 2 (child 2); 0x18>>3 = 3 (child 3); both 0x..>>4 = 1 (parent 1)
	src.Members = []Member{mk(0x10, 1), mk(0x18, 2), mk(0x10, 3), mk(0x18, 4)}

	rb := NewRebucketer(eng5, 9000, 1000, true)
	out := rb.Rebucket([16]byte{}, src)
	if len(out) != 2 {
		t.Fatalf("got %d bundles, want 2 child groups", len(out))
	}
	total := 0
	seen := map[uint16]bool{}
	for _, b := range out {
		if b.ShardBits != 5 {
			t.Errorf("bundle shardBits %d, want 5", b.ShardBits)
		}
		if b.SubtreeID != src.SubtreeID {
			t.Error("subtree not preserved")
		}
		seen[b.GroupIdx] = true
		for _, m := range b.Members {
			if uint16(eng5.GroupIndex(&m.TxID)) != b.GroupIdx {
				t.Errorf("member routed to wrong child group %d", b.GroupIdx)
			}
		}
		total += len(b.Members)
	}
	if total != 4 {
		t.Errorf("members conserved: got %d, want 4", total)
	}
	if !seen[2] || !seen[3] {
		t.Errorf("expected child groups {2,3}, saw %v", seen)
	}
}
