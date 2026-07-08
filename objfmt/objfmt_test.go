package objfmt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/lightwebinc/shard-common/frame"
)

// buildTx hand-assembles a minimal standard transaction with the given
// unlocking/locking script lengths.
func buildTx(t *testing.T, inScript, outScript int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{0x01, 0x00, 0x00, 0x00}) // version 1
	b.WriteByte(0x01)                       // in count
	b.Write(make([]byte, 32))               // prev txid
	b.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF}) // prev index
	writeVarInt(&b, uint64(inScript))
	b.Write(bytes.Repeat([]byte{0xAB}, inScript))
	b.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF})                         // sequence
	b.WriteByte(0x01)                                               // out count
	b.Write([]byte{0x40, 0x42, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00}) // value
	writeVarInt(&b, uint64(outScript))
	b.Write(bytes.Repeat([]byte{0xCD}, outScript))
	b.Write([]byte{0x00, 0x00, 0x00, 0x00}) // locktime
	return b.Bytes()
}

// buildEF converts a 1-in standard tx from buildTx into its BRC-30 EF form
// with the given spent locking-script length.
func buildEF(t *testing.T, std []byte, spentScript int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(std[:4])
	b.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0xEF})
	// input vector: count + input fields up to and including sequence
	inEnd := 4 + 1 + 36
	sLen, n, err := varInt(std, inEnd)
	if err != nil {
		t.Fatal(err)
	}
	inEnd += n + int(sLen) + 4
	b.Write(std[4:inEnd])
	// EF extension: spent value + locking script
	b.Write([]byte{0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	writeVarInt(&b, uint64(spentScript))
	b.Write(bytes.Repeat([]byte{0xEE}, spentScript))
	// outputs + locktime verbatim
	b.Write(std[inEnd:])
	return b.Bytes()
}

func writeVarInt(b *bytes.Buffer, v uint64) {
	switch {
	case v < 0xFD:
		b.WriteByte(byte(v))
	case v <= 0xFFFF:
		b.WriteByte(0xFD)
		var w [2]byte
		binary.LittleEndian.PutUint16(w[:], uint16(v))
		b.Write(w[:])
	case v <= 0xFFFFFFFF:
		b.WriteByte(0xFE)
		var w [4]byte
		binary.LittleEndian.PutUint32(w[:], uint32(v))
		b.Write(w[:])
	default:
		b.WriteByte(0xFF)
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], v)
		b.Write(w[:])
	}
}

func TestTxSizeStandard(t *testing.T) {
	for _, scripts := range [][2]int{{0, 0}, {1, 1}, {107, 25}, {300, 300}, {70000, 3}} {
		tx := buildTx(t, scripts[0], scripts[1])
		n, err := TxSize(tx)
		if err != nil {
			t.Fatalf("scripts %v: %v", scripts, err)
		}
		if n != len(tx) {
			t.Fatalf("scripts %v: size %d, want %d", scripts, n, len(tx))
		}
	}
}

func TestTxSizeEF(t *testing.T) {
	std := buildTx(t, 107, 25)
	ef := buildEF(t, std, 25)
	if !IsEF(ef) {
		t.Fatal("IsEF(ef) = false")
	}
	if IsEF(std) {
		t.Fatal("IsEF(std) = true")
	}
	n, err := TxSize(ef)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(ef) {
		t.Fatalf("size %d, want %d", n, len(ef))
	}
}

func TestTxSizeShortAndTrailing(t *testing.T) {
	tx := buildTx(t, 50, 50)
	for cut := 1; cut < len(tx); cut++ {
		if _, err := TxSize(tx[:cut]); !errors.Is(err, ErrShort) && !errors.Is(err, ErrMalformed) {
			t.Fatalf("cut %d: err = %v, want ErrShort", cut, err)
		}
	}
	// Every prefix of a valid tx must be Short, never Malformed.
	for cut := 1; cut < len(tx); cut++ {
		if _, err := TxSize(tx[:cut]); errors.Is(err, ErrMalformed) {
			t.Fatalf("cut %d: valid prefix reported malformed", cut)
		}
	}
	// Trailing bytes are not consumed.
	n, err := TxSize(append(append([]byte{}, tx...), 0xAA, 0xBB))
	if err != nil || n != len(tx) {
		t.Fatalf("trailing: n=%d err=%v, want %d nil", n, err, len(tx))
	}
}

func TestTxSizeMalformed(t *testing.T) {
	tx := buildTx(t, 5, 5)
	zeroIn := append([]byte{}, tx...)
	zeroIn[4] = 0x00 // zero input count → EF-marker-or-malformed path
	zeroIn = append(zeroIn, 0x01)
	if _, err := TxSize(zeroIn[:11]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("zero inputs: %v, want ErrMalformed", err)
	}
}

func TestCoinbaseParses(t *testing.T) {
	// A coinbase is structurally a tx whose single input has a null
	// prevout; the walker must handle it like any other tx.
	cb := buildTx(t, 12, 25)
	n, err := TxSize(cb)
	if err != nil || n != len(cb) {
		t.Fatalf("coinbase: n=%d err=%v", n, err)
	}
}

func TestTxIDStandardVsEF(t *testing.T) {
	std := buildTx(t, 107, 25)
	ef := buildEF(t, std, 25)

	idStd, err := TxID(std)
	if err != nil {
		t.Fatal(err)
	}
	idEF, err := TxID(ef)
	if err != nil {
		t.Fatal(err)
	}
	if idStd != idEF {
		t.Fatal("TxID(EF) != TxID(standard) — EF extras must be excluded")
	}

	first := sha256.Sum256(std)
	want := sha256.Sum256(first[:])
	if idStd != want {
		t.Fatal("TxID != SHA256d(standard serialization)")
	}

	back, err := ToStandard(ef)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, std) {
		t.Fatal("ToStandard(EF) != original standard bytes")
	}
}

// fragmentedReader yields the stream in fixed-size chunks to exercise
// object boundaries split across reads.
type fragmentedReader struct {
	data  []byte
	chunk int
}

func (f *fragmentedReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		return 0, io.EOF
	}
	n := f.chunk
	if n > len(f.data) {
		n = len(f.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, f.data[:n])
	f.data = f.data[n:]
	return n, nil
}

func TestReaderSplitsBackToBackTxs(t *testing.T) {
	txs := [][]byte{
		buildTx(t, 0, 1),
		buildEF(t, buildTx(t, 107, 25), 25),
		buildTx(t, 300, 3),
		buildTx(t, 1, 70000),
	}
	var stream []byte
	for _, tx := range txs {
		stream = append(stream, tx...)
	}

	for _, chunk := range []int{1, 3, 4096, len(stream)} {
		rd := NewReader(&fragmentedReader{data: stream, chunk: chunk}, ClassTx)
		for i, want := range txs {
			got, err := rd.Next()
			if err != nil {
				t.Fatalf("chunk %d tx %d: %v", chunk, i, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("chunk %d tx %d: bytes differ", chunk, i)
			}
		}
		if _, err := rd.Next(); err != io.EOF {
			t.Fatalf("chunk %d: tail err = %v, want io.EOF", chunk, err)
		}
	}
}

func TestReaderMidObjectEOF(t *testing.T) {
	tx := buildTx(t, 50, 50)
	rd := NewReader(bytes.NewReader(tx[:len(tx)-3]), ClassTx)
	if _, err := rd.Next(); err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReaderObjectTooLarge(t *testing.T) {
	tx := buildTx(t, 8192, 8192)
	rd := NewReader(bytes.NewReader(tx), ClassTx)
	rd.SetMaxObject(1024)
	if _, err := rd.Next(); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("err = %v, want ErrObjectTooLarge", err)
	}
}

func TestClassDispatch(t *testing.T) {
	// Subtree and block are registered: a short buffer is ErrShort (need more),
	// not ErrClassNotRegistered.
	if _, err := Size(ClassSubtree, []byte{0}); !errors.Is(err, ErrShort) {
		t.Fatalf("subtree short: %v, want ErrShort", err)
	}
	if _, err := Size(ClassBlock, []byte{0}); !errors.Is(err, ErrShort) {
		t.Fatalf("block short: %v, want ErrShort", err)
	}
	// MulticastFrame has no frame.Frame form for subtree/block.
	if _, err := MulticastFrame(ClassSubtree, []byte{0}); !errors.Is(err, ErrClassNotRegistered) {
		t.Fatalf("MulticastFrame subtree: %v, want ErrClassNotRegistered", err)
	}
	if ClassTx.String() != "tx" || ClassSubtree.String() != "subtree" || ClassBlock.String() != "block" {
		t.Fatal("Class.String labels wrong")
	}
}

// buildSubtree assembles a BRC-143 subtree push frame: 32B root + uint64 count
// + count×32 hashes. The first node is the 0xFF×32 coinbase placeholder.
func buildSubtree(t *testing.T, count int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0x11}, 32)) // merkle root
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(count))
	b.Write(c[:])
	for i := 0; i < count; i++ {
		if i == 0 {
			b.Write(bytes.Repeat([]byte{0xFF}, 32)) // coinbase placeholder
		} else {
			b.Write(bytes.Repeat([]byte{byte(i)}, 32))
		}
	}
	return b.Bytes()
}

// buildBlock assembles a BRC-144 block push frame with the given subtree-root
// count, an inline coinbase, and a BUMP of bumpLen bytes.
func buildBlock(t *testing.T, roots, bumpLen int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write(bytes.Repeat([]byte{0x22}, frame.BlockHeaderSize)) // 80B header
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], 7) // TransactionCount
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], 4096) // SizeInBytes
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], uint64(roots)) // SubtreeCount
	b.Write(u[:])
	for i := 0; i < roots; i++ {
		b.Write(bytes.Repeat([]byte{byte(0x30 + i)}, 32))
	}
	b.Write(buildTx(t, 20, 25))              // inline coinbase (a plain tx shape)
	binary.BigEndian.PutUint64(u[:], 800001) // Height
	b.Write(u[:])
	binary.BigEndian.PutUint64(u[:], uint64(bumpLen)) // CoinbaseBUMPLen
	b.Write(u[:])
	b.Write(bytes.Repeat([]byte{0x74}, bumpLen)) // BUMP
	return b.Bytes()
}

func TestSubtreeSize(t *testing.T) {
	st := buildSubtree(t, 5)
	n, err := SubtreeSize(st)
	if err != nil || n != len(st) {
		t.Fatalf("SubtreeSize=%d,%v want %d", n, err, len(st))
	}
	// Short header and short body both report ErrShort.
	if _, err := SubtreeSize(st[:20]); !errors.Is(err, ErrShort) {
		t.Fatalf("short header: %v want ErrShort", err)
	}
	if _, err := SubtreeSize(st[:len(st)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("short body: %v want ErrShort", err)
	}
	// Trailing bytes: Size reports only the first object's length.
	n, err = SubtreeSize(append(append([]byte{}, st...), 0xAA))
	if err != nil || n != len(st) {
		t.Fatalf("trailing: %d,%v want %d", n, err, len(st))
	}
}

func TestBlockSize(t *testing.T) {
	blk := buildBlock(t, 3, 40)
	n, err := BlockSize(blk)
	if err != nil || n != len(blk) {
		t.Fatalf("BlockSize=%d,%v want %d", n, err, len(blk))
	}
	// Zero-BUMP block.
	blk0 := buildBlock(t, 0, 0)
	if n, err := BlockSize(blk0); err != nil || n != len(blk0) {
		t.Fatalf("BlockSize zero=%d,%v want %d", n, err, len(blk0))
	}
	// Truncated mid-coinbase and mid-BUMP report ErrShort.
	if _, err := BlockSize(blk[:len(blk)-1]); !errors.Is(err, ErrShort) {
		t.Fatalf("short BUMP: %v want ErrShort", err)
	}
	if _, err := BlockSize(blk[:BlockPrefixSize+3*32+4]); !errors.Is(err, ErrShort) {
		t.Fatalf("short coinbase: %v want ErrShort", err)
	}
}

func TestSubtreeMulticastRoundTrip(t *testing.T) {
	st := buildSubtree(t, 4)
	raw, err := MulticastBytes(ClassSubtree, st)
	if err != nil {
		t.Fatal(err)
	}
	if raw[6] != frame.FrameVerV5 {
		t.Fatalf("FrameVer=0x%02x want subtree 0x05", raw[6])
	}
	sf, err := frame.DecodeSubtreeData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sf.HashKey != 0 || sf.SeqNum != 0 {
		t.Fatal("frame must be unstamped")
	}
	var wantRoot [32]byte
	copy(wantRoot[:], st[0:32])
	if sf.SubtreeID != wantRoot {
		t.Fatal("SubtreeID != in-band merkle root")
	}
	p, err := frame.DecodeSubtreeDataPayload(sf.Payload, frame.SubtreeMsgHashesOnly)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Nodes) != 4 {
		t.Fatalf("nodes=%d want 4", len(p.Nodes))
	}
	// Placeholder preserved by value at node 0.
	var ph [32]byte
	for i := range ph {
		ph[i] = 0xFF
	}
	if p.Nodes[0].TxHash != ph {
		t.Fatal("coinbase placeholder not preserved at node 0")
	}
}

func TestBlockMulticastCarriesBodyVerbatim(t *testing.T) {
	blk := buildBlock(t, 2, 32)
	raw, err := MulticastBytes(ClassBlock, blk)
	if err != nil {
		t.Fatal(err)
	}
	if raw[6] != frame.FrameVerV4 {
		t.Fatalf("FrameVer=0x%02x want block 0x04", raw[6])
	}
	bf, err := frame.DecodeBlock(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bf.MsgType != frame.BlockMsgAnnounce {
		t.Fatalf("MsgType=0x%02x want announce", bf.MsgType)
	}
	if bf.HashKey != 0 || bf.SeqNum != 0 {
		t.Fatal("frame must be unstamped")
	}
	// The payload is the BRC-144 body byte-for-byte (verbatim, no projection).
	if !bytes.Equal(bf.Payload, blk) {
		t.Fatal("block payload is not the verbatim BRC-144 body")
	}
	// ContentID is SHA256d of the 80-byte header.
	first := sha256.Sum256(blk[:frame.BlockHeaderSize])
	want := sha256.Sum256(first[:])
	if bf.ContentID != want {
		t.Fatal("ContentID != SHA256d(header)")
	}
}

func TestReaderSplitsSubtreesAndBlocks(t *testing.T) {
	st1, st2 := buildSubtree(t, 3), buildSubtree(t, 6)
	rd := NewReader(bytes.NewReader(append(append([]byte{}, st1...), st2...)), ClassSubtree)
	for i, want := range [][]byte{st1, st2} {
		got, err := rd.Next()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("subtree %d: err=%v equal=%v", i, err, bytes.Equal(got, want))
		}
	}
	if _, err := rd.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}

	b1, b2 := buildBlock(t, 1, 16), buildBlock(t, 0, 0)
	rb := NewReader(bytes.NewReader(append(append([]byte{}, b1...), b2...)), ClassBlock)
	for i, want := range [][]byte{b1, b2} {
		got, err := rb.Next()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("block %d: err=%v equal=%v", i, err, bytes.Equal(got, want))
		}
	}
	if _, err := rb.Next(); err != io.EOF {
		t.Fatalf("want EOF, got %v", err)
	}
}

func TestMulticastFrameRoundTrip(t *testing.T) {
	tx := buildEF(t, buildTx(t, 107, 25), 25)
	f, err := MulticastFrame(ClassTx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if f.HashKey != 0 || f.SeqNum != 0 {
		t.Fatal("frame must be unstamped")
	}
	wantID, _ := TxID(tx)
	if f.TxID != wantID {
		t.Fatal("frame TxID mismatch")
	}

	buf := make([]byte, frame.HeaderSize+len(tx))
	n, err := frame.Encode(f, buf)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := frame.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Payload, tx) {
		t.Fatal("decoded payload differs from submitted object")
	}
	if dec.TxID != wantID {
		t.Fatal("decoded TxID differs")
	}
}
