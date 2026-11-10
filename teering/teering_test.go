package teering

import (
	"bytes"
	"errors"
	"math/rand"
	"path/filepath"
	"testing"
)

func TestRoundTripAndWrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	r := rand.New(rand.NewSource(1))
	buf := make([]byte, MaxDatagram)
	var sent, got int
	// Many times the capacity, in records of mixed sizes, so the end of the
	// region is crossed in every alignment; the consumer keeps up in lockstep
	// and in bursts.
	for round := 0; round < 40; round++ {
		var want [][]byte
		for i := 0; i < 200; i++ {
			n := 1 + r.Intn(9000)
			b := make([]byte, n)
			r.Read(b)
			if err := p.Write(b); err != nil {
				if errors.Is(err, ErrNoRoom) {
					break
				}
				t.Fatal(err)
			}
			want = append(want, b)
			sent++
		}
		for _, w := range want {
			n := c.Next(buf)
			if n == 0 {
				t.Fatalf("round %d: ring empty with %d records to read", round, len(want))
			}
			if !bytes.Equal(buf[:n], w) {
				t.Fatalf("round %d: record differs (%d vs %d bytes)", round, n, len(w))
			}
			got++
		}
		if n := c.Next(buf); n != 0 {
			t.Fatalf("round %d: extra record of %d bytes", round, n)
		}
	}
	if got != sent || sent < 1000 {
		t.Fatalf("sent %d, got %d", sent, got)
	}
	if c.Lost() != 0 || p.Dropped() != 0 {
		t.Fatalf("lost %d dropped %d", c.Lost(), p.Dropped())
	}
}

func TestNoRoomDrops(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	b := make([]byte, 60000)
	var ok int
	for i := 0; i < 100; i++ {
		if err := p.Write(b); err == nil {
			ok++
		}
	}
	if ok < 16 || ok > 17 || p.Dropped() != uint64(100-ok) {
		t.Fatalf("wrote %d, dropped %d", ok, p.Dropped())
	}
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, MaxDatagram)
	for i := 0; i < ok; i++ {
		if c.Next(buf) != 60000 {
			t.Fatalf("record %d missing", i)
		}
	}
	if err := p.Write(b); err != nil {
		t.Fatalf("room after a drain: %v", err)
	}
	if c.Next(buf) != 60000 {
		t.Fatal("the record after the drain is missing")
	}
}

func TestProducerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_ = p.Write([]byte("old"))
	}
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	buf := make([]byte, 64)
	if c.Next(buf) != 3 {
		t.Fatal("first old record")
	}
	_ = p.Close()
	p2, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p2.Close() }()
	_ = p2.Write([]byte("new!"))
	_ = p2.Write([]byte("new!"))
	// The same file, reset in place: the consumer's mapping stays valid, it
	// sees the new generation, drops what it had not read and continues at
	// the producer's head (the record written before it noticed is gone).
	if n := c.Next(buf); n != 0 {
		t.Fatalf("after the restart the consumer gave %d bytes", n)
	}
	if c.Lost() != 1 {
		t.Fatalf("lost %d, want 1", c.Lost())
	}
	_ = p2.Write([]byte("again"))
	if n := c.Next(buf); n != 5 || string(buf[:5]) != "again" {
		t.Fatalf("new generation gave %d %q", n, buf[:n])
	}
}

// TestPeekAdvance reads through views: Peek is stable until Advance, the
// producer cannot reuse a peeked record, and a view's bytes are the
// datagram's across the region's end.
func TestPeekAdvance(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.Peek() != nil {
		t.Fatal("Peek on an empty ring")
	}
	c.Advance() // no pending Peek: nothing happens
	r := rand.New(rand.NewSource(2))
	for round := 0; round < 400; round++ {
		var want [][]byte
		for i := 0; i < 20; i++ {
			b := make([]byte, 1+r.Intn(9000))
			r.Read(b)
			if err := p.Write(b); err != nil {
				t.Fatal(err)
			}
			want = append(want, b)
		}
		for i, w := range want {
			v := c.Peek()
			if !bytes.Equal(v, w) {
				t.Fatalf("round %d datagram %d: view of %d bytes, want %d", round, i, len(v), len(w))
			}
			if v2 := c.Peek(); len(v2) != len(v) || &v2[0] != &v[0] {
				t.Fatalf("round %d datagram %d: second Peek moved", round, i)
			}
			if cap(v) != len(v) {
				t.Fatalf("view capacity %d past its length %d", cap(v), len(v))
			}
			c.Advance()
		}
		if c.Peek() != nil {
			t.Fatalf("round %d: extra datagram", round)
		}
	}
	// A peeked record is not released: a full ring refuses the producer
	// until Advance.
	big := make([]byte, 60000)
	for p.Write(big) == nil {
	}
	if c.Peek() == nil {
		t.Fatal("full ring peeks nothing")
	}
	if err := p.Write(big); !errors.Is(err, ErrNoRoom) {
		t.Fatalf("write into a full ring with a peeked record: %v", err)
	}
	c.Advance()
	if err := p.Write(big); err != nil {
		t.Fatalf("write after Advance: %v", err)
	}
	if c.Lost() != 0 {
		t.Fatalf("lost %d", c.Lost())
	}
}

// TestRestartWithStaleTail is the restart a consumer loses the race with: it
// releases a datagram of the old generation after the producer reset the
// counters, leaving a tail past the new head. The producer has no room until
// the consumer's next read resets to the new generation; then both resume.
func TestRestartWithStaleTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for range 4 {
		if err := p.Write(make([]byte, 1000)); err != nil {
			t.Fatal(err)
		}
	}
	if c.Peek() == nil {
		t.Fatal("no datagram")
	}
	_ = p.Close()
	p2, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p2.Close() }()
	c.Advance() // the old generation's release, after the reset
	if err := p2.Write([]byte("early")); err != ErrNoRoom {
		t.Fatalf("write before the consumer's reset: %v, want ErrNoRoom", err)
	}
	if v := c.Peek(); v != nil {
		t.Fatalf("read %d bytes of the old generation", len(v))
	}
	want := []byte("after the restart")
	if err := p2.Write(want); err != nil {
		t.Fatalf("write after the consumer's reset: %v", err)
	}
	buf := make([]byte, 64)
	if n := c.Next(buf); string(buf[:n]) != string(want) {
		t.Fatalf("got %q", buf[:n])
	}
	if c.Next(buf) != 0 {
		t.Fatal("extra datagram")
	}
}

// TestCreateOtherSizeMakesANewFile: a ring of another capacity is a new
// file, so a consumer of the old one keeps a valid mapping and sees Stale.
func TestCreateOtherSizeMakesANewFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = p.Close()
	if c.Stale() {
		t.Fatal("stale before the resize")
	}
	p2, err := Create(path, 2*MinCapacity)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p2.Close() }()
	if !c.Stale() {
		t.Fatal("not stale after a create of another size")
	}
	if c.Peek() != nil {
		t.Fatal("datagram on the old file")
	}
	c2, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	if err := p2.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if v := c2.Peek(); string(v) != "x" {
		t.Fatalf("got %q", v)
	}
}
