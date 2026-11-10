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
