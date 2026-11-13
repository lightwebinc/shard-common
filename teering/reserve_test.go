package teering

import (
	"bytes"
	"errors"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
)

func ringPair(t *testing.T, capacity int) (*Producer, *Consumer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ring")
	p, err := Create(path, capacity)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Attach(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = p.Close() })
	return p, c
}

func drain(t *testing.T, c *Consumer) [][]byte {
	t.Helper()
	var out [][]byte
	buf := make([]byte, MaxDatagram)
	for {
		n := c.Next(buf)
		if n == 0 {
			return out
		}
		out = append(out, bytes.Clone(buf[:n]))
	}
}

// What a consumer reads from reservations is what it reads from Writes of
// the same datagrams, over many wraps and mixed with Writes.
func TestReservedEqualsWritten(t *testing.T) {
	p, c := ringPair(t, MinCapacity)
	r := rand.New(rand.NewSource(7))
	var want, got [][]byte
	for round := 0; round < 300; round++ {
		if round%3 == 2 {
			b := make([]byte, 1+r.Intn(9000))
			r.Read(b)
			if err := p.Write(b); err != nil {
				t.Fatal(err)
			}
			want = append(want, b)
		} else {
			seg, count := 1+r.Intn(9000), 1+r.Intn(12)
			last := 1 + r.Intn(seg)
			res, err := p.Reserve((count-1)*seg + last)
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			b := res.Bytes()
			if len(b) != (count-1)*seg+last {
				t.Fatalf("run of %d bytes, asked %d", len(b), (count-1)*seg+last)
			}
			r.Read(b)
			for i := 0; i < count; i++ {
				want = append(want, bytes.Clone(b[i*seg:min((i+1)*seg, len(b))]))
			}
			p.Commit(res, seg)
			p.Unpin(res)
		}
		got = append(got, drain(t, c)...)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d datagrams, wrote %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("datagram %d differs", i)
		}
	}
	if c.Lost() != 0 || p.Dropped() != 0 || p.Pinned() != 0 {
		t.Fatalf("lost %d dropped %d pinned %d", c.Lost(), p.Dropped(), p.Pinned())
	}
}

// The consumer sees reservations in the order they were reserved, whatever
// order they are committed in, and nothing of one before it is committed.
func TestReservationsPublishInOrder(t *testing.T) {
	p, c := ringPair(t, MinCapacity)
	a, _ := p.Reserve(300)
	b, _ := p.Reserve(300)
	for i := range a.Bytes() {
		a.Bytes()[i] = 'a'
	}
	for i := range b.Bytes() {
		b.Bytes()[i] = 'b'
	}
	if err := p.Write([]byte("w")); err != nil { // behind both
		t.Fatal(err)
	}
	p.Commit(b, 300)
	if got := drain(t, c); len(got) != 0 {
		t.Fatalf("%d datagrams visible before the first reservation was committed", len(got))
	}
	p.Commit(a, 200)
	got := drain(t, c)
	if len(got) != 4 || len(got[0]) != 200 || len(got[1]) != 100 || len(got[2]) != 300 || string(got[3]) != "w" ||
		got[0][0] != 'a' || got[2][0] != 'b' {
		t.Fatalf("order or content wrong: %d datagrams", len(got))
	}
	p.Unpin(a)
	p.Unpin(b)
}

// A void reservation is stepped over: the consumer reads what is around it
// and counts nothing lost.
func TestVoidIsSkipped(t *testing.T) {
	p, c := ringPair(t, MinCapacity)
	a, _ := p.Reserve(500)
	b, _ := p.Reserve(2*8952 + 100)
	d, _ := p.Reserve(700)
	copy(a.Bytes(), bytes.Repeat([]byte{1}, 500))
	copy(d.Bytes(), bytes.Repeat([]byte{3}, 700))
	p.Commit(a, 500)
	p.Void(b)
	p.Commit(d, 700)
	got := drain(t, c)
	if len(got) != 2 || len(got[0]) != 500 || len(got[1]) != 700 || got[1][0] != 3 {
		t.Fatalf("read %d datagrams around a void reservation", len(got))
	}
	if c.Lost() != 0 || p.Pinned() != 2 {
		t.Fatalf("lost %d pinned %d", c.Lost(), p.Pinned())
	}
}

// Space is not handed out again while pinned, even after the consumer has
// released it; once unpinned it is.
func TestPinnedSpaceIsNotReused(t *testing.T) {
	p, c := ringPair(t, MinCapacity)
	reserve := func() (*Reservation, error) { return p.Reserve(4 * 60000) }
	first, err := reserve()
	if err != nil {
		t.Fatal(err)
	}
	marker := bytes.Repeat([]byte{0xEE}, 60000)
	copy(first.Bytes(), marker)
	p.Commit(first, 60000)
	drain(t, c) // the consumer has released it; it stays pinned
	var held []*Reservation
	for {
		r, err := reserve()
		if errors.Is(err, ErrNoRoom) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range r.Bytes() {
			r.Bytes()[i] = 0x11
		}
		p.Commit(r, 60000)
		drain(t, c)
		held = append(held, r)
		if len(held) > 100 {
			t.Fatal("the ring never filled around a pinned reservation")
		}
	}
	if !bytes.Equal(first.Bytes()[:60000], marker) {
		t.Fatal("pinned memory was written over")
	}
	p.Unpin(first)
	for _, r := range held {
		p.Unpin(r)
	}
	if _, err := reserve(); err != nil {
		t.Fatalf("no room after everything was unpinned and read: %v", err)
	}
}

// Many goroutines reserve, fill and commit at once; a reader gets every
// datagram whole, each producer's in its own order.
func TestConcurrentReservations(t *testing.T) {
	p, c := ringPair(t, 8<<20)
	const writers, each = 6, 400
	var wg sync.WaitGroup
	stop := make(chan struct{})
	seen := make([]int, writers)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, MaxDatagram)
		total := 0
		for total < writers*each {
			n := c.Next(buf)
			if n == 0 {
				select {
				case <-stop:
					return
				default:
				}
				continue
			}
			w, seq := int(buf[0]), int(buf[1])|int(buf[2])<<8
			if seq != seen[w] {
				t.Errorf("writer %d: datagram %d read, want %d", w, seq, seen[w])
				return
			}
			for _, x := range buf[3:n] {
				if x != byte(w) {
					t.Errorf("writer %d: torn datagram", w)
					return
				}
			}
			seen[w]++
			total++
		}
	}()
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for seq := 0; seq < each; {
				n := 3 + 1000*(w+1)
				r, err := p.Reserve(n)
				if err != nil {
					continue // the reader will make room
				}
				b := r.Bytes()
				b[0], b[1], b[2] = byte(w), byte(seq), byte(seq>>8)
				for i := 3; i < len(b); i++ {
					b[i] = byte(w)
				}
				p.Commit(r, n)
				p.Unpin(r)
				seq++
			}
		}(w)
	}
	wg.Wait()
	<-done
	close(stop)
	for w, n := range seen {
		if n != each {
			t.Fatalf("writer %d: %d of %d datagrams read", w, n, each)
		}
	}
	if c.Lost() != 0 {
		t.Fatalf("lost %d", c.Lost())
	}
}

// A reservation whose producer never commits it (it died, or forgot) is
// space the consumer steps over once the head passes it.
func TestUncommittedIsVoidOnDisk(t *testing.T) {
	p, c := ringPair(t, MinCapacity)
	a, _ := p.Reserve(4000)
	b, _ := p.Reserve(100)
	copy(b.Bytes(), bytes.Repeat([]byte{9}, 100))
	p.Commit(b, 100)
	p.Void(a) // done without a Commit: published as it was reserved
	got := drain(t, c)
	if len(got) != 1 || len(got[0]) != 100 || got[0][0] != 9 || c.Lost() != 0 {
		t.Fatalf("read %d datagrams, lost %d", len(got), c.Lost())
	}
	// A seg that is no datagram size voids the run instead of publishing rubbish.
	d, _ := p.Reserve(3 * 9000)
	p.Commit(d, 0)
	p.Unpin(d)
	if got := drain(t, c); len(got) != 0 || c.Lost() != 0 {
		t.Fatalf("a run committed with no datagram size was read (%d datagrams, lost %d)", len(got), c.Lost())
	}
}
