package teering

import (
	"encoding/binary"
	"sync/atomic"
)

// Reservations: ring space a producer fills in place.
//
// Write copies a datagram into the ring. A producer that builds its
// datagrams anyway (a proxy fragmenting a record) can build them in the ring
// instead: Reserve returns the memory for a run of datagrams laid back to
// back, the producer fills it (on any goroutine, without a lock: the space
// is its own until published), sends from it, and Commit publishes the run.
// The tee is then no copy at all, and because the run is contiguous the
// producer can send it as it would send a buffer of its own (GSO messages of
// several datagrams from one slice).
//
// A run is one record in the ring: its length carries batchFlag and its
// second word the size of every datagram but the last, which may be shorter.
// The consumer hands the datagrams out one at a time, as it does single
// records, and releases the run's space when it has read the last.
//
// Reservations are published in the order they were reserved: the head moves
// past one only when every earlier one is committed or given up (Void), so
// the consumer sees the datagrams in reservation order whatever order the
// producer finishes them in. A Write made while reservations are outstanding
// takes its place behind them.
//
// A reservation stays pinned after Commit until Unpin: its memory is not
// handed out again, even once the consumer has released it, while the
// producer (or the kernel, for a zero-copy send) may still read it. Unpin
// when nothing references the memory any more. Void unpins.
//
// A consumer must be built with reservations to read a ring that carries
// them: an older one reads a run as a torn record, counts a loss and resumes
// at the head, so the endpoint is rolled before the proxy uses them.
//
// Producer methods are safe for concurrent use.

// Reservation is a run of datagrams reserved in the ring.
type Reservation struct {
	start, end uint64 // head counts: the run's record, with any skip ahead of it
	buf        []byte // the run's datagrams, back to back
	hdr        uint64 // the record header's offset in the data region
	done       bool
}

// Bytes is the run's memory: its datagrams back to back, each seg bytes but
// the last. It is the producer's until Commit; after Commit it must not be
// written, and may be read until Unpin.
func (r *Reservation) Bytes() []byte { return r.buf }

// Reserve reserves a run of count datagrams, each seg bytes except the last,
// which is last bytes (0 < last <= seg), and returns the reservation, or
// ErrNoRoom when the ring cannot hold it now (the consumer has not released
// enough, or released space is still pinned): the caller then sends another
// way and may Write the datagrams, which counts a drop when that fails too.
// ErrTooLarge for a datagram over MaxDatagram or a run over MaxBatch.
func (p *Producer) Reserve(seg, count, last int) (*Reservation, error) {
	if seg <= 0 || count <= 0 || last <= 0 || last > seg || seg > MaxDatagram || (count-1)*seg+last > MaxBatch {
		return nil, ErrTooLarge
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reserveLocked(seg, count, last)
}

func (p *Producer) reserveLocked(seg, count, last int) (*Reservation, error) {
	total := uint64((count-1)*seg + last)
	need := recHeader + (total+7)&^7
	if need > p.cap {
		return nil, ErrTooLarge
	}
	pos := p.resv
	off := pos % p.cap
	skip := uint64(0)
	if off+need > p.cap {
		skip = p.cap - off
	}
	if pos+skip+need-p.floorLocked() > p.cap {
		return nil, ErrNoRoom
	}
	if skip > 0 {
		if skip >= recHeader {
			binary.LittleEndian.PutUint32(p.data[off:], skipMarker)
		}
		pos += skip
		off = 0
	}
	word := uint32(total)
	if count > 1 {
		word |= batchFlag
	}
	binary.LittleEndian.PutUint32(p.data[off:], word)
	binary.LittleEndian.PutUint32(p.data[off+4:], uint32(seg))
	r := &Reservation{start: p.resv, end: pos + need, hdr: off,
		buf: p.data[off+recHeader : off+recHeader+total : off+recHeader+total]}
	p.resv = r.end
	p.out = append(p.out, r)
	p.pins = append(p.pins, r)
	return r, nil
}

// Commit publishes r's datagrams to the consumer, once every reservation
// made before it is committed or void. r stays pinned until Unpin.
func (p *Producer) Commit(r *Reservation) {
	p.mu.Lock()
	r.done = true
	p.publishLocked()
	p.mu.Unlock()
}

// Void gives r up: its record is marked so the consumer steps over it, and
// its space is released to the ring like any other. Use it when the
// datagrams will not be sent after all. Void after Commit only unpins.
func (p *Producer) Void(r *Reservation) {
	p.mu.Lock()
	if !r.done {
		binary.LittleEndian.PutUint32(p.data[r.hdr:], uint32(len(r.buf))|voidFlag)
		r.done = true
	}
	p.unpinLocked(r)
	p.publishLocked()
	p.mu.Unlock()
}

// Unpin says nothing reads r's memory any more: once the consumer has
// released it, it is handed out again.
func (p *Producer) Unpin(r *Reservation) {
	p.mu.Lock()
	p.unpinLocked(r)
	p.mu.Unlock()
}

func (p *Producer) unpinLocked(r *Reservation) {
	for i, x := range p.pins {
		if x == r {
			p.pins = append(p.pins[:i], p.pins[i+1:]...)
			return
		}
	}
}

// publishLocked moves the head past every leading reservation that is done.
func (p *Producer) publishLocked() {
	n := 0
	for n < len(p.out) && p.out[n].done {
		p.head = p.out[n].end
		n++
	}
	if n == 0 {
		return
	}
	p.out = append(p.out[:0], p.out[n:]...)
	atomic.StoreUint64(p.h.u64(16), p.head)
}

// floorLocked is the oldest byte the ring must keep: what the consumer has
// not released, or the oldest pinned reservation when that is older.
func (p *Producer) floorLocked() uint64 {
	t := p.h.tail()
	if len(p.pins) > 0 && p.pins[0].start < t {
		return p.pins[0].start
	}
	return t
}

// Pinned is how many reservations are still pinned (not yet Unpin'd or void).
func (p *Producer) Pinned() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pins)
}
