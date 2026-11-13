package teering

import (
	"encoding/binary"
	"sync/atomic"
)

// Reservations: ring space a producer fills in place.
//
// Write copies a datagram into the ring. A producer that builds its
// datagrams anyway (a proxy fragmenting a record) can build them in the ring
// instead: Reserve lays out the records for a run of datagrams and returns
// their memory, the producer fills it (on any goroutine, without the lock:
// the space is its own until published), sends from it, and Commit publishes
// the run. The tee is then no copy at all.
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
// Producer methods are safe for concurrent use.

// Reservation is a run of datagrams reserved in the ring.
type Reservation struct {
	start, end uint64   // head counts: the run's records, with any skip ahead of them
	bufs       [][]byte // each datagram's memory in the ring
	hdrs       []uint64 // each record header's offset in the data region
	done       bool
}

// Datagrams is the memory of each datagram, in order, each of the size asked
// for. It is the producer's until Commit; after Commit it must not be
// written, and may be read until Unpin.
func (r *Reservation) Datagrams() [][]byte { return r.bufs }

// Reserve reserves records for datagrams of the given sizes and returns the
// reservation, or ErrNoRoom when the ring cannot hold them now (the consumer
// has not released enough, or released space is still pinned): the caller
// then sends another way and may Write the datagrams, which counts a drop
// when that fails too. ErrTooLarge past MaxDatagram.
func (p *Producer) Reserve(sizes []int) (*Reservation, error) {
	for _, n := range sizes {
		if n > MaxDatagram {
			return nil, ErrTooLarge
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reserveLocked(sizes)
}

func (p *Producer) reserveLocked(sizes []int) (*Reservation, error) {
	floor := p.floorLocked()
	// First pass: where everything would go, writing nothing.
	pos := p.resv
	for _, n := range sizes {
		need := uint64(recHeader + pad8(n))
		if off := pos % p.cap; off+need > p.cap {
			pos += p.cap - off
		}
		pos += need
	}
	if pos-floor > p.cap {
		return nil, ErrNoRoom
	}
	r := &Reservation{start: p.resv, end: pos, bufs: make([][]byte, 0, len(sizes)), hdrs: make([]uint64, 0, len(sizes))}
	pos = p.resv
	for _, n := range sizes {
		need := uint64(recHeader + pad8(n))
		off := pos % p.cap
		if off+need > p.cap {
			if p.cap-off >= recHeader {
				binary.LittleEndian.PutUint32(p.data[off:], skipMarker)
			}
			pos += p.cap - off
			off = 0
		}
		binary.LittleEndian.PutUint32(p.data[off:], uint32(n))
		binary.LittleEndian.PutUint32(p.data[off+4:], 0)
		r.hdrs = append(r.hdrs, off)
		r.bufs = append(r.bufs, p.data[off+recHeader:off+recHeader+uint64(n):off+recHeader+uint64(n)])
		pos += need
	}
	p.resv = pos
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

// Void gives r up: its records are marked so the consumer steps over them,
// and its space is released to the ring like any other. Use it when the
// datagrams will not be sent after all.
func (p *Producer) Void(r *Reservation) {
	p.mu.Lock()
	if !r.done {
		for i, off := range r.hdrs {
			binary.LittleEndian.PutUint32(p.data[off:], uint32(len(r.bufs[i]))|voidFlag)
		}
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
