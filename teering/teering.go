// Package teering is a shared-memory tee ring: a file (tmpfs, /dev/shm)
// mapped by one producer and one consumer on the same host, carrying the
// datagrams a proxy mirrors to its co-located retry endpoint without the
// loopback UDP stack. The loopback tee copies every byte into socket buffers,
// segments the GSO messages in software, delivers them through the loopback
// device and copies them out again in the endpoint's recvmmsg; on the lab's
// edge that cost the retry endpoint as many cycles as the proxy itself
// (2026-11-10). The ring is one memcpy by the producer and one by the
// consumer into its slot, with no syscall on the path.
//
// # Layout (little endian, the host's)
//
//	Offset  Size  Field
//	 0      4     Magic "TEER"
//	 4      4     Version (1)
//	 8      8     Capacity of the data region in bytes (a multiple of 8)
//	16      8     Head: bytes the producer has published, monotonic
//	24      8     Tail: bytes the consumer has released, monotonic
//	32      8     Dropped: datagrams the producer could not fit
//	40      8     Generation: the producer's open time (unix nanoseconds)
//	48     16     Reserved
//	64      …     Data region, Capacity bytes
//
// A record in the data region is a 4-byte length, 4 reserved bytes and the
// datagram, padded to 8 bytes. A record never crosses the region's end: when
// the rest of the region is too short the producer writes a skip marker
// (length 0xFFFFFFFF) and the consumer jumps to the next multiple of
// Capacity. Head and tail are monotonic byte counts; an offset is the count
// modulo Capacity. The producer publishes a record by storing head after the
// bytes; the consumer releases one by storing tail after its copy. One
// producer, one consumer: the ring is not multi-writer.
//
// A producer that opens an existing file resets its header in place and
// stamps a new generation; a consumer whose generation no longer matches the
// file's resumes at the producer's head and counts what it skipped as lost.
// A file that was replaced (another inode) is detected with Stale.
package teering

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	magic      = 0x52454554 // "TEER" little endian
	version    = 1
	headerSize = 64
	skipMarker = 0xFFFFFFFF
	// voidFlag on a record's length marks space a producer reserved and gave
	// up (reserve.go): the consumer steps over it. A consumer built before
	// reservations reads it as a torn record and resumes at the head.
	voidFlag = 0x80000000
	// batchFlag on a record's length marks a run of datagrams laid back to
	// back (reserve.go): the length is the run's bytes and the record's
	// second word the size of every datagram but the last. A consumer built
	// before reservations reads it as a torn record too.
	batchFlag = 0x40000000
	// MaxBatch is the most bytes one reserved run holds.
	MaxBatch  = 32 << 20
	recHeader = 8
	// MinCapacity is the smallest data region accepted: room for a few
	// jumbo datagrams.
	MinCapacity = 1 << 20
	// MaxDatagram is the largest datagram a record carries (IPv6 without
	// jumbograms).
	MaxDatagram = 64 << 10
)

var (
	ErrNoRoom    = errors.New("teering: no room")
	ErrTooLarge  = errors.New("teering: datagram too large")
	ErrBadHeader = errors.New("teering: not a tee ring")
)

type header struct {
	m []byte
}

func (h header) u64(off int) *uint64 { return (*uint64)(unsafe.Pointer(&h.m[off])) }
func (h header) capacity() uint64    { return binary.LittleEndian.Uint64(h.m[8:]) }
func (h header) head() uint64        { return atomic.LoadUint64(h.u64(16)) }
func (h header) tail() uint64        { return atomic.LoadUint64(h.u64(24)) }
func (h header) generation() uint64  { return atomic.LoadUint64(h.u64(40)) }

func pad8(n int) int { return (n + 7) &^ 7 }

// Producer is the writing side of a ring.
type Producer struct {
	f    *os.File
	m    []byte
	h    header
	data []byte
	cap  uint64
	head uint64 // the producer's own copy of head

	// Reservations (reserve.go). mu guards everything below and the
	// producer's writes; resv is where the next reservation starts (head
	// when none is outstanding), out the reservations not yet published, in
	// order, pins those whose memory a caller still reads.
	mu   sync.Mutex
	resv uint64
	out  []*Reservation
	pins []*Reservation
}

// Create makes the ring file at path with a data region of capacity bytes,
// world readable and writable so a consumer under another user (systemd
// DynamicUser) can attach, and maps it. An existing file of the same size is
// reused in place (its header reset, a new generation), so a consumer that
// still maps it keeps a valid mapping; a file of another size is removed and
// made anew (a mapping of a resized file faults past its end), which
// Consumer.Stale reports.
func Create(path string, capacity int) (*Producer, error) {
	if capacity < MinCapacity {
		return nil, fmt.Errorf("teering: capacity %d below %d", capacity, MinCapacity)
	}
	capacity = pad8(capacity)
	if st, err := os.Lstat(path); err == nil && st.Size() != int64(headerSize+capacity) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o666)
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0o666) // the umask applied to the create
	size := headerSize + capacity
	if err := f.Truncate(int64(size)); err != nil {
		_ = f.Close()
		return nil, err
	}
	m, err := unix.Mmap(int(f.Fd()), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	p := &Producer{f: f, m: m, h: header{m}, data: m[headerSize:], cap: uint64(capacity)}
	// The generation last: a consumer on the old mapping sees the reset
	// counters only once the generation says they are new.
	binary.LittleEndian.PutUint32(m[0:], magic)
	binary.LittleEndian.PutUint32(m[4:], version)
	binary.LittleEndian.PutUint64(m[8:], uint64(capacity))
	atomic.StoreUint64(p.h.u64(16), 0)
	atomic.StoreUint64(p.h.u64(24), 0)
	atomic.StoreUint64(p.h.u64(32), 0)
	atomic.StoreUint64(p.h.u64(40), uint64(time.Now().UnixNano()))
	return p, nil
}

// Write publishes one datagram. ErrNoRoom when the consumer has not released
// enough (the datagram is counted as dropped in the header), ErrTooLarge past
// MaxDatagram.
func (p *Producer) Write(b []byte) error {
	if len(b) > MaxDatagram {
		return ErrTooLarge
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.out) > 0 {
		// Behind reservations not yet published: the datagram takes its
		// place after them and is published with them, in order.
		r, err := p.reserveLocked(len(b), 1, len(b))
		if err != nil {
			p.drop()
			return err
		}
		copy(r.buf, b)
		p.unpinLocked(r)
		r.done = true
		p.publishLocked()
		return nil
	}
	need := uint64(recHeader + pad8(len(b)))
	tail := p.floorLocked()
	off := p.head % p.cap
	// A record never crosses the end: skip the rest of the region first.
	if off+need > p.cap {
		skip := p.cap - off
		if p.head+skip+need-tail > p.cap {
			p.drop()
			return ErrNoRoom
		}
		if skip >= recHeader {
			binary.LittleEndian.PutUint32(p.data[off:], skipMarker)
		}
		p.head += skip
		p.resv = p.head
		off = 0
	}
	if p.head+need-tail > p.cap {
		p.drop()
		return ErrNoRoom
	}
	binary.LittleEndian.PutUint32(p.data[off:], uint32(len(b)))
	binary.LittleEndian.PutUint32(p.data[off+4:], 0)
	copy(p.data[off+recHeader:], b)
	p.head += need
	p.resv = p.head
	atomic.StoreUint64(p.h.u64(16), p.head)
	return nil
}

func (p *Producer) drop() { atomic.AddUint64(p.h.u64(32), 1) }

// Backlog is how many bytes are published and not yet released.
func (p *Producer) Backlog() uint64 { return p.head - p.h.tail() }

// Dropped is the datagrams the producer could not fit since Create.
func (p *Producer) Dropped() uint64 { return atomic.LoadUint64(p.h.u64(32)) }

// Close unmaps the ring; the file stays for a consumer to drain.
func (p *Producer) Close() error {
	err := unix.Munmap(p.m)
	_ = p.f.Close()
	return err
}

// Consumer is the reading side of a ring.
type Consumer struct {
	path string
	ino  uint64
	f    *os.File
	m    []byte
	h    header
	data []byte
	cap  uint64
	gen  uint64
	tail uint64
	pend uint64 // length of the record Peek returned, 0 when none
	// A run being read (reserve.go): brec is its record's length in the ring
	// (released when the run is read to its end), boff where its next
	// datagram starts in the data region, bleft the bytes still unread and
	// bseg its datagrams' size; bcur is the datagram Peek returned.
	brec, boff, bleft, bseg, bcur uint64
	seen                          uint64 // the head at the last look, under the current generation
	lost                          uint64
	idle                          int
}

// Attach maps the ring file at path. The file must have been created by a
// Producer (ErrBadHeader otherwise).
func Attach(path string) (*Consumer, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if st.Size() < headerSize+MinCapacity {
		_ = f.Close()
		return nil, ErrBadHeader
	}
	m, err := unix.Mmap(int(f.Fd()), 0, int(st.Size()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	h := header{m}
	if binary.LittleEndian.Uint32(m[0:]) != magic || binary.LittleEndian.Uint32(m[4:]) != version ||
		h.capacity() != uint64(st.Size()-headerSize) {
		_ = unix.Munmap(m)
		_ = f.Close()
		return nil, ErrBadHeader
	}
	c := &Consumer{path: path, f: f, m: m, h: h, data: m[headerSize:], cap: h.capacity(), gen: h.generation()}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		c.ino = sys.Ino
	}
	c.tail = c.h.tail()
	c.seen = c.h.head()
	return c, nil
}

// Stale reports whether the path now names another file than the one c
// maps (the producer created a new one: systemd's RemoveIPC takes a
// DynamicUser's /dev/shm files with the service), so the owner re-attaches.
func (c *Consumer) Stale() bool {
	st, err := os.Stat(c.path)
	if err != nil {
		return true
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	return ok && sys.Ino != c.ino
}

// Next copies the next datagram into buf and returns its length, or 0 when
// the ring is empty. A datagram longer than buf is skipped and counted as
// lost. A producer that reopened the file (new generation) resets the
// consumer to its head; what was unread counts as lost.
func (c *Consumer) Next(buf []byte) int {
	for {
		v := c.Peek()
		if v == nil {
			return 0
		}
		if len(v) > len(buf) {
			c.lost++
			c.Advance()
			continue
		}
		n := copy(buf, v)
		c.Advance()
		return n
	}
}

// Peek returns the next datagram as a view into the ring, or nil when the
// ring is empty. The view is valid until Advance, which releases it to the
// producer: a caller that keeps the bytes copies them first, once, into
// memory of its own (Next copies into a buffer the caller then copies
// again). Peek without Advance returns the same datagram.
func (c *Consumer) Peek() []byte {
	for {
		head := c.h.head()
		if gen := c.h.generation(); gen != c.gen {
			// The producer restarted: what was unread is gone with its
			// counters (one loss counted, the exact number is unknown:
			// what the old producer published after the consumer's last
			// look is not seen at all). The head read above may predate
			// the reset; the producer stores the generation last, so a
			// head read now is the new generation's.
			c.gen = gen
			if c.tail != c.seen {
				c.lost++
			}
			head = c.h.head()
			c.tail, c.seen = head, head
			c.pend = 0
			c.brec, c.bleft, c.bcur = 0, 0, 0
			atomic.StoreUint64(c.h.u64(24), c.tail)
			continue
		}
		c.seen = head
		if c.bleft > 0 {
			// Inside a run: its next datagram.
			c.bcur = min(c.bseg, c.bleft)
			return c.data[c.boff : c.boff+c.bcur : c.boff+c.bcur]
		}
		if c.tail == head {
			return nil
		}
		off := c.tail % c.cap
		if off+recHeader > c.cap {
			c.tail += c.cap - off
			continue
		}
		n := binary.LittleEndian.Uint32(c.data[off:])
		if n == skipMarker {
			c.tail += c.cap - off
			continue
		}
		if n&(voidFlag|batchFlag) != 0 {
			total := uint64(n &^ (voidFlag | batchFlag))
			rec := recHeader + (total+7)&^7
			seg := uint64(binary.LittleEndian.Uint32(c.data[off+4:]))
			if total == 0 || total > MaxBatch || c.tail+rec > head || off+rec > c.cap || (n&batchFlag != 0 && (seg == 0 || seg > MaxDatagram)) {
				// Not a record this producer wrote: resume at its head.
				c.lost++
				c.tail = head
				atomic.StoreUint64(c.h.u64(24), c.tail)
				continue
			}
			if n&voidFlag != 0 {
				// A reservation the producer gave up: its space, no datagram.
				c.tail += rec
				atomic.StoreUint64(c.h.u64(24), c.tail)
				continue
			}
			c.brec, c.boff, c.bleft, c.bseg = rec, off+recHeader, total, seg
			continue
		}
		rec := uint64(recHeader + pad8(int(n)))
		if n > MaxDatagram || c.tail+rec > head || off+rec > c.cap {
			// Not a record this producer wrote (never with one producer):
			// resume at its head.
			c.lost++
			c.tail = head
			atomic.StoreUint64(c.h.u64(24), c.tail)
			continue
		}
		c.pend = rec
		return c.data[off+recHeader : off+recHeader+uint64(n) : off+recHeader+uint64(n)]
	}
}

// Advance releases the datagram Peek returned. Without a pending Peek it
// does nothing.
func (c *Consumer) Advance() {
	if c.bcur > 0 {
		c.boff += c.bcur
		c.bleft -= c.bcur
		c.bcur = 0
		if c.bleft == 0 {
			c.tail += c.brec
			c.brec = 0
			atomic.StoreUint64(c.h.u64(24), c.tail)
		}
		return
	}
	if c.pend == 0 {
		return
	}
	c.tail += c.pend
	c.pend = 0
	atomic.StoreUint64(c.h.u64(24), c.tail)
}

// Wait pauses when the ring was empty: a few empty polls spin, then it sleeps
// with a backoff up to max, reset by Ready.
func (c *Consumer) Wait(max time.Duration) {
	c.idle++
	switch {
	case c.idle < 64:
		return
	case c.idle < 128:
		time.Sleep(20 * time.Microsecond)
	default:
		d := time.Duration(c.idle-127) * 50 * time.Microsecond
		if d > max {
			d = max
		}
		time.Sleep(d)
	}
}

// Ready resets the wait backoff: call after a datagram was read.
func (c *Consumer) Ready() { c.idle = 0 }

// Lost is the datagrams skipped by this consumer (too long, torn, or
// unread at a producer restart).
func (c *Consumer) Lost() uint64 { return c.lost }

// Dropped is the producer's own drop count.
func (c *Consumer) Dropped() uint64 { return atomic.LoadUint64(c.h.u64(32)) }

// Close unmaps the ring.
func (c *Consumer) Close() error {
	err := unix.Munmap(c.m)
	_ = c.f.Close()
	return err
}
