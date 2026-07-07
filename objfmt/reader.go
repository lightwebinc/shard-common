package objfmt

import (
	"errors"
	"fmt"
	"io"
)

// DefaultMaxObject bounds a single object read from a stream. Transactions
// sit far below it; it exists so a corrupt or hostile length field cannot
// balloon memory. Lanes carrying larger classes (subtree, block) raise it
// explicitly when those codecs register.
const DefaultMaxObject = 64 << 20 // 64 MiB

// Reader splits a single-class byte stream into whole objects. The lane
// carries exactly one class (frames are bare — no tag, no length prefix), so
// the class is supplied out of band at construction.
type Reader struct {
	r          io.Reader
	c          Class
	max        int
	buf        []byte
	start, end int // unconsumed window into buf
}

// NewReader returns a Reader that yields class-c objects from r, each
// bounded by DefaultMaxObject.
func NewReader(r io.Reader, c Class) *Reader {
	return &Reader{r: r, c: c, max: DefaultMaxObject}
}

// SetMaxObject raises or lowers the single-object size bound.
func (rd *Reader) SetMaxObject(n int) { rd.max = n }

// Next returns the next whole object from the stream. The returned slice
// aliases the Reader's buffer and is valid only until the following Next
// call. It returns io.EOF at a clean object boundary and
// io.ErrUnexpectedEOF when the stream ends mid-object.
func (rd *Reader) Next() ([]byte, error) {
	for {
		if rd.end > rd.start {
			n, err := Size(rd.c, rd.buf[rd.start:rd.end])
			switch {
			case err == nil:
				obj := rd.buf[rd.start : rd.start+n]
				rd.start += n
				return obj, nil
			case errors.Is(err, ErrShort):
				// fall through to read more
			default:
				return nil, err
			}
			if rd.end-rd.start >= rd.max {
				return nil, fmt.Errorf("%w: >%d bytes without a boundary", ErrObjectTooLarge, rd.max)
			}
		}

		// Compact the pending window to the front, then grow if needed.
		if rd.start > 0 {
			copy(rd.buf, rd.buf[rd.start:rd.end])
			rd.end -= rd.start
			rd.start = 0
		}
		if len(rd.buf)-rd.end < 4096 {
			grow := 2 * len(rd.buf)
			if grow == 0 {
				grow = 64 << 10
			}
			if grow > rd.max+4096 {
				grow = rd.max + 4096
			}
			nb := make([]byte, grow)
			copy(nb, rd.buf[:rd.end])
			rd.buf = nb
		}

		n, err := rd.r.Read(rd.buf[rd.end:])
		rd.end += n
		if err != nil {
			if err == io.EOF {
				if rd.end == rd.start {
					return nil, io.EOF
				}
				// Bytes remain: either a whole object arrived together
				// with the EOF (loop to parse it), a truncated object
				// (unexpected EOF), or garbage (malformed).
				if _, serr := Size(rd.c, rd.buf[rd.start:rd.end]); serr == nil {
					continue
				} else if errors.Is(serr, ErrShort) {
					return nil, io.ErrUnexpectedEOF
				} else {
					return nil, serr
				}
			}
			return nil, err
		}
	}
}
