package interest

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Delivery kinds.
const (
	// DeliverUnicast: to one host.
	DeliverUnicast byte = 1
	// DeliverMulticast: to a group, from any source.
	DeliverMulticast byte = 2
	// DeliverMulticastSSM: to a group, from one source.
	DeliverMulticastSSM byte = 3
)

// Delivery encodings.
const (
	// EncodeRecords: BRC-149 delivery records on a TCP stream.
	EncodeRecords byte = 1
	// EncodeFrames: BRC-149 frames in UDP datagrams.
	EncodeFrames byte = 2
)

// Delivery is where the objects for a topic should arrive: the value of an
// [ExtDelivery] extension. It is meaningful only to the next hop up. A hop
// that distributes replaces it with its own address when it announces
// upward; a hop that does not distribute drops it and says so with
// [StatusAddressNotHonored]. A receiver distributes when its policy is a
// [Deliverer].
//
//	Offset  Size   Field
//	  0       1    Kind      1 unicast, 2 multicast, 3 source-specific multicast
//	  1       1    Encoding  1 delivery records on TCP, 2 frames on UDP
//	  2       1    Family    4 or 6
//	  3       1    reserved
//	  4       2    Port
//	  6    4 or 16 Address   the host, or the group
//	  …    4 or 16 Source    Kind 3 only, same family
type Delivery struct {
	Kind     byte
	Encoding byte
	Addr     netip.Addr
	Port     uint16
	// Source is the sender of a source-specific group. Invalid otherwise.
	Source netip.Addr
}

// Validate checks that the fields agree with one another. Addresses are
// checked as they are encoded: an IPv4-mapped IPv6 address is the IPv4
// address.
func (d *Delivery) Validate() error {
	addr, src := d.Addr.Unmap(), d.Source.Unmap()
	if !addr.IsValid() {
		return fmt.Errorf("interest: delivery without an address")
	}
	switch d.Kind {
	case DeliverUnicast:
		if addr.IsMulticast() || addr.IsUnspecified() {
			return fmt.Errorf("interest: unicast delivery to %s", addr)
		}
		if src.IsValid() {
			return fmt.Errorf("interest: unicast delivery names a source")
		}
	case DeliverMulticast:
		if !addr.IsMulticast() {
			return fmt.Errorf("interest: multicast delivery to %s, which is not a group", addr)
		}
		if src.IsValid() {
			return fmt.Errorf("interest: any-source delivery names a source")
		}
	case DeliverMulticastSSM:
		if !addr.IsMulticast() {
			return fmt.Errorf("interest: multicast delivery to %s, which is not a group", addr)
		}
		if !src.IsValid() || src.IsMulticast() || src.Is4() != addr.Is4() {
			return fmt.Errorf("interest: source-specific delivery needs a unicast source of the group's family")
		}
	default:
		return fmt.Errorf("interest: delivery kind %d", d.Kind)
	}
	return nil
}

// AppendValue appends the wire form of d.
func (d *Delivery) AppendValue(dst []byte) ([]byte, error) {
	if err := d.Validate(); err != nil {
		return dst, err
	}
	addr := d.Addr.Unmap()
	family := byte(6)
	if addr.Is4() {
		family = 4
	}
	dst = append(dst, d.Kind, d.Encoding, family, 0)
	dst = binary.BigEndian.AppendUint16(dst, d.Port)
	dst = append(dst, addr.AsSlice()...)
	if d.Kind == DeliverMulticastSSM {
		dst = append(dst, d.Source.Unmap().AsSlice()...)
	}
	return dst, nil
}

// ParseDelivery decodes the value of an [ExtDelivery] extension.
func ParseDelivery(v []byte) (*Delivery, error) {
	d, rest, err := parseDelivery(v)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d bytes after a delivery address", ErrMalformed, len(rest))
	}
	return d, nil
}

func parseDelivery(v []byte) (*Delivery, []byte, error) {
	if len(v) < 6 {
		return nil, nil, fmt.Errorf("%w: delivery of %d bytes", ErrMalformed, len(v))
	}
	d := &Delivery{Kind: v[0], Encoding: v[1], Port: binary.BigEndian.Uint16(v[4:6])}
	var alen int
	switch v[2] {
	case 4:
		alen = 4
	case 6:
		alen = 16
	default:
		return nil, nil, fmt.Errorf("%w: delivery family %d", ErrMalformed, v[2])
	}
	p := v[6:]
	if len(p) < alen {
		return nil, nil, fmt.Errorf("%w: delivery address truncated", ErrMalformed)
	}
	d.Addr, _ = netip.AddrFromSlice(p[:alen])
	p = p[alen:]
	if d.Kind == DeliverMulticastSSM {
		if len(p) < alen {
			return nil, nil, fmt.Errorf("%w: delivery source truncated", ErrMalformed)
		}
		d.Source, _ = netip.AddrFromSlice(p[:alen])
		p = p[alen:]
	}
	if err := d.Validate(); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return d, p, nil
}

// Assignment tells a sender where a topic will be found: the value of an
// [ExtAssign] extension in an ACK. It is the downward form of a delivery
// address, and the natural one for multicast, where the upstream names the
// group and the host joins it.
//
//	Offset  Size  Field
//	  0      32   TopicID
//	 32       …   a delivery address, as in [Delivery]
type Assignment struct {
	Topic TopicID
	Delivery
}

// AppendValue appends the wire form of a.
func (a *Assignment) AppendValue(dst []byte) ([]byte, error) {
	dst = append(dst, a.Topic[:]...)
	return a.Delivery.AppendValue(dst)
}

// ParseAssignment decodes the value of an [ExtAssign] extension.
func ParseAssignment(v []byte) (*Assignment, error) {
	if len(v) < 32 {
		return nil, fmt.Errorf("%w: assignment of %d bytes", ErrMalformed, len(v))
	}
	d, err := ParseDelivery(v[32:])
	if err != nil {
		return nil, err
	}
	a := &Assignment{Delivery: *d}
	copy(a.Topic[:], v[:32])
	return a, nil
}
