package interest

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/shard"
)

func fuzzSeeds(f *testing.F) {
	ann := Announce{
		Header:  Header{Version: Version, SenderID: 3, Token: 4, Seq: 5, Flags: FlagScopeWanted},
		Records: []Record{{Topic: topic("a"), Lifetime: 60}, {Topic: topic("b"), Lifetime: 0, Ext: AppendTLV(nil, 0x90, []byte{1})}},
		Ext:     AppendTLV(nil, ExtDelivery, []byte{1, 1, 4, 0, 0x23, 0xD3, 192, 0, 2, 1}),
	}
	b, _ := ann.Append(nil)
	f.Add(b)
	dig := Digest{Header: Header{Version: Version, SenderID: 3, Token: 4, Seq: 6}, Since: 5, SetCount: 1}
	b, _ = dig.Append(nil)
	f.Add(b)
	sc, _ := NewScope(shard.DomainBEEF, 6, [16]byte{1}, []uint16{0x1001, 0x1002})
	ack := Ack{
		Header:   Header{Version: Version, SenderID: 3, Token: 4, Seq: 5},
		Statuses: []RecordStatus{{Index: 1, Status: StatusNotServed}},
		Ext:      AppendNotices(AppendTLV(nil, ExtScope, sc.Value()), []Notice{{Topic: topic("a"), Status: StatusUnserved}}),
	}
	b, _ = ack.Append(nil)
	f.Add(b)
	b, _ = (&Resync{Header: Header{Version: Version, SenderID: 3}}).Append(nil)
	f.Add(b)
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
}

// No input may panic a decoder, and whatever decodes must encode back to
// something that decodes to the same message.
func FuzzDecode(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := DecodeHeader(b); err != nil {
			return
		}
		if m, err := DecodeAnnounce(b); err == nil {
			for i := range m.Records {
				_, _ = ParseTLVs(m.Records[i].Ext)
			}
			_, _ = ParseTLVs(m.Ext)
			if len(b) <= MaxDatagram {
				out, err := m.Append(nil)
				if err != nil {
					t.Fatalf("a decoded announce does not encode: %v", err)
				}
				back, err := DecodeAnnounce(out)
				if err != nil || len(back.Records) != len(m.Records) || !bytes.Equal(back.Ext, m.Ext) {
					t.Fatalf("announce did not survive a round trip: %v", err)
				}
				for i := range m.Records {
					if back.Records[i].Topic != m.Records[i].Topic || back.Records[i].Lifetime != m.Records[i].Lifetime ||
						!bytes.Equal(back.Records[i].Ext, m.Records[i].Ext) {
						t.Fatalf("record %d did not survive a round trip", i)
					}
				}
			}
		}
		if m, err := DecodeDigest(b); err == nil && len(b) <= MaxDatagram {
			out, err := m.Append(nil)
			if err != nil {
				t.Fatalf("a decoded digest does not encode: %v", err)
			}
			back, err := DecodeDigest(out)
			if err != nil || back.Since != m.Since || back.SetCount != m.SetCount || back.SetDigest != m.SetDigest || !bytes.Equal(back.Ext, m.Ext) {
				t.Fatalf("digest did not survive a round trip: %v", err)
			}
		}
		if m, err := DecodeAck(b); err == nil {
			if tlvs, err := ParseTLVs(m.Ext); err == nil {
				for _, x := range tlvs {
					switch x.Type {
					case ExtScope:
						if sc, err := ParseScope(x.Value); err == nil {
							_ = sc.Contains(TopicID{1})
							if v := sc.Value(); v != nil {
								if back, err := ParseScope(v); err != nil || !back.Equal(sc) {
									t.Fatalf("scope did not survive a round trip: %v", err)
								}
							}
						}
					case ExtNotice:
						_, _ = ParseNotices(x.Value)
					case ExtAssign:
						_, _ = ParseAssignment(x.Value)
					case ExtDelivery:
						if d, err := ParseDelivery(x.Value); err == nil {
							if _, err := d.AppendValue(nil); err != nil {
								t.Fatalf("a parsed delivery does not encode: %v", err)
							}
						}
					}
				}
			}
			if len(b) <= MaxDatagram {
				out, err := m.Append(nil)
				if err != nil {
					t.Fatalf("a decoded ack does not encode: %v", err)
				}
				back, err := DecodeAck(out)
				if err != nil || back.Result != m.Result || len(back.Statuses) != len(m.Statuses) {
					t.Fatalf("ack did not survive a round trip: %v", err)
				}
			}
		}
	})
}

// Arbitrary datagrams from a sender that holds a valid token must never
// panic the receiver or break its bookkeeping.
func FuzzReceiver(f *testing.F) {
	fuzzSeeds(f)
	sc, _ := NewScope(shard.DomainBEEF, 3, [16]byte{}, []uint16{0x1000, 0x1003, 0x1007})
	src := netip.MustParseAddrPort("[2001:db8::10]:4000")
	f.Fuzz(func(t *testing.T, b []byte) {
		pol := &testPolicy{scope: sc, listOnly: true, quota: 3}
		r := NewReceiver(ReceiverConfig{Policy: notingPolicy{pol}, Secret: []byte("fuzz"), MaxTopicsPerSender: 20})
		now := time.Unix(1_700_000_000, 0)
		// Split the input into datagrams and give each the right token, so
		// that the fuzzer reaches the state machine instead of stopping at
		// the token check.
		for len(b) > 0 {
			n := len(b)
			if n > 2 {
				n = 2 + int(binary.BigEndian.Uint16(b[:2]))%400
				b = b[2:]
				if n > len(b) {
					n = len(b)
				}
			}
			pkt := bytes.Clone(b[:n])
			b = b[n:]
			if h, err := DecodeHeader(pkt); err == nil {
				binary.BigEndian.PutUint64(pkt[24:32], r.token(src, h.SenderID))
			}
			resp := r.Handle(src, pkt, now)
			if resp != nil {
				if len(resp) > MaxDatagram {
					t.Fatalf("a %d-byte answer", len(resp))
				}
				if _, err := DecodeAck(resp); err != nil {
					t.Fatalf("the receiver's own answer does not decode: %v", err)
				}
			}
			now = now.Add(700 * time.Millisecond)
			r.Tick(now)
			if err := receiverInvariants(r); err != nil {
				t.Fatal(err)
			}
		}
		r.Reevaluate("p", now)
		r.Tick(now.Add(2 * time.Hour))
		if err := receiverInvariants(r); err != nil {
			t.Fatal(err)
		}
		if got := r.Stats().Topics; got != 0 {
			t.Fatalf("%d topics outlived every lifetime", got)
		}
	})
}

// Arbitrary answers must never panic the client or break its bookkeeping,
// whatever they claim.
func FuzzClient(f *testing.F) {
	fuzzSeeds(f)
	up := netip.MustParseAddrPort("[2001:db8::1]:8729")
	f.Fuzz(func(t *testing.T, b []byte) {
		c := NewClient(ClientConfig{SenderID: 3, Upstreams: []netip.AddrPort{up}, SeqStart: 100})
		for _, x := range topics("f", 70) {
			c.Add(x)
		}
		now := time.Unix(1_700_000_000, 0)
		for round := 0; round < 6 && len(b) > 0; round++ {
			out, _ := c.Poll(now)
			n := len(b)
			if n > 2 {
				n = 2 + int(binary.BigEndian.Uint16(b[:2]))%400
				b = b[2:]
				if n > len(b) {
					n = len(b)
				}
			}
			pkt := bytes.Clone(b[:n])
			b = b[n:]
			// Aim the answer at something the client actually sent, so
			// the fuzzer reaches the handling instead of the lookup.
			if len(out) > 0 && len(pkt) >= HeaderSize {
				if h, err := DecodeHeader(out[round%len(out)].Data); err == nil {
					binary.BigEndian.PutUint64(pkt[16:24], h.SenderID)
					binary.BigEndian.PutUint64(pkt[32:40], h.Seq)
				}
			}
			c.Handle(up, pkt, now)
			if err := clientInvariants(c); err != nil {
				t.Fatal(err)
			}
			if round%2 == 0 {
				c.Remove(topic("f-1"))
				c.Add(topic("late"))
			}
			now = now.Add(300 * time.Millisecond)
		}
		c.Poll(now.Add(time.Hour))
		if err := clientInvariants(c); err != nil {
			t.Fatal(err)
		}
	})
}
