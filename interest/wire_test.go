package interest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/lightwebinc/shard-common/shard"
)

func topic(name string) TopicID { return TopicID(sha256.Sum256([]byte(name))) }

func TestHeaderLayout(t *testing.T) {
	m := &Resync{Header: Header{
		Flags: 0xA5, Version: 7, Hops: 3, SenderID: 0x1122334455667788,
		Token: 0x99AABBCCDDEEFF00, Seq: 0x0102030405060708,
	}}
	b, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "e3e1f3e8" + "02bf" + "53" + "a5" + "07" + "03" + "00" + "00" + "0000" + "0000" +
		"1122334455667788" + "99aabbccddeeff00" + "0102030405060708"
	if got := hex.EncodeToString(b); got != want {
		t.Fatalf("header bytes\n got %s\nwant %s", got, want)
	}
	if len(b) != HeaderSize {
		t.Fatalf("header is %d bytes, want %d", len(b), HeaderSize)
	}
	h, err := DecodeHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != MsgResync || h.Flags != 0xA5 || h.Version != 7 || h.Hops != 3 ||
		h.SenderID != m.SenderID || h.Token != m.Token || h.Seq != m.Seq {
		t.Fatalf("decoded header %+v", h)
	}
}

func TestDecodeHeaderRejects(t *testing.T) {
	good, _ := (&Resync{}).Append(nil)
	if _, err := DecodeHeader(good[:HeaderSize-1]); !errors.Is(err, ErrShort) {
		t.Errorf("short header: %v", err)
	}
	bad := bytes.Clone(good)
	bad[0] ^= 1
	if _, err := DecodeHeader(bad); !errors.Is(err, ErrMagic) {
		t.Errorf("bad magic: %v", err)
	}
	bad = bytes.Clone(good)
	bad[5] ^= 1
	if _, err := DecodeHeader(bad); !errors.Is(err, ErrMagic) {
		t.Errorf("bad protocol version: %v", err)
	}
	for _, typ := range []byte{0x00, 0x02, 0x10, 0x12, 0x40, 0x4F, 0x54, 0xFF} {
		bad = bytes.Clone(good)
		bad[6] = typ
		if _, err := DecodeHeader(bad); !errors.Is(err, ErrType) {
			t.Errorf("type %#x: %v", typ, err)
		}
	}
}

func TestAnnounceRoundTrip(t *testing.T) {
	ext, err := (&Delivery{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: netip.MustParseAddr("2001:db8::7"), Port: 9171}).AppendValue(nil)
	if err != nil {
		t.Fatal(err)
	}
	m := &Announce{
		Header: Header{Flags: FlagScopeWanted | FlagSync, Hops: 2, SenderID: 42, Token: 7, Seq: 1000},
		Records: []Record{
			{Topic: topic("tm_a"), Lifetime: 300},
			{Topic: topic("tm_b"), Lifetime: LifetimeWithdraw},
			{Topic: topic("tm_c"), Lifetime: LifetimeDefault, Ext: AppendTLV(nil, ExtDelivery, ext)},
		},
		Ext: AppendTLV(nil, 0x7E, []byte("opaque")),
	}
	b, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAnnounce(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 3 || got.Flags != m.Flags || got.Hops != 2 || got.SenderID != 42 || got.Token != 7 || got.Seq != 1000 {
		t.Fatalf("header %+v", got.Header)
	}
	for i := range m.Records {
		if got.Records[i].Topic != m.Records[i].Topic || got.Records[i].Lifetime != m.Records[i].Lifetime ||
			!bytes.Equal(got.Records[i].Ext, m.Records[i].Ext) {
			t.Fatalf("record %d: %+v", i, got.Records[i])
		}
	}
	tlvs, err := ParseTLVs(got.Records[2].Ext)
	if err != nil || len(tlvs) != 1 || tlvs[0].Type != ExtDelivery {
		t.Fatalf("record extensions: %v %v", tlvs, err)
	}
	d, err := ParseDelivery(tlvs[0].Value)
	if err != nil || d.Port != 9171 || d.Addr != netip.MustParseAddr("2001:db8::7") {
		t.Fatalf("delivery %+v %v", d, err)
	}
	if !bytes.Equal(got.Ext, m.Ext) {
		t.Fatalf("message extensions %x", got.Ext)
	}
}

func TestAnnounceSizeLimit(t *testing.T) {
	m := &Announce{}
	for i := 0; i < MaxRecords; i++ {
		m.Records = append(m.Records, Record{Topic: TopicID{byte(i)}, Lifetime: 1})
	}
	b, err := m.Append(nil)
	if err != nil {
		t.Fatalf("%d records must fit: %v", MaxRecords, err)
	}
	if len(b) > MaxDatagram {
		t.Fatalf("%d bytes exceeds the limit", len(b))
	}
	m.Records = append(m.Records, Record{})
	if _, err := m.Append(nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("one record too many: %v", err)
	}
}

func TestAnnounceMalformed(t *testing.T) {
	m := &Announce{Records: []Record{{Topic: topic("x"), Lifetime: 9, Ext: []byte{1, 2, 3}}}}
	b, _ := m.Append(nil)

	// A count that claims more records than the datagram holds.
	c := bytes.Clone(b)
	binary.BigEndian.PutUint16(c[12:14], 200)
	if _, err := DecodeAnnounce(c); !errors.Is(err, ErrMalformed) {
		t.Errorf("inflated count: %v", err)
	}
	// An extension length that runs past the end.
	c = bytes.Clone(b)
	binary.BigEndian.PutUint16(c[HeaderSize+36:], 400)
	if _, err := DecodeAnnounce(c); !errors.Is(err, ErrMalformed) {
		t.Errorf("inflated extension length: %v", err)
	}
	// A truncated record.
	if _, err := DecodeAnnounce(b[:HeaderSize+20]); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated record: %v", err)
	}
	// The wrong decoder.
	if _, err := DecodeDigest(b); !errors.Is(err, ErrType) {
		t.Errorf("announce as digest: %v", err)
	}
}

func TestDigestRoundTrip(t *testing.T) {
	var d SetDigest
	d.Toggle(topic("a"))
	d.Toggle(topic("b"))
	m := &Digest{Header: Header{SenderID: 9, Token: 8, Seq: 77, Flags: FlagScopeWanted}, Since: 70, SetCount: 2, SetDigest: d}
	b, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != HeaderSize+DigestBodySize {
		t.Fatalf("digest is %d bytes", len(b))
	}
	got, err := DecodeDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Since != 70 || got.SetCount != 2 || got.SetDigest != d || got.Seq != 77 || got.Flags != FlagScopeWanted {
		t.Fatalf("%+v", got)
	}
	if _, err := DecodeDigest(b[:len(b)-1]); !errors.Is(err, ErrShort) {
		t.Errorf("short digest: %v", err)
	}
}

func TestAckRoundTrip(t *testing.T) {
	sc, err := NewScope(shard.DomainBEEF, 6, [16]byte{1, 2, 3}, []uint16{0x1001, 0x1020})
	if err != nil {
		t.Fatal(err)
	}
	ext := AppendTLV(nil, ExtScope, sc.Value())
	ext = AppendNotices(ext, []Notice{{Topic: topic("n"), Status: StatusUnserved}})
	m := &Ack{
		Header:          Header{Result: ResultOK, Flags: FlagNoticesTruncated, SenderID: 5, Token: 6, Seq: 7},
		LastSeq:         7,
		SetCount:        3,
		ScopeGen:        sc.Gen(),
		SetDigest:       SetDigest{0xAA},
		LifetimeMin:     30,
		LifetimeDefault: 300,
		LifetimeMax:     3600,
		Statuses:        []RecordStatus{{Index: 1, Status: StatusNotServed}, {Index: 4, Status: StatusAddressNotHonored}},
		Ext:             ext,
	}
	b, err := m.Append(nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAck(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Result != ResultOK || got.LastSeq != 7 || got.SetCount != 3 || got.ScopeGen != sc.Gen() ||
		got.SetDigest != m.SetDigest || got.LifetimeMin != 30 || got.LifetimeDefault != 300 || got.LifetimeMax != 3600 {
		t.Fatalf("%+v", got)
	}
	if len(got.Statuses) != 2 || got.Statuses[0] != m.Statuses[0] || got.Statuses[1] != m.Statuses[1] {
		t.Fatalf("statuses %+v", got.Statuses)
	}
	tlvs, err := ParseTLVs(got.Ext)
	if err != nil || len(tlvs) != 2 {
		t.Fatalf("extensions %v %v", tlvs, err)
	}
	v, ok := FindTLV(tlvs, ExtScope)
	if !ok {
		t.Fatal("no scope extension")
	}
	back, err := ParseScope(v)
	if err != nil || !back.Equal(sc) || back.Gen() != sc.Gen() {
		t.Fatalf("scope %+v %v", back, err)
	}
	v, _ = FindTLV(tlvs, ExtNotice)
	ns, err := ParseNotices(v)
	if err != nil || len(ns) != 1 || ns[0].Topic != topic("n") || ns[0].Status != StatusUnserved {
		t.Fatalf("notices %+v %v", ns, err)
	}
}

// An answer to a source that has not proven it can receive must not be
// larger than the smallest request, or the receiver would amplify traffic
// toward a spoofed address.
func TestHeaderOnlyAcks(t *testing.T) {
	for _, r := range []Result{ResultToken, ResultVersion} {
		m := &Ack{Header: Header{Result: r, Token: 99, SenderID: 1, Seq: 2}, SetCount: 5, Statuses: []RecordStatus{{Index: 1, Status: StatusOverCap}}}
		b, err := m.Append(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != HeaderSize {
			t.Errorf("%v ack is %d bytes, want the header alone", r, len(b))
		}
		got, err := DecodeAck(b)
		if err != nil || got.Result != r || got.Token != 99 || got.SetCount != 0 || got.Statuses != nil {
			t.Errorf("%v ack decoded as %+v, %v", r, got, err)
		}
	}
	if (&Ack{Header: Header{Result: ResultStale}}).Result.HasBody() != true {
		t.Error("a stale ack carries a body")
	}
}

func TestSetDigest(t *testing.T) {
	var a, b SetDigest
	ts := []TopicID{topic("1"), topic("2"), topic("3"), topic("4")}
	for _, x := range ts {
		a.Toggle(x)
	}
	for i := len(ts) - 1; i >= 0; i-- {
		b.Toggle(ts[i])
	}
	if a != b {
		t.Fatal("the digest depends on order")
	}
	a.Toggle(ts[2])
	if a == b {
		t.Fatal("removing a topic left the digest unchanged")
	}
	a.Toggle(ts[2])
	if a != b {
		t.Fatal("adding the topic back did not restore the digest")
	}
	for _, x := range ts {
		a.Toggle(x)
	}
	if a != (SetDigest{}) {
		t.Fatal("the empty set does not digest to zero")
	}
}

func TestStatusClasses(t *testing.T) {
	for _, s := range []Status{StatusNotServed, StatusOutsideBound, StatusOverCap, StatusRateLimited, StatusUnsupported, StatusBadAddress} {
		if !s.Refused() || s.Held() || s.Served() {
			t.Errorf("%v must be a refusal", s)
		}
	}
	for _, s := range []Status{StatusAddressNotHonored, StatusUnserved, StatusUpstreamRefused} {
		if s.Refused() || !s.Held() {
			t.Errorf("%v must be a note on a held topic", s)
		}
	}
	if !StatusOK.Held() || !StatusOK.Served() || StatusOK.Refused() {
		t.Error("ok must be held and served")
	}
	if StatusUnserved.Served() || StatusUpstreamRefused.Served() || !StatusAddressNotHonored.Served() {
		t.Error("served classification")
	}
	if StatusPending.Refused() || StatusPending.Held() {
		t.Error("pending is neither refused nor held")
	}
}

// The group derivation must agree with the one the edge uses to join and
// route, at every width a plane may have.
func TestGroupIndexAgreesWithPlaneEngine(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for bits := uint(0); bits <= 15; bits++ {
		// Domain 0xE with 15 bits would reach the control plane.
		domains := []uint8{shard.DomainBEEF, 0x2, 0xE}
		for _, domain := range domains {
			if shard.ValidatePlane(domain, bits) != nil {
				continue
			}
			pe, err := shard.NewPlane(0xFF05, 0x000B, bits, domain)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 200; i++ {
				var id TopicID
				for j := range id {
					id[j] = byte(r.Uint32())
				}
				key := [32]byte(id)
				if got, want := uint32(GroupIndex(domain, uint8(bits), id)), pe.GroupIndex(&key); got != want {
					t.Fatalf("domain %#x bits %d: group %#x, plane engine says %#x", domain, bits, got, want)
				}
			}
		}
	}
}

func TestScopeForms(t *testing.T) {
	gen := [16]byte{9}
	all, err := AllScope(shard.DomainBEEF, 8, gen)
	if err != nil {
		t.Fatal(err)
	}
	if !all.Contains(topic("anything")) || !all.All() || all.Groups() != nil {
		t.Fatal("an all scope must contain everything")
	}

	// A short list is sent as a list, a dense one as a bitmap.
	few, _ := NewScope(shard.DomainBEEF, 8, gen, []uint16{0x10FF, 0x1000, 0x1000})
	if got := few.Groups(); len(got) != 2 || got[0] != 0x1000 || got[1] != 0x10FF {
		t.Fatalf("groups %v", got)
	}
	if few.Value()[2]&scopeFlagBitmap != 0 {
		t.Fatal("two groups of 256 must be a list")
	}
	var many []uint16
	for i := 0; i < 200; i++ {
		many = append(many, 0x1000+uint16(i))
	}
	dense, _ := NewScope(shard.DomainBEEF, 8, gen, many)
	if dense.Value()[2]&scopeFlagBitmap == 0 {
		t.Fatal("200 groups of 256 must be a bitmap")
	}
	if len(dense.Value()) != scopeFixedSize+32 {
		t.Fatalf("bitmap scope is %d bytes", len(dense.Value()))
	}

	for _, s := range []*Scope{all, few, dense} {
		back, err := ParseScope(s.Value())
		if err != nil {
			t.Fatal(err)
		}
		if !back.Equal(s) || back.Gen() != s.Gen() || back.Gen() == 0 {
			t.Fatalf("scope did not survive the wire: %+v", back)
		}
	}
	if few.Gen() == dense.Gen() || few.Gen() == all.Gen() {
		t.Fatal("different scopes share a generation value")
	}
	other, _ := NewScope(shard.DomainBEEF, 8, [16]byte{10}, []uint16{0x1000, 0x10FF})
	if other.Gen() == few.Gen() {
		t.Fatal("a new plane generation must change the scope generation")
	}
}

func TestScopeContains(t *testing.T) {
	const bits = 4
	gen := [16]byte{}
	// Deliver the even groups only.
	var groups []uint16
	for i := uint16(0); i < 16; i += 2 {
		groups = append(groups, 0x1000+i)
	}
	sc, err := NewScope(shard.DomainBEEF, bits, gen, groups)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		id := topic(string(rune('a'+i%26)) + string(rune(i)))
		g := GroupIndex(shard.DomainBEEF, bits, id)
		if sc.GroupOf(id) != g {
			t.Fatal("GroupOf disagrees with GroupIndex")
		}
		if got, want := sc.Contains(id), g%2 == 0; got != want {
			t.Fatalf("topic in group %#x: contains %v", g, got)
		}
	}
	empty, _ := NewScope(shard.DomainBEEF, bits, gen, nil)
	if empty.Contains(topic("x")) || empty.All() || empty.Groups() == nil {
		t.Fatal("an empty scope contains nothing and is not the all scope")
	}
	one, _ := AllScope(shard.DomainBEEF, 0, gen)
	if one.GroupOf(topic("x")) != 0x1000 {
		t.Fatal("a plane of width zero has one group, its base")
	}
	single, _ := NewScope(shard.DomainBEEF, 0, gen, []uint16{0x1000})
	if !single.Contains(topic("x")) {
		t.Fatal("the single group of a zero-width plane")
	}
}

func TestScopeRejects(t *testing.T) {
	if _, err := NewScope(shard.DomainBEEF, 4, [16]byte{}, []uint16{0x1010}); err == nil {
		t.Error("a group past the plane's width")
	}
	if _, err := NewScope(shard.DomainBEEF, 4, [16]byte{}, []uint16{0x0001}); err == nil {
		t.Error("a group of another plane")
	}
	if _, err := NewScope(0xF, 4, [16]byte{}, nil); err == nil {
		t.Error("the forbidden domain")
	}
	// Eight bits, so that two groups are sent as a list.
	good, _ := NewScope(shard.DomainBEEF, 8, [16]byte{}, []uint16{0x1001, 0x1002})
	v := bytes.Clone(good.Value())
	if _, err := ParseScope(v[:len(v)-1]); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated list: %v", err)
	}
	// Descending groups.
	binary.BigEndian.PutUint16(v[scopeFixedSize:], 0x1002)
	binary.BigEndian.PutUint16(v[scopeFixedSize+2:], 0x1001)
	if _, err := ParseScope(v); !errors.Is(err, ErrMalformed) {
		t.Errorf("descending groups: %v", err)
	}
	// A bitmap of the wrong length, and one with a bit past the plane.
	narrow, _ := NewScope(shard.DomainBEEF, 2, [16]byte{}, []uint16{0x1001, 0x1002})
	v = bytes.Clone(narrow.Value())
	if v[2]&scopeFlagBitmap == 0 || len(v) != scopeFixedSize+1 {
		t.Fatalf("two groups of four must be a one-byte bitmap, got %x", v)
	}
	if _, err := ParseScope(append(bytes.Clone(v), 0)); !errors.Is(err, ErrMalformed) {
		t.Errorf("bitmap one byte too long: %v", err)
	}
	v[scopeFixedSize] |= 0x80
	if _, err := ParseScope(v); !errors.Is(err, ErrMalformed) {
		t.Errorf("bitmap bit past the plane: %v", err)
	}
	all, _ := AllScope(shard.DomainBEEF, 4, [16]byte{})
	v = append(bytes.Clone(all.Value()), 0x10, 0x00)
	if _, err := ParseScope(v); !errors.Is(err, ErrMalformed) {
		t.Errorf("all with a trailing list: %v", err)
	}
}

func TestScopeTooLargeToAdvertise(t *testing.T) {
	// Half of a 15-bit plane is neither a short list nor a small bitmap.
	var groups []uint16
	for i := 0; i < 1<<15; i += 2 {
		groups = append(groups, 0x1000+uint16(i))
	}
	sc, err := NewScope(shard.DomainBEEF, 15, [16]byte{}, groups)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Value() != nil {
		t.Fatalf("a %d-group scope must not be advertised", len(groups))
	}
	if sc.Gen() == 0 {
		t.Fatal("it still has a generation value")
	}
	if !sc.Contains(TopicID{0x00, 0x00}) || sc.Contains(TopicID{0x00, 0x02}) {
		t.Fatal("membership must still work")
	}
}

func TestUnionScope(t *testing.T) {
	gen := [16]byte{1}
	a, _ := NewScope(shard.DomainBEEF, 4, gen, []uint16{0x1000, 0x1001})
	b, _ := NewScope(shard.DomainBEEF, 4, gen, []uint16{0x1001, 0x1005})
	u := UnionScope([]*Scope{a, b})
	if got := u.Groups(); len(got) != 3 || got[0] != 0x1000 || got[1] != 0x1001 || got[2] != 0x1005 {
		t.Fatalf("union %v", got)
	}
	all, _ := AllScope(shard.DomainBEEF, 4, gen)
	if u := UnionScope([]*Scope{a, all}); u == nil || !u.All() {
		t.Fatal("a union with an all scope is all")
	}
	if UnionScope([]*Scope{a, nil}) != nil {
		t.Fatal("an unknown upstream makes the union unknown")
	}
	wider, _ := NewScope(shard.DomainBEEF, 5, gen, []uint16{0x1000})
	if UnionScope([]*Scope{a, wider}) != nil {
		t.Fatal("upstreams at different widths have no union")
	}
	if UnionScope(nil) != nil {
		t.Fatal("no upstreams, no scope")
	}
}

func TestDeliveryForms(t *testing.T) {
	cases := []Delivery{
		{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: netip.MustParseAddr("192.0.2.7"), Port: 9171},
		{Kind: DeliverUnicast, Encoding: EncodeRecords, Addr: netip.MustParseAddr("2001:db8::7"), Port: 9171},
		{Kind: DeliverMulticast, Encoding: EncodeFrames, Addr: netip.MustParseAddr("ff05::1:2"), Port: 9001},
		{Kind: DeliverMulticast, Encoding: EncodeFrames, Addr: netip.MustParseAddr("239.1.2.3"), Port: 9001},
		{Kind: DeliverMulticastSSM, Encoding: EncodeFrames, Addr: netip.MustParseAddr("ff35::1:2"), Port: 9001, Source: netip.MustParseAddr("2001:db8::1")},
		{Kind: DeliverMulticastSSM, Encoding: EncodeFrames, Addr: netip.MustParseAddr("232.1.2.3"), Port: 9001, Source: netip.MustParseAddr("192.0.2.1")},
	}
	wantLen := []int{10, 22, 22, 10, 38, 14}
	for i, c := range cases {
		v, err := c.AppendValue(nil)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if len(v) != wantLen[i] {
			t.Errorf("case %d: %d bytes, want %d", i, len(v), wantLen[i])
		}
		back, err := ParseDelivery(v)
		if err != nil || *back != c {
			t.Errorf("case %d: %+v %v", i, back, err)
		}
		a := Assignment{Topic: topic("t"), Delivery: c}
		av, err := a.AppendValue(nil)
		if err != nil {
			t.Fatal(err)
		}
		ab, err := ParseAssignment(av)
		if err != nil || *ab != a {
			t.Errorf("case %d assignment: %+v %v", i, ab, err)
		}
	}
	bad := []Delivery{
		{Kind: DeliverUnicast, Addr: netip.MustParseAddr("ff05::1")},
		{Kind: DeliverMulticast, Addr: netip.MustParseAddr("2001:db8::1")},
		{Kind: DeliverMulticastSSM, Addr: netip.MustParseAddr("ff35::1")},
		{Kind: DeliverMulticastSSM, Addr: netip.MustParseAddr("ff35::1"), Source: netip.MustParseAddr("192.0.2.1")},
		{Kind: 9, Addr: netip.MustParseAddr("2001:db8::1")},
		{Kind: DeliverUnicast},
	}
	for i, c := range bad {
		if _, err := c.AppendValue(nil); err == nil {
			t.Errorf("bad case %d was accepted", i)
		}
	}
	v, _ := cases[1].AppendValue(nil)
	if _, err := ParseDelivery(append(v, 0)); !errors.Is(err, ErrMalformed) {
		t.Errorf("trailing byte: %v", err)
	}
	if _, err := ParseDelivery(v[:len(v)-1]); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated address: %v", err)
	}
}

func TestTLVs(t *testing.T) {
	b := AppendTLV(nil, 1, []byte{0xAA})
	b = AppendTLV(b, 0x90, nil)
	b = AppendTLV(b, 2, bytes.Repeat([]byte{0x55}, 300))
	tlvs, err := ParseTLVs(b)
	if err != nil || len(tlvs) != 3 || tlvs[0].Type != 1 || tlvs[1].Type != 0x90 || len(tlvs[1].Value) != 0 || len(tlvs[2].Value) != 300 {
		t.Fatalf("%v %v", tlvs, err)
	}
	if _, err := ParseTLVs(b[:len(b)-1]); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated value: %v", err)
	}
	if _, err := ParseTLVs(b[:2]); !errors.Is(err, ErrMalformed) {
		t.Errorf("truncated header: %v", err)
	}
	if out, err := ParseTLVs(nil); err != nil || out != nil {
		t.Errorf("empty area: %v %v", out, err)
	}
}
