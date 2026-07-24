package frame

import (
	"errors"
	"testing"
)

func domainsManifest() *ShardManifest {
	m := &ShardManifest{
		Flags: ShardManifestFlagAuthoritative | ShardManifestFlagGroupsValid |
			ShardManifestFlagDomainsValid,
		InstanceID:       0xC0FFEE,
		Epoch:            7,
		TTL:              90,
		AnnounceInterval: 30,
		ShardBits:        8,
		RoleHint:         RoleHintListenerBEEF,
		Groups:           []uint16{0, 1, 2},
	}
	for i := range m.SrcIPv6 {
		m.SrcIPv6[i] = byte(i)
	}
	for i := range m.GenerationID {
		m.GenerationID[i] = byte(0x40 + i)
	}
	beef := DomainDescriptor{
		DomainID:  0x1,
		ShardBits: 12,
		SlotSpan:  1,
		Flags:     DomainFlagSourceModeSSM | DomainFlagActive,
	}
	for i := range beef.GenerationID {
		beef.GenerationID[i] = byte(0xB0 + i)
	}
	m.Domains = []DomainDescriptor{beef}
	return m
}

func encodeManifest(t *testing.T, m *ShardManifest) []byte {
	t.Helper()
	buf := make([]byte, ShardManifestSize(m))
	n, err := EncodeShardManifest(m, buf)
	if err != nil {
		t.Fatalf("EncodeShardManifest: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("wrote %d, want %d", n, len(buf))
	}
	return buf
}

func TestDomainsFlagBit(t *testing.T) {
	if ShardManifestFlagDomainsValid != 1<<7 {
		t.Fatalf("DomainsValid = 0x%02X, want 0x80", ShardManifestFlagDomainsValid)
	}
	if RoleHintProducerBEEF != 6 || RoleHintListenerBEEF != 7 {
		t.Fatal("BRC-148 RoleHint values wrong")
	}
}

func TestDomainsRoundTrip(t *testing.T) {
	m := domainsManifest()
	// Add a second descriptor carrying a per-domain successor.
	d2 := DomainDescriptor{
		DomainID:  0x2,
		ShardBits: 4,
		SlotSpan:  1,
		Flags:     DomainFlagActive | DomainFlagSuccessorValid,
		Successor: &SuccessorBlock{ShardBits: 5, Flags: SuccessorFlagSourceModeSSM, TransitionEpoch: 1234},
	}
	for i := range d2.Successor.GenerationID {
		d2.Successor.GenerationID[i] = byte(0xD0 + i)
	}
	m.Domains = append(m.Domains, d2)

	buf := encodeManifest(t, m)
	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("DecodeShardManifest: %v", err)
	}
	if len(got.Domains) != 2 {
		t.Fatalf("decoded %d domains, want 2", len(got.Domains))
	}
	b := got.Domains[0]
	if b.DomainID != 0x1 || b.ShardBits != 12 || b.SlotSpan != 1 ||
		b.Flags != (DomainFlagSourceModeSSM|DomainFlagActive) || b.Version != 0 ||
		b.GenerationID != m.Domains[0].GenerationID || b.Successor != nil {
		t.Errorf("beef descriptor mismatch: %+v", b)
	}
	s := got.Domains[1].Successor
	if s == nil || s.ShardBits != 5 || s.Flags != SuccessorFlagSourceModeSSM ||
		s.TransitionEpoch != 1234 || s.GenerationID != d2.Successor.GenerationID {
		t.Errorf("per-domain successor mismatch: %+v", s)
	}
}

func TestDomainsBackCompat(t *testing.T) {
	// A manifest without the flag decodes with nil Domains, and trailing
	// size/CRC math is unchanged (BRC-139-only consumers stay correct).
	m := domainsManifest()
	m.Flags &^= ShardManifestFlagDomainsValid
	m.Domains = nil
	buf := encodeManifest(t, m)
	got, err := DecodeShardManifest(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Domains != nil {
		t.Fatal("Domains non-nil without DomainsValid")
	}
}

func TestDomainsCoherence(t *testing.T) {
	m := domainsManifest()
	m.Domains = nil // flag set, no descriptors
	buf := make([]byte, 256)
	if _, err := EncodeShardManifest(m, buf); !errors.Is(err, ErrShardManifestBadDomains) {
		t.Errorf("DomainsValid without descriptors: %v", err)
	}

	m2 := domainsManifest()
	m2.Flags &^= ShardManifestFlagDomainsValid // descriptors without flag
	if _, err := EncodeShardManifest(m2, buf); !errors.Is(err, ErrShardManifestBadDomains) {
		t.Errorf("descriptors without DomainsValid: %v", err)
	}
}

func TestDomainsValidationTable(t *testing.T) {
	gen := func(mut func(m *ShardManifest)) error {
		m := domainsManifest()
		mut(m)
		buf := make([]byte, 1024)
		_, err := EncodeShardManifest(m, buf)
		return err
	}
	cases := []struct {
		name string
		mut  func(m *ShardManifest)
		ok   bool
	}{
		{"wide beef plane bits 15 span 8", func(m *ShardManifest) {
			m.Domains[0].ShardBits = 15
			m.Domains[0].SlotSpan = 8
		}, true},
		{"domain 0x0F forbidden", func(m *ShardManifest) { m.Domains[0].DomainID = 0x0F }, false},
		{"duplicate DomainID", func(m *ShardManifest) {
			m.Domains = append(m.Domains, m.Domains[0])
		}, false},
		{"bits 15 with implied-span-violating SlotSpan", func(m *ShardManifest) {
			m.Domains[0].ShardBits = 15 // implies span 8
			m.Domains[0].SlotSpan = 1
		}, false},
		{"slot overlap via SlotSpan", func(m *ShardManifest) {
			m.Domains[0].SlotSpan = 2 // reserves 0x1 and 0x2
			d := DomainDescriptor{DomainID: 0x2, ShardBits: 4, SlotSpan: 1}
			m.Domains = append(m.Domains, d)
		}, false},
		{"top domain slot span past 0xE", func(m *ShardManifest) {
			m.Domains[0].DomainID = 0x0E
			m.Domains[0].SlotSpan = 2
		}, false},
		{"domain-0 agreement ok", func(m *ShardManifest) {
			d0 := DomainDescriptor{DomainID: 0, ShardBits: m.ShardBits, SlotSpan: 1,
				GenerationID: m.GenerationID}
			m.Domains = append(m.Domains, d0)
		}, true},
		{"domain-0 bits disagreement", func(m *ShardManifest) {
			d0 := DomainDescriptor{DomainID: 0, ShardBits: m.ShardBits + 1, SlotSpan: 1,
				GenerationID: m.GenerationID}
			m.Domains = append(m.Domains, d0)
		}, false},
		{"domain-0 generation disagreement", func(m *ShardManifest) {
			d0 := DomainDescriptor{DomainID: 0, ShardBits: m.ShardBits, SlotSpan: 1}
			m.Domains = append(m.Domains, d0)
		}, false},
		{"successor without authoritative", func(m *ShardManifest) {
			m.Flags &^= ShardManifestFlagAuthoritative
			m.Domains[0].Flags |= DomainFlagSuccessorValid
			m.Domains[0].Successor = &SuccessorBlock{ShardBits: 11}
		}, false},
		{"successor bits jump 2", func(m *ShardManifest) {
			m.Domains[0].Flags |= DomainFlagSuccessorValid
			m.Domains[0].Successor = &SuccessorBlock{ShardBits: 10} // active 12
		}, false},
		{"successor flag without block", func(m *ShardManifest) {
			m.Domains[0].Flags |= DomainFlagSuccessorValid
		}, false},
	}
	for _, c := range cases {
		err := gen(c.mut)
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrShardManifestBadDomains) {
			t.Errorf("%s: err = %v, want ErrShardManifestBadDomains", c.name, err)
		}
	}
}

func TestDomainsDecodeGuards(t *testing.T) {
	m := domainsManifest()
	buf := encodeManifest(t, m)

	// CRC covers the Domains section.
	tamper := append([]byte(nil), buf...)
	tamper[len(tamper)-1] ^= 0xFF // last byte = descriptor generation tail
	if _, err := DecodeShardManifest(tamper); !errors.Is(err, ErrShardManifestBadCRC) {
		t.Errorf("tampered domains byte: err = %v, want ErrShardManifestBadCRC", err)
	}

	// Truncated mid-section.
	if _, err := DecodeShardManifest(buf[:len(buf)-4]); !errors.Is(err, ErrShardManifestTruncated) {
		t.Errorf("truncated: err = %v, want ErrShardManifestTruncated", err)
	}

	// Count byte of zero is malformed (DomainsValid=1 && DomainCount=0).
	zero := append([]byte(nil), buf...)
	countOff := len(zero) - 1 - DomainDescriptorSize // count precedes the single descriptor
	zero[countOff] = 0
	if _, err := DecodeShardManifest(zero); !errors.Is(err, ErrShardManifestBadDomains) {
		t.Errorf("zero count: err = %v, want ErrShardManifestBadDomains", err)
	}
}
