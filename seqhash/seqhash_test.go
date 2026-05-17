package seqhash

import (
	"testing"
)

func TestHashDeterministic(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	var sub [32]byte

	h1 := Hash(ip, 0, sub)
	h2 := Hash(ip, 0, sub)
	if h1 != h2 {
		t.Errorf("Hash not deterministic: %x != %x", h1, h2)
	}
}

func TestHashStableSameFlow(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	var sub [32]byte

	h1 := Hash(ip, 0, sub)
	h2 := Hash(ip, 0, sub)
	if h1 != h2 {
		t.Errorf("Hash not stable for same flow: %x != %x", h1, h2)
	}
}

func TestHashDifferentGroups(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	var sub [32]byte

	h1 := Hash(ip, 0, sub)
	h2 := Hash(ip, 1, sub)
	if h1 == h2 {
		t.Errorf("Hash(group=0) == Hash(group=1): collision at %x", h1)
	}
}

func TestHashDifferentSenders(t *testing.T) {
	var ip1, ip2 [16]byte
	copy(ip1[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	copy(ip2[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25})

	var sub [32]byte
	h1 := Hash(ip1, 0, sub)
	h2 := Hash(ip2, 0, sub)
	if h1 == h2 {
		t.Errorf("Hash(sender1) == Hash(sender2): collision at %x", h1)
	}
}

func TestHashDifferentSubtrees(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	var subA, subB [32]byte
	subA[0] = 0xAA
	subB[0] = 0xBB

	h1 := Hash(ip, 0, subA)
	h2 := Hash(ip, 0, subB)
	if h1 == h2 {
		t.Errorf("Hash(subtreeA) == Hash(subtreeB): collision at %x", h1)
	}
}

func TestHashFlowIsolation(t *testing.T) {
	var ip [16]byte
	copy(ip[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	var subA, subB, subC [32]byte
	subA[0] = 0x01
	subB[0] = 0x02
	subC[0] = 0x03

	h0 := Hash(ip, 0, subA)
	h1 := Hash(ip, 1, subA)
	h2 := Hash(ip, 0, subB)
	h3 := Hash(ip, 0, subC)

	if h0 == h1 || h0 == h2 || h0 == h3 || h1 == h2 {
		t.Error("different flows produced the same HashKey")
	}
	t.Logf("flow keys: grp0/subA=%x grp1/subA=%x grp0/subB=%x grp0/subC=%x", h0, h1, h2, h3)
}

func BenchmarkHash(b *testing.B) {
	var ip [16]byte
	copy(ip[:], []byte{0xfd, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24})
	var sub [32]byte
	b.ResetTimer()
	for range b.N {
		_ = Hash(ip, 0, sub)
	}
}
