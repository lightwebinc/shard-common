package manifest_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lightwebinc/shard-common/frame"
	"github.com/lightwebinc/shard-common/manifest"
)

// TestIntegration_WireRoundTrip exercises the full BRC-137 pipeline end
// to end without external infrastructure: encode a manifest, send it
// across a loopback UDP socket, receive and decode it, upsert into a
// registry, and confirm the evaluator adopts the value after quorum +
// hysteresis. Posture-agnostic at the wire level; the same code path
// runs under Postures A (ASM) and C (SSM) since the manifest format is
// identical — only the kernel multicast filter differs.
func TestIntegration_WireRoundTrip(t *testing.T) {
	// 1. Stand up a loopback UDP socket pair: sender → receiver.
	addr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("udp6 loopback unavailable: %v", err)
	}
	recv, err := net.ListenUDP("udp6", addr)
	if err != nil {
		t.Skipf("ListenUDP: %v", err)
	}
	defer func() { _ = recv.Close() }()

	send, err := net.DialUDP("udp6", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Skipf("DialUDP: %v", err)
	}
	defer func() { _ = send.Close() }()

	// 2. Wire a Registry + Evaluator on the receive side. Run in a
	// background goroutine that reads each datagram and Upserts into
	// the registry.
	reg := manifest.NewRegistry(60 * time.Second)
	ev := manifest.NewEvaluator(manifest.EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = recv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, src, err := recv.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if n < 7 || buf[6] != frame.MsgTypeShardManifest {
				continue
			}
			m, err := frame.DecodeShardManifest(buf[:n])
			if err != nil {
				continue
			}
			srcAddr, ok := netip.AddrFromSlice(src.IP.To16())
			if !ok {
				continue
			}
			reg.Upsert(srcAddr, m)
		}
	}()

	// 3. Send two distinct authoritative manifests carrying the same
	// ShardBits=8 — should reach quorum and be adopted.
	mk := func(id uint32) *frame.ShardManifest {
		return &frame.ShardManifest{
			Flags:            frame.ShardManifestFlagAuthoritative | frame.ShardManifestFlagGroupsValid | frame.ShardManifestFlagPilotOnly,
			InstanceID:       id,
			Epoch:            uint32(time.Now().Unix()),
			AnnounceInterval: 300,
			ShardBits:        8,
			RoleHint:         frame.RoleHintManifestOnly,
			Groups:           []uint16{0, 1, 2, 3},
		}
	}
	for _, id := range []uint32{0xAAAA0001, 0xAAAA0002} {
		m := mk(id)
		buf := make([]byte, frame.ShardManifestSize(m))
		n, err := frame.EncodeShardManifest(m, buf)
		if err != nil {
			t.Fatalf("Encode(%d): %v", id, err)
		}
		if _, err := send.Write(buf[:n]); err != nil {
			t.Fatalf("Write(%d): %v", id, err)
		}
	}

	// 4. Poll the evaluator for adoption. The receive goroutine should
	// have upserted both manifests by now; quorum=2 with hysteresis=1ns
	// makes adoption near-immediate on the second Evaluate call.
	var adopted manifest.Adopted
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// Both source IPs are the same loopback (127.0.0.1 or ::1),
		// but distinct InstanceIDs satisfy the (SrcIPv6, InstanceID)
		// keying — we should see at least one entry once the read
		// goroutine has processed both writes.
		if reg.Len() >= 1 {
			_ = ev.Evaluate(reg.Snapshot()) // first call records timestamp
			time.Sleep(2 * time.Millisecond)
			adopted = ev.Evaluate(reg.Snapshot())
			if adopted.QuorumMet["shard_bits"] && adopted.ShardBits == 8 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Both manifests come from the SAME UDP source addr (loopback); the
	// registry keys on (SrcIPv6, InstanceID). Distinct InstanceIDs
	// produce two entries, hence quorum is reachable.
	if reg.Len() < 2 {
		t.Fatalf("registry only saw %d entries; expected 2", reg.Len())
	}
	if !adopted.QuorumMet["shard_bits"] {
		t.Fatalf("quorum never met; adopted=%+v", adopted)
	}
	if adopted.ShardBits != 8 {
		t.Errorf("ShardBits = %d, want 8", adopted.ShardBits)
	}
	if len(adopted.PilotGroups) != 4 {
		t.Errorf("PilotGroups len = %d, want 4", len(adopted.PilotGroups))
	}

	cancel()
	wg.Wait()
}

// TestIntegration_SuccessorPipelineAdopts exercises the bridging-mode
// signal flow: an authoritative manifest carries a Successor block, and
// the evaluator surfaces a Successor view after quorum is satisfied.
func TestIntegration_SuccessorPipelineAdopts(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("udp6 loopback unavailable: %v", err)
	}
	recv, err := net.ListenUDP("udp6", addr)
	if err != nil {
		t.Skipf("ListenUDP: %v", err)
	}
	defer func() { _ = recv.Close() }()
	send, err := net.DialUDP("udp6", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Skipf("DialUDP: %v", err)
	}
	defer func() { _ = send.Close() }()

	reg := manifest.NewRegistry(60 * time.Second)
	ev := manifest.NewEvaluator(manifest.EvaluatorConfig{
		Quorum:     2,
		Hysteresis: 1 * time.Nanosecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = recv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, src, err := recv.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if n < 7 || buf[6] != frame.MsgTypeShardManifest {
				continue
			}
			m, err := frame.DecodeShardManifest(buf[:n])
			if err != nil {
				continue
			}
			srcAddr, _ := netip.AddrFromSlice(src.IP.To16())
			reg.Upsert(srcAddr, m)
		}
	}()

	successorEpoch := uint32(time.Now().Add(1 * time.Hour).Unix())
	mk := func(id uint32) *frame.ShardManifest {
		m := &frame.ShardManifest{
			Flags: frame.ShardManifestFlagAuthoritative |
				frame.ShardManifestFlagGroupsValid |
				frame.ShardManifestFlagPilotOnly |
				frame.ShardManifestFlagSuccessorValid,
			InstanceID:       id,
			Epoch:            uint32(time.Now().Unix()),
			AnnounceInterval: 300,
			ShardBits:        8,
			Groups:           []uint16{0, 1},
			Successor: &frame.SuccessorBlock{
				ShardBits:       9, // +1 from active
				Flags:           frame.SuccessorFlagSourceModeSSM,
				TransitionEpoch: successorEpoch,
			},
		}
		copy(m.Successor.GenerationID[:], []byte("successor-gen-id"))
		return m
	}
	for _, id := range []uint32{0xBBBB0001, 0xBBBB0002} {
		m := mk(id)
		buf := make([]byte, frame.ShardManifestSize(m))
		n, err := frame.EncodeShardManifest(m, buf)
		if err != nil {
			t.Fatalf("Encode(%d): %v", id, err)
		}
		if _, err := send.Write(buf[:n]); err != nil {
			t.Fatalf("Write(%d): %v", id, err)
		}
	}

	var adopted manifest.Adopted
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if reg.Len() >= 2 {
			_ = ev.Evaluate(reg.Snapshot())
			time.Sleep(2 * time.Millisecond)
			adopted = ev.Evaluate(reg.Snapshot())
			if adopted.Successor != nil {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	if adopted.Successor == nil {
		t.Fatalf("Successor never adopted; adopted=%+v", adopted)
	}
	if adopted.Successor.ShardBits != 9 {
		t.Errorf("Successor.ShardBits = %d, want 9", adopted.Successor.ShardBits)
	}
	if !adopted.Successor.SourceModeSSM {
		t.Errorf("Successor.SourceModeSSM = false, want true")
	}
	if adopted.Successor.TransitionEpoch != successorEpoch {
		t.Errorf("Successor.TransitionEpoch = %d, want %d", adopted.Successor.TransitionEpoch, successorEpoch)
	}

	cancel()
	wg.Wait()
}
