package frame_test

import (
	"bytes"
	"testing"

	"github.com/lightwebinc/bitcoin-shard-common/frame"
)

// makeSubtreeDataFrame returns a SubtreeDataFrame with known fields.
func makeSubtreeDataFrame(msgType byte, payloadLen int) (*frame.SubtreeDataFrame, []byte) {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i & 0xFF)
	}
	sf := &frame.SubtreeDataFrame{
		MsgType: msgType,
		HashKey: 0xDEADBEEFCAFEBABE,
		SeqNum:  42,
		Payload: payload,
	}
	for i := range sf.SubtreeID {
		sf.SubtreeID[i] = byte(i + 1)
	}
	return sf, payload
}

func TestEncodeDecodeSubtreeDataFrame_HashesOnly(t *testing.T) {
	sf, _ := makeSubtreeDataFrame(frame.SubtreeMsgHashesOnly, 64)
	buf := make([]byte, frame.HeaderSize+len(sf.Payload))
	n, err := frame.EncodeSubtreeData(sf, buf)
	if err != nil {
		t.Fatalf("EncodeSubtreeData: %v", err)
	}
	if n != len(buf) {
		t.Fatalf("EncodeSubtreeData: wrote %d bytes, want %d", n, len(buf))
	}

	got, err := frame.DecodeSubtreeData(buf)
	if err != nil {
		t.Fatalf("DecodeSubtreeData: %v", err)
	}
	if got.MsgType != sf.MsgType {
		t.Errorf("MsgType: got 0x%02X, want 0x%02X", got.MsgType, sf.MsgType)
	}
	if got.SubtreeID != sf.SubtreeID {
		t.Errorf("SubtreeID mismatch")
	}
	if got.HashKey != sf.HashKey {
		t.Errorf("HashKey: got %d, want %d", got.HashKey, sf.HashKey)
	}
	if got.SeqNum != sf.SeqNum {
		t.Errorf("SeqNum: got %d, want %d", got.SeqNum, sf.SeqNum)
	}
	if !bytes.Equal(got.Payload, sf.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestEncodeDecodeSubtreeDataFrame_FullNodes(t *testing.T) {
	sf, _ := makeSubtreeDataFrame(frame.SubtreeMsgFullNodes, 128)
	buf := make([]byte, frame.HeaderSize+len(sf.Payload))
	_, err := frame.EncodeSubtreeData(sf, buf)
	if err != nil {
		t.Fatalf("EncodeSubtreeData: %v", err)
	}
	got, err := frame.DecodeSubtreeData(buf)
	if err != nil {
		t.Fatalf("DecodeSubtreeData: %v", err)
	}
	if got.MsgType != frame.SubtreeMsgFullNodes {
		t.Errorf("MsgType: got 0x%02X, want 0x%02X", got.MsgType, frame.SubtreeMsgFullNodes)
	}
}

func TestDecodeSubtreeData_WireLayout(t *testing.T) {
	sf, _ := makeSubtreeDataFrame(frame.SubtreeMsgHashesOnly, 0)
	buf := make([]byte, frame.HeaderSize)
	_, err := frame.EncodeSubtreeData(sf, buf)
	if err != nil {
		t.Fatalf("EncodeSubtreeData: %v", err)
	}

	if buf[6] != frame.FrameVerV5 {
		t.Errorf("byte[6] FrameVer: got 0x%02X, want 0x05", buf[6])
	}
	if buf[7] != frame.SubtreeMsgHashesOnly {
		t.Errorf("byte[7] MsgType: got 0x%02X, want 0x%02X", buf[7], frame.SubtreeMsgHashesOnly)
	}
	if !bytes.Equal(buf[8:40], sf.SubtreeID[:]) {
		t.Errorf("bytes[8:40] SubtreeID mismatch")
	}
	for i := 56; i < 88; i++ {
		if buf[i] != 0 {
			t.Errorf("byte[%d] LayoutPad32: got 0x%02X, want 0x00", i, buf[i])
		}
	}
}

func TestIsSubtreeDataFrame(t *testing.T) {
	sf, _ := makeSubtreeDataFrame(frame.SubtreeMsgHashesOnly, 0)
	buf := make([]byte, frame.HeaderSize)
	_, _ = frame.EncodeSubtreeData(sf, buf)

	if !frame.IsSubtreeDataFrame(buf) {
		t.Error("IsSubtreeDataFrame: expected true for V5 frame")
	}
	buf[6] = frame.FrameVerV2
	if frame.IsSubtreeDataFrame(buf) {
		t.Error("IsSubtreeDataFrame: expected false for V2 frame")
	}
}

func TestDecodeSubtreeData_Errors(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func([]byte)
	}{
		{"too short", func(b []byte) { b = b[:10]; _ = b }},
		{"bad magic", func(b []byte) { b[0] = 0xFF }},
		{"bad ver", func(b []byte) { b[6] = 0x02 }},
		{"bad msgtype", func(b []byte) { b[7] = 0xFF }},
	}

	sf, _ := makeSubtreeDataFrame(frame.SubtreeMsgHashesOnly, 0)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, frame.HeaderSize)
			_, _ = frame.EncodeSubtreeData(sf, buf)
			if tc.name == "too short" {
				_, err := frame.DecodeSubtreeData(buf[:10])
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			tc.corrupt(buf)
			_, err := frame.DecodeSubtreeData(buf)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestEncodeDecodeSubtreeDataPayload_HashesOnly(t *testing.T) {
	p := &frame.SubtreeDataPayload{
		TotalFees:      1_000_000,
		TotalSizeBytes: 50_000,
		Nodes: []frame.SubtreeNode{
			{TxHash: [32]byte{1, 2, 3}},
			{TxHash: [32]byte{4, 5, 6}},
		},
		ConflictHashes: [][32]byte{{0xAA}},
	}

	enc, err := frame.EncodeSubtreeDataPayload(p, frame.SubtreeMsgHashesOnly)
	if err != nil {
		t.Fatalf("EncodeSubtreeDataPayload: %v", err)
	}

	got, err := frame.DecodeSubtreeDataPayload(enc, frame.SubtreeMsgHashesOnly)
	if err != nil {
		t.Fatalf("DecodeSubtreeDataPayload: %v", err)
	}
	if got.TotalFees != p.TotalFees {
		t.Errorf("TotalFees: got %d, want %d", got.TotalFees, p.TotalFees)
	}
	if got.TotalSizeBytes != p.TotalSizeBytes {
		t.Errorf("TotalSizeBytes: got %d, want %d", got.TotalSizeBytes, p.TotalSizeBytes)
	}
	if len(got.Nodes) != len(p.Nodes) {
		t.Fatalf("Nodes len: got %d, want %d", len(got.Nodes), len(p.Nodes))
	}
	if got.Nodes[0].TxHash != p.Nodes[0].TxHash {
		t.Errorf("Nodes[0].TxHash mismatch")
	}
	if got.Nodes[0].Fee != 0 || got.Nodes[0].Size != 0 {
		t.Errorf("HashesOnly: Fee/Size should be zero")
	}
	if len(got.ConflictHashes) != 1 || got.ConflictHashes[0] != p.ConflictHashes[0] {
		t.Errorf("ConflictHashes mismatch")
	}
}

func TestEncodeDecodeSubtreeDataPayload_FullNodes(t *testing.T) {
	p := &frame.SubtreeDataPayload{
		TotalFees:      9_999,
		TotalSizeBytes: 8_888,
		Nodes: []frame.SubtreeNode{
			{TxHash: [32]byte{10}, Fee: 500, Size: 250},
			{TxHash: [32]byte{20}, Fee: 750, Size: 375},
		},
		ConflictHashes: nil,
	}

	enc, err := frame.EncodeSubtreeDataPayload(p, frame.SubtreeMsgFullNodes)
	if err != nil {
		t.Fatalf("EncodeSubtreeDataPayload: %v", err)
	}

	got, err := frame.DecodeSubtreeDataPayload(enc, frame.SubtreeMsgFullNodes)
	if err != nil {
		t.Fatalf("DecodeSubtreeDataPayload: %v", err)
	}
	if len(got.Nodes) != 2 {
		t.Fatalf("Nodes len: got %d, want 2", len(got.Nodes))
	}
	if got.Nodes[0].Fee != 500 || got.Nodes[0].Size != 250 {
		t.Errorf("Nodes[0]: Fee=%d Size=%d, want 500 250", got.Nodes[0].Fee, got.Nodes[0].Size)
	}
	if got.Nodes[1].Fee != 750 || got.Nodes[1].Size != 375 {
		t.Errorf("Nodes[1]: Fee=%d Size=%d, want 750 375", got.Nodes[1].Fee, got.Nodes[1].Size)
	}
	if len(got.ConflictHashes) != 0 {
		t.Errorf("ConflictHashes: got %d, want 0", len(got.ConflictHashes))
	}
}

func TestSubtreeDataPayloadSizes(t *testing.T) {
	const oneMillion = 1 << 20
	p := &frame.SubtreeDataPayload{
		Nodes:          make([]frame.SubtreeNode, oneMillion),
		ConflictHashes: nil,
	}

	enc, err := frame.EncodeSubtreeDataPayload(p, frame.SubtreeMsgHashesOnly)
	if err != nil {
		t.Fatalf("EncodeSubtreeDataPayload hashes-only 1M: %v", err)
	}
	wantHashes := frame.SubtreeDataPayloadHeaderSize + oneMillion*frame.SubtreeNodeHashSize + 8
	if len(enc) != wantHashes {
		t.Errorf("hashes-only size: got %d, want %d", len(enc), wantHashes)
	}

	enc2, err := frame.EncodeSubtreeDataPayload(p, frame.SubtreeMsgFullNodes)
	if err != nil {
		t.Fatalf("EncodeSubtreeDataPayload full-nodes 1M: %v", err)
	}
	wantFull := frame.SubtreeDataPayloadHeaderSize + oneMillion*frame.SubtreeNodeFullSize + 8
	if len(enc2) != wantFull {
		t.Errorf("full-nodes size: got %d, want %d", len(enc2), wantFull)
	}
}
