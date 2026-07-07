package objfmt

import (
	"github.com/lightwebinc/shard-common/frame"
)

// MulticastFrame wraps a pushed object into its multicast frame for the
// forwarder: the up-direction half of the codec. The returned frame is
// unstamped (zero HashKey/SeqNum) — the proxy stamps authoritatively from
// the observed source, exactly as for any submitted frame.
//
// ClassTx wraps a BRC-12/30 transaction into a BRC-124/128 frame
// (FrameVer 0x02; an EF payload is carried as-is per BRC-128). ClassSubtree
// and ClassBlock return [ErrClassNotRegistered] until their codecs land
// (BRC-132 / BRC-131 wraps respectively).
func MulticastFrame(c Class, obj []byte) (*frame.Frame, error) {
	switch c {
	case ClassTx:
		n, err := TxSize(obj)
		if err != nil {
			return nil, err
		}
		id, err := TxID(obj[:n])
		if err != nil {
			return nil, err
		}
		return &frame.Frame{
			Version: frame.FrameVerV2,
			TxID:    id,
			Payload: obj[:n],
		}, nil
	default:
		return nil, ErrClassNotRegistered
	}
}
