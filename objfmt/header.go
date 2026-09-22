package objfmt

import "github.com/lightwebinc/shard-common/frame"

// BlockHeaderSize returns the length of the bare block header at the start of
// buf. A BSV block header is a fixed 80 bytes ([frame.BlockHeaderSize]), so
// the answer is 80 whenever that many bytes are present and [ErrShort]
// otherwise.
//
// The function name matches the class-codec convention (TxSize, SubtreeSize,
// BlockSize, BEEFRecordSize, BEEFDeliverySize). It deliberately does not
// shadow [frame.BlockHeaderSize] with a package-level constant of the same
// name: that identifier is the function.
//
// Two properties follow from the fixed size and both matter to a lane:
//
//   - It never returns [ErrMalformed]. Any 80 bytes are a well-formed object
//     here, because the class carries no tag, no length and no magic to check
//     (objfmt is byte-only and does no validation; proof of work and chaining
//     are the consumer's job). A stream that loses byte alignment upstream
//     therefore yields an endless run of plausible-looking headers rather
//     than a decode error, so a header lane cannot detect desync from the
//     codec alone.
//   - [ErrObjectTooLarge] is unreachable for any reader whose maximum is at
//     least 80, and fires on the very first header for any reader below it.
//     A reader bound for this class is a floor to respect, not a ceiling to
//     tune: set it to at least [frame.BlockHeaderSize].
func BlockHeaderSize(buf []byte) (int, error) {
	if len(buf) < frame.BlockHeaderSize {
		return 0, ErrShort
	}
	return frame.BlockHeaderSize, nil
}
