package core

import (
	"errors"
	"testing"
)

// TestH2ConsumeFrameRejectsOversizedFrame verifies the receive path rejects a
// frame larger than the advertised SETTINGS_MAX_FRAME_SIZE (H2DefaultMaxFrameSize)
// with FRAME_SIZE_ERROR, as soon as the 9-byte header is seen, rather than
// accepting anything up to the 24-bit protocol ceiling (H2MaxFrameSize, 16 MiB)
// and buffering the whole payload first.
func TestH2ConsumeFrameRejectsOversizedFrame(t *testing.T) {
	hc := &H2Conn{}
	hc.done = make(chan struct{})
	close(hc.done) // make sendGoAway's enqueueWriteSync return immediately

	fLen := H2DefaultMaxFrameSize + 1 // one over the advertised limit, well under 16 MiB
	hdr := []byte{
		byte(fLen >> 16), byte(fLen >> 8), byte(fLen), // length (24-bit)
		0x00,                   // type: DATA
		0x00,                   // flags
		0x00, 0x00, 0x00, 0x01, // stream id 1
	}
	hc.appBuf = hdr
	hc.appBufValid = len(hdr)
	hc.appBufOff = 0

	// Only the header is buffered (avail == 9); a correct implementation must
	// reject here without waiting for (or buffering) the oversized payload.
	_, err := hc.consumeFrame()
	if !errors.Is(err, ErrH2FrameTooLarge) {
		t.Fatalf("consumeFrame() err = %v, want ErrH2FrameTooLarge", err)
	}
}

// TestH2DefaultMaxFrameSizeBelowCeiling documents that the advertised receive
// limit is well below the 24-bit protocol ceiling, so enforcing it is meaningful.
func TestH2DefaultMaxFrameSizeBelowCeiling(t *testing.T) {
	if H2DefaultMaxFrameSize >= H2MaxFrameSize {
		t.Fatalf("H2DefaultMaxFrameSize (%d) should be below H2MaxFrameSize (%d)",
			H2DefaultMaxFrameSize, H2MaxFrameSize)
	}
}
