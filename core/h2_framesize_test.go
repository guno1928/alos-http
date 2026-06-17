package core

import (
	"errors"
	"testing"
)

// TestH2ConsumeFrameRejectsOversizedFrame verifies the receive path rejects a
// frame larger than the advertised SETTINGS_MAX_FRAME_SIZE (H2DefaultMaxFrameSize)
// as soon as the 9-byte header is seen, instead of accepting up to the 24-bit
// ceiling (H2MaxFrameSize, 16 MiB) and buffering the whole payload.
func TestH2ConsumeFrameRejectsOversizedFrame(t *testing.T) {
	hc := &H2Conn{}
	hc.done = make(chan struct{})
	close(hc.done) // make sendGoAway's enqueueWriteSync return immediately

	fLen := H2DefaultMaxFrameSize + 1 // one over the advertised limit, well under 16 MiB
	hdr := []byte{
		byte(fLen >> 16), byte(fLen >> 8), byte(fLen),
		0x00, 0x00, // DATA, no flags
		0x00, 0x00, 0x00, 0x01, // stream 1
	}
	hc.appBuf = hdr
	hc.appBufValid = len(hdr)
	hc.appBufOff = 0

	if _, err := hc.consumeFrame(); !errors.Is(err, ErrH2FrameTooLarge) {
		t.Fatalf("consumeFrame() err = %v, want ErrH2FrameTooLarge", err)
	}
}

func TestH2DefaultMaxFrameSizeBelowCeiling(t *testing.T) {
	if H2DefaultMaxFrameSize >= H2MaxFrameSize {
		t.Fatalf("H2DefaultMaxFrameSize (%d) should be below H2MaxFrameSize (%d)", H2DefaultMaxFrameSize, H2MaxFrameSize)
	}
}

// BenchmarkH2ConsumeFrameSmall measures the per-frame parse cost (where the
// new size check lives) for an in-bounds DATA frame.
func BenchmarkH2ConsumeFrameSmall(b *testing.B) {
	payload := make([]byte, 64)
	frame := make([]byte, 0, 9+len(payload))
	frame = append(frame, 0x00, 0x00, byte(len(payload)), 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
	frame = append(frame, payload...)

	hc := &H2Conn{}
	hc.done = make(chan struct{})
	close(hc.done)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hc.appBuf = frame
		hc.appBufValid = len(frame)
		hc.appBufOff = 0
		_, _ = hc.consumeFrame()
	}
}
