//go:build linux

package core

import "testing"

func TestFPH2PaddedDataCreditsWholeFramePayload(t *testing.T) {
	c := &backendConn{state: connClosed, be: &beLoop{cfg: &fpConfig{MaxResponseBody: 1 << 20}}, transport: &plainTransport{h2: true}}
	c.h2init()
	st := &h2Stream{id: 1}
	c.h2.streams[1] = st
	payload := []byte{5, 'a', 'b', 'c', 0, 0, 0, 0, 0}
	if err := c.be.h2proto.onDataFrame(c, h2FlagPadded, 1, payload); err != nil {
		t.Fatal(err)
	}
	if string(st.body) != "abc" {
		t.Fatalf("body = %q", st.body)
	}
	out := c.wbuf.unread()
	if len(out) != 2*(h2FrameHeaderSize+4) {
		t.Fatalf("expected two WINDOW_UPDATE frames, got %d bytes", len(out))
	}
	for i := 0; i < 2; i++ {
		f := out[i*(h2FrameHeaderSize+4):]
		if f[3] != h2FrameWindowUpdate {
			t.Fatalf("frame %d type %#x", i, f[3])
		}
		inc := int(f[9])<<24 | int(f[10])<<16 | int(f[11])<<8 | int(f[12])
		if inc != len(payload) {
			t.Fatalf("frame %d credits %d bytes, want the full %d-byte payload including padding (window leaks otherwise)", i, inc, len(payload))
		}
	}
}
