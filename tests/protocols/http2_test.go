package protocols_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func TestHTTP2FrameRoundTripMatrix(t *testing.T) {
	for i := 0; i < 64; i++ {
		t.Run(fmt.Sprintf("frame_%02d", i), func(t *testing.T) {
			payload := bytes.Repeat([]byte{byte(i), byte(i + 1)}, i)
			typ := byte(i % 10)
			flags := byte(i % 16)
			streamID := uint32(i*2 + 1)
			wire := core.H2WriteFrame(make([]byte, 0, 9+len(payload)), typ, flags, streamID, payload)
			frame, err := core.H2ReadFrame(func() ([]byte, error) { return wire, nil })
			if err != nil {
				t.Fatal(err)
			}
			if frame.Length != uint32(len(payload)) || frame.Type != typ || frame.Flags != flags || frame.StreamID != streamID || !bytes.Equal(frame.Payload, payload) {
				t.Fatalf("frame mismatch: %#v", frame)
			}
		})
	}
}

func TestHTTP2ControlFrames(t *testing.T) {
	for i := 0; i < 16; i++ {
		t.Run(fmt.Sprintf("settings_%02d", i), func(t *testing.T) {
			wire := core.H2WriteSettings(nil, [][2]uint32{{1, uint32(4096 + i)}, {3, uint32(100 + i)}})
			if len(wire) != 21 || wire[3] != core.H2FrameSettings {
				t.Fatalf("invalid SETTINGS frame: %x", wire)
			}
		})
		t.Run(fmt.Sprintf("window_%02d", i), func(t *testing.T) {
			wire := core.H2WriteWindowUpdate(nil, uint32(i*2+1), uint32(1024+i))
			if len(wire) != 13 || wire[3] != core.H2FrameWindowUpdate {
				t.Fatalf("invalid WINDOW_UPDATE frame: %x", wire)
			}
		})
		t.Run(fmt.Sprintf("ping_%02d", i), func(t *testing.T) {
			data := [8]byte{byte(i), 1, 2, 3, 4, 5, 6, 7}
			wire := core.H2WritePing(nil, i%2 == 0, data)
			if len(wire) != 17 || wire[3] != core.H2FramePing || !bytes.Equal(wire[9:], data[:]) {
				t.Fatalf("invalid PING frame: %x", wire)
			}
		})
	}
}

func TestHTTP2MalformedFrames(t *testing.T) {
	for size := 0; size < 9; size++ {
		t.Run(fmt.Sprintf("short_%d", size), func(t *testing.T) {
			_, err := core.H2ReadFrame(func() ([]byte, error) { return make([]byte, size), nil })
			if err == nil {
				t.Fatal("short frame accepted")
			}
		})
	}
	for declared := 1; declared <= 16; declared++ {
		t.Run(fmt.Sprintf("truncated_%02d", declared), func(t *testing.T) {
			wire := make([]byte, 9)
			wire[2] = byte(declared)
			_, err := core.H2ReadFrame(func() ([]byte, error) { return wire, nil })
			if err == nil {
				t.Fatal("truncated payload accepted")
			}
		})
	}
}
