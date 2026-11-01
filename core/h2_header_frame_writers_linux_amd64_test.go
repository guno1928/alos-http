//go:build linux && amd64

package core

import (
	"bytes"
	"testing"
)

func TestH2HeaderFrameWritersFragmentAtLimit(t *testing.T) {
	const limit = 100
	big := h2BigHeaderValue()[:1000]
	resp := &Response{}
	resp.SetHeader("x-big", big).Status(200)
	cases := map[string][]byte{
		"response":    appendH2ResponseHeadersFrameIndexed([]byte("prefix"), 5, resp, true, nil, "ALOS", limit),
		"status-only": appendH2StatusOnlyResponseIndexed([]byte("prefix"), 5, 431, big, nil, limit),
		"block":       appendH2HeaderBlockFrame([]byte("prefix"), 5, H2FlagEndHeaders|H2FlagEndStream, &hpackEncTable{}, bytes.Repeat([]byte{0x40}, 3*limit+1), limit),
	}
	for name, out := range cases {
		if !bytes.HasPrefix(out, []byte("prefix")) {
			t.Fatalf("%s: clobbered preceding output", name)
		}
		out = out[len("prefix"):]
		frames := 0
		for len(out) > 0 {
			n := int(out[0])<<16 | int(out[1])<<8 | int(out[2])
			typ, flags := out[3], out[4]
			id := uint32(out[5])<<24 | uint32(out[6])<<16 | uint32(out[7])<<8 | uint32(out[8])
			wantType := byte(H2FrameContinuation)
			if frames == 0 {
				wantType = H2FrameHeaders
			}
			last := 9+n == len(out)
			if typ != wantType || id != 5 || n > limit || last != (flags&H2FlagEndHeaders != 0) {
				t.Fatalf("%s frame %d: type %d stream %d len %d flags %#x last %v", name, frames, typ, id, n, flags, last)
			}
			if frames == 0 && flags&H2FlagEndStream == 0 {
				t.Fatalf("%s: END_STREAM dropped from HEADERS", name)
			}
			if frames > 0 && flags&H2FlagEndStream != 0 {
				t.Fatalf("%s: END_STREAM set on CONTINUATION", name)
			}
			out = out[9+n:]
			frames++
		}
		if frames < 2 {
			t.Fatalf("%s: not fragmented (%d frame)", name, frames)
		}
	}
}

func TestH2RootFastResponseFragmentsOversizedHeaders(t *testing.T) {
	enc := HpackEncoder{}
	encodeH2ResponseHeaders(&enc, 200, "text/plain", 4, [][2]string{{"x-big", h2BigHeaderValue()}}, "ALOS")
	fast := newH2RootFastResponse(append([]byte(nil), enc.Buf...), []byte("root"))
	if len(fast.framed) != 0 || len(fast.tlsInner) != 0 {
		t.Fatalf("prebuilt frame kept for a %d-byte header block", len(enc.Buf))
	}
	out := appendFastH2RootResponse(nil, fast, 5, H2DefaultMaxFrameSize)
	var types []byte
	var block []byte
	for len(out) > 0 {
		n := int(out[0])<<16 | int(out[1])<<8 | int(out[2])
		if n > H2DefaultMaxFrameSize {
			t.Fatalf("frame type %d carries %d bytes", out[3], n)
		}
		if out[3] != H2FrameData {
			block = append(block, out[9:9+n]...)
		}
		types = append(types, out[3])
		out = out[9+n:]
	}
	if len(types) < 3 || types[0] != H2FrameHeaders || types[1] != H2FrameContinuation || types[len(types)-1] != H2FrameData {
		t.Fatalf("frame sequence %v", types)
	}
	if _, err := NewHpackDecoder().DecodeInto(nil, block); err != nil {
		t.Fatalf("reassembled root header block does not decode: %v", err)
	}
}
