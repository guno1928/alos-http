package core

import (
	"testing"
)

// These fuzz harnesses (finding L6) exercise the wire-facing parsers that
// consume untrusted bytes off the network. The invariant under test for every
// target is the same: on hostile input the parser must not panic, must not hang
// (the fuzzer's own deadline catches hangs), and must never report success with
// offsets/lengths that fall outside the input it was handed.

// FuzzParseH1RequestHead fuzzes the HTTP/1 request-head parser.
//
// Invariant: when ok is true, headerEnd must be a valid index into data
// (0 < headerEnd <= len(data)). contentLength is allowed to be the -1 sentinel
// (unparseable Content-Length); any value below that floor would be a defect.
func FuzzParseH1RequestHead(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"))
	f.Add([]byte("OPTIONS * HTTP/1.1\r\nConnection: close\r\n\r\n"))
	// Malformed / hostile seeds.
	f.Add([]byte(""))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("GET\r\n\r\n"))                                          // no spaces in request line
	f.Add([]byte("GET / HTTP/1.1\r\nContent-Length: notanumber\r\n\r\n")) // CL sentinel path
	f.Add([]byte("GET / HTTP/1.1\r\n: novalue\r\n\r\n"))                  // empty header name
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a"))                            // no terminating CRLF CRLF

	f.Fuzz(func(t *testing.T, data []byte) {
		var req Request
		headerEnd, contentLength, _, _, _, ok := ParseH1RequestHead(data, &req)

		if ok {
			if headerEnd <= 0 || headerEnd > len(data) {
				t.Fatalf("ok=true but headerEnd=%d out of bounds for input len=%d", headerEnd, len(data))
			}
		} else if headerEnd != 0 {
			t.Fatalf("ok=false should report headerEnd=0, got %d", headerEnd)
		}

		// contentLength may legitimately be -1 (sentinel for an unparseable
		// Content-Length). Any other negative value would be a parser defect.
		if contentLength < -1 {
			t.Fatalf("contentLength=%d below the -1 sentinel floor", contentLength)
		}
	})
}

// FuzzQPACKDecode fuzzes the QPACK header-block decoder.
//
// Invariant: never panics; on success the decoder never returns more than its
// internal cap of headers.
func FuzzQPACKDecode(f *testing.F) {
	// Valid encoded-field-section prefix (required insert count 0, base 0)
	// followed by an indexed static-table reference (0xC0 | idx).
	f.Add([]byte{0x00, 0x00, 0xC0 | 17}) // indexed static reference
	f.Add([]byte{0x00, 0x00, 0xD1})      // another indexed static ref
	// Literal with literal name (0x20 family): name len 1, 'x', value len 1, 'y'.
	f.Add([]byte{0x00, 0x00, 0x21, 'x', 0x01, 'y'})
	// Malformed / hostile seeds.
	f.Add([]byte{})
	f.Add([]byte{0x00})             // too short (< 2)
	f.Add([]byte{0x00, 0x00})       // valid prefix, empty body
	f.Add([]byte{0x00, 0x00, 0x3f}) // literal-with-name-ref claiming huge length
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})

	d := &QPACKDecoder{}
	f.Fuzz(func(t *testing.T, data []byte) {
		headers, err := d.Decode(data)
		if err != nil {
			return
		}
		if len(headers) > 128 {
			t.Fatalf("decoder returned %d headers, exceeds the 128 cap", len(headers))
		}
	})
}

// FuzzHpackDecode fuzzes the HPACK (HTTP/2) header-block decoder.
//
// Invariant: never panics; on success the header count stays within the
// decoder's internal cap.
func FuzzHpackDecode(f *testing.F) {
	// Indexed header field 0x82 == ":method: GET" (static index 2).
	f.Add([]byte{0x82})
	f.Add([]byte{0x82, 0x86, 0x84}) // :method GET, :scheme http, :path /
	// Literal header field with incremental indexing, new name "x"/"y".
	f.Add([]byte{0x40, 0x01, 'x', 0x01, 'y'})
	// Dynamic table size update.
	f.Add([]byte{0x20})
	// Malformed / hostile seeds.
	f.Add([]byte{})
	f.Add([]byte{0xff})             // indexed with continuation byte missing
	f.Add([]byte{0x80})             // indexed index 0 (invalid)
	f.Add([]byte{0x40, 0x7f, 0xff}) // literal name length overflow attempt
	f.Add([]byte{0x00})             // literal without indexing, index 0, then EOF

	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewHpackDecoder()
		headers, err := d.Decode(data)
		if err != nil {
			return
		}
		if len(headers) > 128 {
			t.Fatalf("decoder returned %d headers, exceeds the 128 cap", len(headers))
		}
	})
}

// FuzzQuicParseFrames fuzzes the QUIC frame parser over a decrypted payload.
//
// Invariant: never panics; every byte slice the parser hands a visitor callback
// (CRYPTO data, STREAM data, NEW_TOKEN token, NEW_CONNECTION_ID id) must alias
// only into the input buffer, i.e. its length must not exceed the input length.
func FuzzQuicParseFrames(f *testing.F) {
	// PADDING + PING.
	f.Add([]byte{0x00, 0x00, 0x01})
	// CRYPTO frame: type 0x06, offset 0, length 3, "abc".
	f.Add(quicAppendCryptoFrame(nil, 0, []byte("abc")))
	// STREAM frame.
	f.Add(quicAppendStreamFrame(nil, 4, 0, []byte("hi"), true))
	// ACK frame.
	f.Add(quicAppendACKFrame(nil, 10, 0, 5))
	// MAX_DATA.
	f.Add(quicAppendMaxDataFrame(nil, 1<<20))
	// Malformed / hostile seeds.
	f.Add([]byte{})
	f.Add([]byte{0x06})                   // CRYPTO type, truncated
	f.Add([]byte{0x06, 0x00, 0x7f, 0xff}) // CRYPTO claiming a length past EOF
	f.Add([]byte{0x08, 0x40, 0x00})       // STREAM frame, truncated varints
	f.Add([]byte{0xff, 0xff, 0xff, 0xff}) // unknown/huge frame type

	f.Fuzz(func(t *testing.T, data []byte) {
		inputLen := len(data)

		v := &quicFrameVisitor{
			onCrypto: func(fr quicCryptoFrame) {
				if len(fr.data) > inputLen {
					t.Fatalf("CRYPTO frame data len %d exceeds input len %d", len(fr.data), inputLen)
				}
			},
			onStream: func(fr quicStreamFrame) {
				if len(fr.data) > inputLen {
					t.Fatalf("STREAM frame data len %d exceeds input len %d", len(fr.data), inputLen)
				}
			},
			onNewToken: func(token []byte) {
				if len(token) > inputLen {
					t.Fatalf("NEW_TOKEN len %d exceeds input len %d", len(token), inputLen)
				}
			},
			onNewConnID: func(fr quicNewConnIDFrame) {
				if len(fr.connID) > inputLen {
					t.Fatalf("NEW_CONNECTION_ID connID len %d exceeds input len %d", len(fr.connID), inputLen)
				}
			},
		}

		// A parse error is a valid outcome on hostile input; we only assert no
		// panic and that the visitor never saw an out-of-bounds slice.
		_ = quicParseFrames(data, v)
	})
}

// FuzzQuicParseLongHeader fuzzes the QUIC long-header parser.
//
// Invariant: never panics; on success total and the payload window must lie
// within the input (total <= len(data), payloadOff+payloadLen <= len(data)),
// and the connection-ID / token slices must alias into the input.
func FuzzQuicParseLongHeader(f *testing.F) {
	// Minimal Initial-ish long header built via the encoder, with a varint
	// length + payload appended so the success path is reachable.
	hdr := quicBuildLongHeader(nil, quicInitialType, 1, []byte{1, 2, 3, 4}, []byte{5, 6}, nil, 1)
	hdr = quicAppendVarint(hdr, 4) // packet length
	hdr = append(hdr, 0xde, 0xad, 0xbe, 0xef)
	f.Add(hdr)
	// Version-negotiation packet (version == 0): build then zero the version.
	vn := quicBuildLongHeader(nil, quicHandshakeType, 0, []byte{9}, nil, nil, 1)
	vn = append(vn, 0x00, 0x01)
	f.Add(vn)
	// Malformed / hostile seeds.
	f.Add([]byte{})
	f.Add([]byte{0x80})                                     // long-header bit set, too short
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0xff})                   // dcidLen 0xff > 20
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0x02, 1, 2, 0xff, 0xff}) // scid len overrun
	f.Add([]byte{0xc0, 0xff, 0xff, 0xff, 0xff, 0x14})       // dcidLen exactly 20 then EOF

	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, total, err := quicParseLongHeader(data)
		if err != nil {
			if total != 0 {
				t.Fatalf("err returned but total=%d (expected 0)", total)
			}
			return
		}

		if total < 0 || total > len(data) {
			t.Fatalf("total=%d out of bounds for input len=%d", total, len(data))
		}
		if hdr.payloadOff < 0 || hdr.payloadLen < 0 {
			t.Fatalf("negative payload window off=%d len=%d", hdr.payloadOff, hdr.payloadLen)
		}
		if hdr.payloadOff+hdr.payloadLen > len(data) {
			t.Fatalf("payload window [%d,%d) exceeds input len=%d", hdr.payloadOff, hdr.payloadOff+hdr.payloadLen, len(data))
		}
		if len(hdr.dcid) > len(data) || len(hdr.scid) > len(data) || len(hdr.token) > len(data) {
			t.Fatalf("a header slice exceeds input len=%d (dcid=%d scid=%d token=%d)", len(data), len(hdr.dcid), len(hdr.scid), len(hdr.token))
		}
	})
}
