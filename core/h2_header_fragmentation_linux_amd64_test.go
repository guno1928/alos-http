//go:build linux && amd64

package core

import "testing"

const h2BigHeaderChars = 40000

func h2BigHeaderValue() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, h2BigHeaderChars)
	state := uint32(2463534242)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = alphabet[state%uint32(len(alphabet))]
	}
	return string(out)
}

func startH2BigHeaderServer(t *testing.T, overTLS bool, big string) string {
	return startH2FixServer(t, func(c *Config) {
		if overTLS {
			c.PlainHTTP = false
			c.Certs = []CertConfig{{Domain: h2FixAuthority, Source: CertSelfSigned}}
		}
	}, func(s *Server) {
		s.Router.GET("/", func(_ *Request, resp *Response) { resp.SetHeader("x-big", big).Status(200).String("root") })
		s.Router.GET("/big", func(_ *Request, resp *Response) { resp.SetHeader("x-big", big).Status(200).String("ok") })
		s.Router.GET("/big-empty", func(_ *Request, resp *Response) { resp.SetHeader("x-big", big).Status(204) })
		s.Router.GET("/streamed", func(_ *Request, resp *Response) {
			sw := resp.EnsureStreamWriter()
			if sw == nil {
				resp.Status(500).String("no stream writer")
				return
			}
			resp.SetStreamer(sw)
			if sw.WriteHeader(200, [][2]string{{"x-big", big}}, "text/plain") == nil && sw.WriteChunk([]byte("streamed")) == nil {
				_ = sw.Close()
			}
		})
	})
}

func readH2FragmentedHeaderBlock(t *testing.T, rc *h2RawConn, streamID uint32, maxFrame int) ([]byte, int, bool) {
	t.Helper()
	var block []byte
	frames := 0
	endStream := false
	for {
		f, err := rc.tryRead()
		if err != nil {
			t.Fatalf("reading header block after %d frames: %v", frames, err)
		}
		if f.typ == H2FrameGoAway || f.typ == H2FrameRSTStream {
			t.Fatalf("server sent frame type %d instead of the header block", f.typ)
		}
		if frames == 0 && (f.typ != H2FrameHeaders || f.streamID != streamID) {
			continue
		}
		if frames > 0 && (f.typ != H2FrameContinuation || f.streamID != streamID) {
			t.Fatalf("frame %d of the header block is type %d on stream %d, want CONTINUATION on %d", frames, f.typ, f.streamID, streamID)
		}
		if len(f.payload) > maxFrame {
			t.Fatalf("header block frame %d carries %d bytes, peer max frame size is %d", frames, len(f.payload), maxFrame)
		}
		if frames == 0 {
			endStream = f.flags&H2FlagEndStream != 0
		}
		frames++
		block = append(block, f.payload...)
		if f.flags&H2FlagEndHeaders != 0 {
			return block, frames, endStream
		}
	}
}

func TestH2ResponseHeaderBlockLargerThanMaxFrameIsFragmented(t *testing.T) {
	big := h2BigHeaderValue()
	for _, transport := range []string{"h2c", "tls"} {
		overTLS := transport == "tls"
		for _, path := range []string{"/", "/big", "/big-empty", "/streamed"} {
			t.Run(transport+path, func(t *testing.T) {
				t.Parallel()
				addr := startH2BigHeaderServer(t, overTLS, big)
				rc := dialH2RawMaybeTLS(t, addr, overTLS)
				h2FixGet(rc, 1, path)
				block, frames, ended := readH2FragmentedHeaderBlock(t, rc, 1, H2DefaultMaxFrameSize)
				if frames < 2 {
					t.Fatalf("%d-byte header block sent in %d frame", len(block), frames)
				}
				fields, err := NewHpackDecoder().DecodeInto(nil, block)
				if err != nil {
					t.Fatalf("reassembled header block does not decode: %v", err)
				}
				found := false
				for _, f := range fields {
					found = found || f[0] == "x-big" && f[1] == big
				}
				if !found {
					t.Fatalf("reassembled header block lacks the %d-byte x-big field", len(big))
				}
				if !ended {
					rc.awaitStreamEnd(1)
				}
				h2FixGet(rc, 3, "/big")
				if _, frames, _ := readH2FragmentedHeaderBlock(t, rc, 3, H2DefaultMaxFrameSize); frames < 2 {
					t.Fatalf("follow-up response sent in %d frame", frames)
				}
			})
		}
	}
}
