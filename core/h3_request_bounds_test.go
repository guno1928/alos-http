//go:build linux && amd64

package core

import (
	"strings"
	"sync/atomic"
	"testing"
)

func h3BoundsCache(t *testing.T) {
	t.Helper()
	qpackDecodedBlocks.mu.Lock()
	previous, bytes := qpackDecodedBlocks.m, qpackDecodedBlocks.bytes
	qpackDecodedBlocks.m = make(map[string]*qpackCachedSection)
	qpackDecodedBlocks.bytes = 0
	qpackDecodedBlocks.mu.Unlock()
	t.Cleanup(func() {
		qpackDecodedBlocks.mu.Lock()
		qpackDecodedBlocks.m, qpackDecodedBlocks.bytes = previous, bytes
		qpackDecodedBlocks.mu.Unlock()
	})
}

func h3BoundsPeer(t *testing.T, maxHeader int) (*quicTestPeer, *atomic.Int32) {
	t.Helper()
	server := New(Config{MaxHeaderSize: maxHeader})
	hits := &atomic.Int32{}
	server.Router.GET("/bounds", func(_ *Request, resp *Response) {
		hits.Add(1)
		resp.String("bounds-ok")
	})
	server.Router.Build()
	server.fastDispatch.Store(true)
	return newQUICTestPeerFor(t, server), hits
}

func h3BoundsServe(t *testing.T, peer *quicTestPeer, id uint64, data []byte) {
	t.Helper()
	stream := getPooledStream(id, peer.qc)
	stream.refCount.Store(1)
	stream.recvBuf, stream.recvFin = data, true
	stream.maxSend = quicFixUnlimitedCredit
	peer.qc.h3.handleRequestStream(stream)
	peer.qc.releaseStream(stream)
}

func h3BoundsFields(t *testing.T, size int) [][2]string {
	t.Helper()
	fields := [][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "a.test"}, {":path", "/bounds"}, {"x-pad", ""}}
	padding := size - h2FieldListSize(fields)
	if padding < 0 {
		t.Fatal("field-section fixture cannot fit required pseudoheaders")
	}
	fields[len(fields)-1][1] = strings.Repeat("v", padding)
	if h2FieldListSize(fields) != size {
		t.Fatal("field-section fixture has the wrong size")
	}
	return fields
}

func TestH3BoundsFrameReaderDoesNotCommitTruncation(t *testing.T) {
	for _, suffix := range [][]byte{{0x40}, {0x00}, {0x00, 0x40}, {0x00, 0x02, 'x'}, {0x21, 0x02, 'x'}} {
		prefix := h3AppendFrame(nil, 0x21, []byte("ok"))
		reader := h3FrameReader{data: append(prefix, suffix...)}
		if kind, payload, ok := reader.next(); !ok || kind != 0x21 || string(payload) != "ok" {
			t.Fatal("complete extension frame did not parse")
		}
		before := reader.off
		if _, _, ok := reader.next(); ok || reader.off != before {
			t.Errorf("truncation %x: parsed=%v offset=%d, want false and %d", suffix, ok, reader.off, before)
		}
	}
}

func TestH3BoundsRejectsTruncatedFIN(t *testing.T) {
	for _, suffix := range [][]byte{{0x40}, {0x00}, {0x00, 0x40}, {0x00, 0x02, 'x'}, {0x21, 0x02, 'x'}} {
		peer, hits := h3BoundsPeer(t, 8192)
		request := append(h3AppendHeadersFrame(nil, quicFixGET("/bounds")), suffix...)
		h3BoundsServe(t, peer, 0, request)
		closes := peer.sent().closes
		if !peer.qc.closed.Load() || hits.Load() != 0 || len(closes) != 1 || closes[0].errorCode != 0x106 {
			t.Errorf("truncation %x: closed=%v handler=%d closes=%+v, want H3_FRAME_ERROR before dispatch", suffix, peer.qc.closed.Load(), hits.Load(), closes)
		}
	}
}

func TestH3BoundsCleanFINAndUnknownExtensionAccepted(t *testing.T) {
	for _, extension := range []bool{false, true} {
		peer, hits := h3BoundsPeer(t, 8192)
		request := h3AppendHeadersFrame(nil, quicFixGET("/bounds"))
		if extension {
			request = h3AppendFrame(request, 0x21, []byte("ignored"))
		}
		h3BoundsServe(t, peer, 0, request)
		if got := quicFixResponseStatus(t, peer, 0); got != 200 || hits.Load() != 1 || peer.qc.closed.Load() {
			t.Fatalf("valid request: status=%d hits=%d closed=%v", got, hits.Load(), peer.qc.closed.Load())
		}
	}
}

func TestH3BoundsColdRequestLimitAndBoundary(t *testing.T) {
	h3BoundsCache(t)
	peer, hits := h3BoundsPeer(t, 1024)
	for index, size := range []int{5121, 5120} {
		block := quicFixQPACKBlock(h3BoundsFields(t, size)...)
		if _, hit := qpackDecodedBlocks.get(block); hit {
			t.Fatal("cold fixture unexpectedly cached")
		}
		h3BoundsServe(t, peer, uint64(index*4), h3AppendHeadersFrame(nil, block))
		want := 431
		if index == 1 {
			want = 200
		}
		if got := quicFixResponseStatus(t, peer, uint64(index*4)); got != want {
			t.Fatalf("field size %d: status=%d, want %d", size, got, want)
		}
		if hits.Load() != int32(index) {
			t.Fatalf("field size %d: handler hits=%d, want %d", size, hits.Load(), index)
		}
	}
}

func TestH3BoundsMemoAcrossServersAndRuntimeLimits(t *testing.T) {
	h3BoundsCache(t)
	fields := h3BoundsFields(t, 5121)
	if h2FieldListSize(fields[4:]) >= 5120 {
		t.Fatal("pseudoheader fixture does not separate full and regular-only size")
	}
	block := quicFixQPACKBlock(fields...)
	permissive, hits := h3BoundsPeer(t, 8192)
	h3BoundsServe(t, permissive, 0, h3AppendHeadersFrame(nil, block))
	if got := quicFixResponseStatus(t, permissive, 0); got != 200 || hits.Load() != 1 {
		t.Fatal("permissive request did not reach the handler")
	}
	if _, hit := qpackDecodedBlocks.get(block); !hit {
		t.Fatal("fixture did not populate the shared QPACK cache")
	}
	restrictive, deniedHits := h3BoundsPeer(t, 1024)
	h3BoundsServe(t, restrictive, 0, h3AppendHeadersFrame(nil, block))
	if got := quicFixResponseStatus(t, restrictive, 0); got != 431 || deniedHits.Load() != 0 {
		t.Fatalf("cross-server memo bypass: status=%d hits=%d", got, deniedHits.Load())
	}
	limits := permissive.srv.Limits()
	limits.MaxHeaderSize = 1024
	if err := permissive.srv.SetLimits(limits); err != nil {
		t.Fatal(err)
	}
	if _, hit := qpackDecodedBlocks.get(block); !hit {
		t.Fatal("runtime lowering lost memo-hit precondition")
	}
	h3BoundsServe(t, permissive, 4, h3AppendHeadersFrame(nil, block))
	if got := quicFixResponseStatus(t, permissive, 4); got != 431 || hits.Load() != 1 {
		t.Fatalf("runtime memo bypass: status=%d hits=%d", got, hits.Load())
	}
	boundary := quicFixQPACKBlock(h3BoundsFields(t, 5120)...)
	h3BoundsServe(t, permissive, 8, h3AppendHeadersFrame(nil, boundary))
	if got := quicFixResponseStatus(t, permissive, 8); got != 200 || hits.Load() != 2 {
		t.Fatalf("runtime exact boundary: status=%d hits=%d", got, hits.Load())
	}
	if _, hit := qpackDecodedBlocks.get(boundary); !hit {
		t.Fatal("exact-boundary request did not populate the cache")
	}
	h3BoundsServe(t, permissive, 12, h3AppendHeadersFrame(nil, boundary))
	if got := quicFixResponseStatus(t, permissive, 12); got != 200 || hits.Load() != 3 {
		t.Fatalf("runtime memo exact boundary: status=%d hits=%d", got, hits.Load())
	}
}

func TestH3BoundsTrailerLimit(t *testing.T) {
	peer, hits := h3BoundsPeer(t, 1024)
	for index, size := range []int{5121, 5120} {
		trailer := [][2]string{{"x-trailer", strings.Repeat("v", size-32-len("x-trailer"))}}
		request := h3AppendHeadersFrame(nil, quicFixGET("/bounds"))
		request = h3AppendHeadersFrame(request, quicFixQPACKBlock(trailer...))
		h3BoundsServe(t, peer, uint64(index*4), request)
		want := 431
		if index == 1 {
			want = 200
		}
		if got := quicFixResponseStatus(t, peer, uint64(index*4)); got != want || hits.Load() != int32(index) {
			t.Fatalf("trailer size %d: status=%d hits=%d, want %d and %d", size, got, hits.Load(), want, index)
		}
	}
}

func TestH3BoundsHardLimitPreserved(t *testing.T) {
	h3BoundsCache(t)
	peer, hits := h3BoundsPeer(t, 65536)
	for index, size := range []int{16385, 16384} {
		block := quicFixQPACKBlock(h3BoundsFields(t, size)...)
		h3BoundsServe(t, peer, uint64(index*4), h3AppendHeadersFrame(nil, block))
		want := 431
		if index == 1 {
			want = 200
		}
		if got := quicFixResponseStatus(t, peer, uint64(index*4)); got != want || hits.Load() != int32(index) {
			t.Fatalf("hard field limit size %d: status=%d hits=%d", size, got, hits.Load())
		}
	}
}

func TestH3BoundsAdvertisedSettings(t *testing.T) {
	for _, test := range []struct{ configured, advertised int }{{1024, 5120}, {65536, 16384}} {
		peer, _ := h3BoundsPeer(t, test.configured)
		peer.qc.h3.sendControlStream()
		data := quicFixStreamData(peer, 3)
		kind, length := quicParseVarint(data)
		if length == 0 || kind != 0 {
			t.Fatal("missing real control stream")
		}
		reader := h3FrameReader{data: data[length:]}
		kind, payload, ok := reader.next()
		if !ok || kind != 4 {
			t.Fatal("missing SETTINGS frame")
		}
		found := false
		for len(payload) > 0 {
			setting, size := quicParseVarint(payload)
			if size == 0 {
				t.Fatal("truncated setting identifier")
			}
			payload = payload[size:]
			value, size := quicParseVarint(payload)
			if size == 0 {
				t.Fatal("truncated setting value")
			}
			payload = payload[size:]
			if setting == 6 {
				found = true
				if value != uint64(test.advertised) {
					t.Fatalf("configured %d: advertised %d, want %d", test.configured, value, test.advertised)
				}
			}
		}
		if !found {
			t.Fatal("SETTINGS omitted field-section limit")
		}
	}
}

func FuzzH3BoundsFrameReader(f *testing.F) {
	for _, seed := range [][]byte{{}, {0x40}, {0x00}, {0x00, 0x40}, {0x00, 0x02, 'x'}, {0x21, 0x00}, {0x21, 0x01, 'x'}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		reader := h3FrameReader{data: data}
		for {
			before := reader.off
			_, _, ok := reader.next()
			if !ok {
				if reader.off != before {
					t.Fatalf("failed frame advanced cursor from %d to %d", before, reader.off)
				}
				return
			}
			if reader.off <= before || reader.off > len(data) {
				t.Fatal("successful frame made invalid progress")
			}
		}
	})
}
