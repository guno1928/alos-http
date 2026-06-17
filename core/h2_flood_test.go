package core

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/guno1928/alosmap"
)

// fakeClock is a manually-advanced monotonic clock (nanos) for deterministic
// leaky-bucket tests. Read by the read-loop goroutine and advanced by the
// test goroutine, so access is guarded.
type fakeClock struct {
	mu    sync.Mutex
	nanos int64
}

func (c *fakeClock) now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nanos
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.nanos += int64(d)
	c.mu.Unlock()
}

// newTestH2Conn wires an H2Conn over the server side of a net.Pipe exactly as
// ServeH2Plain does, but with an injectable clock and without consuming the
// preface (the test writes frames directly). It returns the running conn, the
// client end of the pipe, and a func that waits for serveLoop teardown.
func newTestH2Conn(t *testing.T, clock *fakeClock) (*H2Conn, net.Conn, func() bool) {
	t.Helper()
	srv := New(DefaultConfig())
	clientConn, serverConn := net.Pipe()

	hc := &H2Conn{
		remoteAddr:        "test",
		conn:              serverConn,
		plain:             true,
		hdrBuf:            make([]byte, 5),
		server:            srv,
		decoder:           NewHpackDecoder(),
		initialWindowSize: H2DefaultWindowSize,
		streams:           alosmap.New(alosmap.WithCapacity(256), alosmap.WithoutCleanup()),
		writeCh:           make(chan WriteRequest, 512),
		done:              make(chan struct{}),
		decryptBuf:        make([]byte, 0, MaxRecordSize),
		appBuf:            make([]byte, 0, MaxRecordSize*2),
		headerAccum:       make([]byte, 0, 4096),
	}
	hc.connWindow.Store(int64(H2DefaultWindowSize))
	hc.maxFrameSize.Store(H2DefaultMaxFrameSize)
	hc.recvConnWindow.Store(int64(H2ConnectionWindowSize))
	hc.flowCond = sync.NewCond(&hc.flowMu)
	hc.now = clock.now
	hc.initFloodDefenses()

	go hc.writerLoop()

	var loopDone sync.WaitGroup
	loopDone.Add(1)
	go func() {
		defer loopDone.Done()
		defer func() {
			close(hc.done)
			hc.flowCond.Broadcast()
			hc.dispatchWg.Wait()
			close(hc.writeCh)
			_ = serverConn.Close()
		}()
		hc.serveLoop()
	}()

	wait := func() bool {
		ch := make(chan struct{})
		go func() {
			loopDone.Wait()
			close(ch)
		}()
		select {
		case <-ch:
			return true
		case <-time.After(3 * time.Second):
			return false
		}
	}

	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	return hc, clientConn, wait
}

// readUntilGoAway reads frames from the client end and returns the GOAWAY
// error code, or fails if the connection closes / times out first.
func readUntilGoAway(t *testing.T, client net.Conn) (uint32, bool) {
	t.Helper()
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var hdr [9]byte
	for {
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			return 0, false
		}
		length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		typ := hdr[3]
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(client, payload); err != nil {
				return 0, false
			}
		}
		if typ == H2FrameGoAway {
			if len(payload) < 8 {
				t.Fatalf("GOAWAY payload too short: %d", len(payload))
			}
			return binary.BigEndian.Uint32(payload[4:8]), true
		}
	}
}

func writeFrame(t *testing.T, client net.Conn, typ, flags byte, streamID uint32, payload []byte) {
	t.Helper()
	frame := H2WriteFrame(nil, typ, flags, streamID, payload)
	_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(frame); err != nil {
		// Peer may have already closed after tripping a flood defense; that
		// is an expected race, not a test failure.
		t.Logf("write frame type=0x%02x: %v", typ, err)
	}
}

func TestH2RapidResetTripsGoAway(t *testing.T) {
	clock := &fakeClock{nanos: 1}
	_, client, wait := newTestH2Conn(t, clock)

	// Drain frames the server sends (initial SETTINGS, WINDOW_UPDATE, pongs,
	// RST acks) and surface the GOAWAY when it arrives.
	goAwayCh := make(chan uint32, 1)
	go func() {
		code, ok := readUntilGoAway(t, client)
		if ok {
			goAwayCh <- code
		} else {
			close(goAwayCh)
		}
	}()

	// HEADERS (open, no END_STREAM) + RST_STREAM in a loop. The stream opens
	// then is immediately reset before producing a response — the Rapid Reset
	// shape. Each RST is charged to the reset-rate bucket; with the clock frozen
	// the bucket never refills, so past its capacity (H2MaxRstStreams) it trips.
	// END_STREAM is intentionally omitted so no handler goroutine is dispatched,
	// keeping this test orthogonal to the C5 stream-lifecycle (UAF) fix on a
	// separate branch. Crucially, the defense no longer decrements on handler
	// completion (it is a rate bucket, not a counter), so the canonical
	// HEADERS(END_STREAM)+RST loop can no longer cancel its own pressure — that
	// is the behavior this fix restores; see consts.go H2MaxRstStreams.
	headerBlock := []byte{0x82, 0x84, 0x87} // :method GET, :path /, :scheme https
	var streamID uint32 = 1
	for i := 0; i < H2MaxRstStreams+50; i++ {
		writeFrame(t, client, H2FrameHeaders, H2FlagEndHeaders, streamID, headerBlock)
		writeFrame(t, client, H2FrameRSTStream, 0, streamID, []byte{0, 0, 0, byte(H2ErrCancel)})
		streamID += 2
	}

	select {
	case code, ok := <-goAwayCh:
		if !ok {
			t.Fatal("connection closed without GOAWAY")
		}
		if code != H2ErrEnhanceYourCalm {
			t.Fatalf("GOAWAY code = 0x%x, want ENHANCE_YOUR_CALM (0x%x)", code, H2ErrEnhanceYourCalm)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for GOAWAY")
	}

	if !wait() {
		t.Fatal("serveLoop did not exit after rapid-reset GOAWAY")
	}
}

func TestH2PingFloodTripsGoAwayAndClose(t *testing.T) {
	// Clock never advances → no leak → bucket fills and trips.
	clock := &fakeClock{nanos: 1}
	_, client, wait := newTestH2Conn(t, clock)

	goAwayCh := make(chan uint32, 1)
	go func() {
		code, ok := readUntilGoAway(t, client)
		if ok {
			goAwayCh <- code
		} else {
			close(goAwayCh)
		}
	}()

	var ping [8]byte
	for i := 0; i < H2MaxPingFrames+50; i++ {
		writeFrame(t, client, H2FramePing, 0, 0, ping[:])
	}

	select {
	case code, ok := <-goAwayCh:
		if !ok {
			t.Fatal("connection closed without GOAWAY")
		}
		if code != H2ErrEnhanceYourCalm {
			t.Fatalf("PING flood GOAWAY code = 0x%x, want 0x%x", code, H2ErrEnhanceYourCalm)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for PING-flood GOAWAY")
	}

	if !wait() {
		t.Fatal("serveLoop did not close after PING flood")
	}
}

func TestH2SettingsFloodTripsGoAway(t *testing.T) {
	clock := &fakeClock{nanos: 1}
	_, client, wait := newTestH2Conn(t, clock)

	goAwayCh := make(chan uint32, 1)
	go func() {
		code, ok := readUntilGoAway(t, client)
		if ok {
			goAwayCh <- code
		} else {
			close(goAwayCh)
		}
	}()

	// Empty SETTINGS frames (valid, payload len 0 is a multiple of 6).
	for i := 0; i < H2MaxSettingsFrames+50; i++ {
		writeFrame(t, client, H2FrameSettings, 0, 0, nil)
	}

	select {
	case code, ok := <-goAwayCh:
		if !ok {
			t.Fatal("connection closed without GOAWAY")
		}
		if code != H2ErrEnhanceYourCalm {
			t.Fatalf("SETTINGS flood GOAWAY code = 0x%x, want 0x%x", code, H2ErrEnhanceYourCalm)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SETTINGS-flood GOAWAY")
	}

	if !wait() {
		t.Fatal("serveLoop did not close after SETTINGS flood")
	}
}

func TestH2ContinuationFloodTripsGoAwayAndClose(t *testing.T) {
	clock := &fakeClock{nanos: 1}
	_, client, wait := newTestH2Conn(t, clock)

	goAwayCh := make(chan uint32, 1)
	go func() {
		code, ok := readUntilGoAway(t, client)
		if ok {
			goAwayCh <- code
		} else {
			close(goAwayCh)
		}
	}()

	// HEADERS without END_HEADERS opens a header block, then a stream of
	// zero-length CONTINUATION frames that never set END_HEADERS. They add
	// no bytes, so only the per-block frame-count cap stops them.
	writeFrame(t, client, H2FrameHeaders, 0, 1, []byte{0x82})
	for i := 0; i < H2MaxContinuationFrames+10; i++ {
		writeFrame(t, client, H2FrameContinuation, 0, 1, nil)
	}

	select {
	case code, ok := <-goAwayCh:
		if !ok {
			t.Fatal("connection closed without GOAWAY")
		}
		if code != H2ErrEnhanceYourCalm {
			t.Fatalf("CONTINUATION flood GOAWAY code = 0x%x, want 0x%x", code, H2ErrEnhanceYourCalm)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for CONTINUATION-flood GOAWAY")
	}

	if !wait() {
		t.Fatal("serveLoop did not close after CONTINUATION flood")
	}
}

func TestH2ContinuationByteCapTripsGoAway(t *testing.T) {
	clock := &fakeClock{nanos: 1}
	hc, client, wait := newTestH2Conn(t, clock)

	goAwayCh := make(chan uint32, 1)
	go func() {
		code, ok := readUntilGoAway(t, client)
		if ok {
			goAwayCh <- code
		} else {
			close(goAwayCh)
		}
	}()

	// Non-empty CONTINUATION frames that overflow the header-block byte cap
	// before hitting the frame-count cap. Each carries a chunk large enough
	// that a handful of frames exceeds maxHeaderBlockBytes.
	byteCap := hc.maxHeaderBlockBytes()
	chunk := make([]byte, 4096)
	writeFrame(t, client, H2FrameHeaders, 0, 1, []byte{0x82})
	for sent := 0; sent <= byteCap+len(chunk); sent += len(chunk) {
		writeFrame(t, client, H2FrameContinuation, 0, 1, chunk)
	}

	select {
	case code, ok := <-goAwayCh:
		if !ok {
			t.Fatal("connection closed without GOAWAY")
		}
		if code != H2ErrEnhanceYourCalm {
			t.Fatalf("CONTINUATION byte-cap GOAWAY code = 0x%x, want 0x%x", code, H2ErrEnhanceYourCalm)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for byte-cap GOAWAY")
	}

	if !wait() {
		t.Fatal("serveLoop did not close after CONTINUATION byte-cap overflow")
	}
}

func TestLeakyBucketRefill(t *testing.T) {
	b := leakyBucket{capacity: 10, refillPerSec: 5}
	var now int64 = 1

	// Burst of 10 admits fits exactly at capacity.
	for i := 0; i < 10; i++ {
		if !b.admit(now) {
			t.Fatalf("admit %d rejected within capacity", i)
		}
	}
	// 11th in the same instant overflows.
	if b.admit(now) {
		t.Fatal("admit beyond capacity should be rejected")
	}

	// After 2s at 5/s the bucket leaks ~10 units, so it admits again.
	now += int64(2 * time.Second)
	if !b.admit(now) {
		t.Fatal("admit after refill should be accepted")
	}
}
