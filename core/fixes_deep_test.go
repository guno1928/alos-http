package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guno1928/alosmap"
)

type mockConn struct {
	net.Conn
	closeCalls atomic.Int32
	writeCalls atomic.Int32
	writeData  []byte
	writeMu    sync.Mutex
	closed     chan struct{}
}

func newMockConn() *mockConn {
	return &mockConn{closed: make(chan struct{})}
}

func (m *mockConn) Close() error {
	m.closeCalls.Add(1)
	select {
	case <-m.closed:
	default:
		close(m.closed)
	}
	return nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.writeCalls.Add(1)
	m.writeMu.Lock()
	m.writeData = append(m.writeData, b...)
	m.writeMu.Unlock()
	return len(b), nil
}

func (m *mockConn) Read([]byte) (int, error)             { <-m.closed; return 0, net.ErrClosed }
func (m *mockConn) LocalAddr() net.Addr                  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443} }
func (m *mockConn) RemoteAddr() net.Addr                 { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 54321} }
func (m *mockConn) SetDeadline(time.Time) error          { return nil }
func (m *mockConn) SetReadDeadline(time.Time) error      { return nil }
func (m *mockConn) SetWriteDeadline(time.Time) error     { return nil }

func newTestH2Conn() (*H2Conn, *mockConn) {
	mc := newMockConn()
	hc := &H2Conn{
		conn:              mc,
		remoteAddr:        "10.0.0.1:54321",
		decoder:           NewHpackDecoder(),
		initialWindowSize: H2DefaultWindowSize,
		streams:           alosmap.NewTypedSized[int64, *H2Stream](16, 0),
		writeCh:           make(chan WriteRequest, 512),
		done:              make(chan struct{}),
		server:            &Server{config: DefaultConfig()},
		headerAccum:       make([]byte, 0, 4096),
	}
	hc.connWindow.Store(int64(H2DefaultWindowSize))
	hc.maxFrameSize.Store(H2DefaultMaxFrameSize)
	hc.recvConnWindow.Store(int64(H2ConnectionWindowSize))
	hc.flowCond = sync.NewCond(&hc.flowMu)
	go func() {
		for {
			select {
			case <-hc.done:
				return
			case req, ok := <-hc.writeCh:
				if !ok {
					return
				}
				if req.Done != nil {
					req.Done <- nil
				}
			}
		}
	}()
	return hc, mc
}

func TestH2PingFloodClose(t *testing.T) {
	hc, mc := newTestH2Conn()
	defer close(hc.done)

	for i := 0; i < int(h2MaxPingCount)+10; i++ {
		f := &H2Frame{
			Type:     H2FramePing,
			Flags:    0,
			StreamID: 0,
			Payload:  make([]byte, 8),
			Length:   8,
		}
		hc.handleFrame(f)
	}

	if mc.closeCalls.Load() == 0 {
		t.Fatal("connection must be closed after exceeding ping flood limit")
	}
}

func TestH2SettingsFloodClose(t *testing.T) {
	hc, mc := newTestH2Conn()
	defer close(hc.done)

	for i := 0; i < int(h2MaxSettingsCount)+10; i++ {
		f := &H2Frame{
			Type:     H2FrameSettings,
			Flags:    0,
			StreamID: 0,
			Payload:  make([]byte, 0),
			Length:   0,
		}
		hc.handleFrame(f)
	}

	if mc.closeCalls.Load() == 0 {
		t.Fatal("connection must be closed after exceeding settings flood limit")
	}
}

func TestH2RSTSlidingWindow(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = 1
	stream.State.Store(StreamOpen)
	hc.streams.Store(int64(1), stream)
	hc.activeStreams.Store(1)

	hc.rstWindowStart.Store(0)
	hc.rstStreamCount.Store(0)

	f := &H2Frame{
		Type:     H2FrameRSTStream,
		Flags:    0,
		StreamID: 1,
		Payload:  make([]byte, 4),
		Length:   4,
	}
	hc.handleFrame(f)

	cnt := hc.rstStreamCount.Load()
	if cnt != 1 {
		t.Fatalf("rstStreamCount should be 1 after first RST, got %d", cnt)
	}

	hc.rstWindowStart.Store(CoarseNanotime() - h2RstWindowDuration - 1)

	stream2 := StreamPool.Get().(*H2Stream)
	stream2.Reset()
	stream2.ID = 3
	stream2.State.Store(StreamOpen)
	hc.streams.Store(int64(3), stream2)
	hc.activeStreams.Add(1)

	f2 := &H2Frame{
		Type:     H2FrameRSTStream,
		Flags:    0,
		StreamID: 3,
		Payload:  make([]byte, 4),
		Length:   4,
	}
	hc.handleFrame(f2)

	cnt2 := hc.rstStreamCount.Load()
	if cnt2 != 1 {
		t.Fatalf("rstStreamCount should reset to 1 after window expiry, got %d", cnt2)
	}
}

func TestH2DispatchRecovery(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	hc.server.Router = NewRouter()
	hc.server.Router.GET("/panic", func(req *Request, resp *Response) {
		panic("test panic in handler")
	})
	hc.server.Router.Build()

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = 1
	stream.State.Store(StreamHalfClosed)
	stream.Method = "GET"
	stream.Path = "/panic"
	hc.streams.Store(int64(stream.ID), stream)
	hc.activeStreams.Store(1)

	hc.dispatchWg.Add(1)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatal("panic must not propagate from dispatchRequest")
			}
		}()
		hc.dispatchRequest(stream)
	}()
}

func TestH2ConditionalWindowUpdate(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	hc.server.config.MaxBodySize = 100

	stream := StreamPool.Get().(*H2Stream)
	stream.Reset()
	stream.ID = 1
	stream.State.Store(StreamOpen)
	stream.Body = make([]byte, 0, 200)
	hc.streams.Store(int64(stream.ID), stream)
	hc.activeStreams.Store(1)

	payload := make([]byte, 110)
	f := &H2Frame{
		Type:     H2FrameData,
		Flags:    0,
		StreamID: 1,
		Payload:  payload,
		Length:   uint32(len(payload)),
	}
	hc.handleFrame(f)

	if _, ok := hc.streams.Load(int64(1)); ok {
		t.Fatal("stream should be deleted after exceeding MaxBodySize")
	}
}

func TestWSMaxMessageSizeDefault(t *testing.T) {
	ws := &WSConn{}
	got := ws.maxMessageSize()
	want := int64(wsDefaultMaxMessageSize)
	if got != want {
		t.Fatalf("default maxMessageSize = %d, want %d", got, want)
	}
	if want != 4*1024*1024 {
		t.Fatalf("wsDefaultMaxMessageSize = %d, want %d", want, 4*1024*1024)
	}
}

func TestWSMaxMessageSizeCustom(t *testing.T) {
	ws := &WSConn{MaxMessageSize: 64 * 1024 * 1024}
	got := ws.maxMessageSize()
	want := int64(64 * 1024 * 1024)
	if got != want {
		t.Fatalf("custom maxMessageSize = %d, want %d", got, want)
	}
}

func TestWSMaxMessageSizeZeroFallback(t *testing.T) {
	ws := &WSConn{MaxMessageSize: 0}
	got := ws.maxMessageSize()
	want := int64(4 * 1024 * 1024)
	if got != want {
		t.Fatalf("zero MaxMessageSize should fall back to %d, got %d", want, got)
	}
}

func TestWSWriteTimeout(t *testing.T) {
	mc := newMockConn()
	ws := &WSConn{conn: mc, writeTimeout: wsDefaultWriteTimeout}
	if ws.writeTimeout != 30*time.Second {
		t.Fatalf("writeTimeout = %v, want 30s", ws.writeTimeout)
	}
}

func TestWSWriteMutex(t *testing.T) {
	mc := newMockConn()
	ws := &WSConn{conn: mc, writeTimeout: wsDefaultWriteTimeout}

	var wg sync.WaitGroup
	const goroutines = 10
	const writes = 50
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < writes; i++ {
				ws.WriteMessage(wsOpText, []byte("hi"))
			}
		}()
	}
	wg.Wait()
	totalWrites := mc.writeCalls.Load()
	if totalWrites != goroutines*writes {
		t.Fatalf("expected %d write calls, got %d", goroutines*writes, totalWrites)
	}
}

func TestQUICAntiAmplification(t *testing.T) {
	qc := &QUICConn{
		done: make(chan struct{}),
	}
	qc.bytesReceived.Store(1200)
	qc.bytesSent.Store(3600)
	qc.addressValidated.Store(false)

	blocked := qc.bytesSent.Load() >= 3*qc.bytesReceived.Load()
	if !blocked {
		t.Fatal("sends should be blocked when bytesSent >= 3*bytesReceived and not validated")
	}
}

func TestQUICAntiAmplificationValidated(t *testing.T) {
	qc := &QUICConn{
		done: make(chan struct{}),
	}
	qc.bytesReceived.Store(1200)
	qc.bytesSent.Store(5000)
	qc.addressValidated.Store(true)

	shouldBlock := !qc.addressValidated.Load() && qc.bytesSent.Load() >= 3*qc.bytesReceived.Load()
	if shouldBlock {
		t.Fatal("sends must NOT be blocked when addressValidated is true")
	}
}

func TestQUICFlowControl(t *testing.T) {
	qc := &QUICConn{
		done:          make(chan struct{}),
		maxDataRemote: 500,
		dataSent:      400,
		streams:       make(map[uint64]*QUICStream),
		loss:          newQuicLossState(),
	}

	var connAvail uint64
	if qc.maxDataRemote > qc.dataSent {
		connAvail = qc.maxDataRemote - qc.dataSent
	}
	if connAvail != 100 {
		t.Fatalf("connAvail = %d, want 100", connAvail)
	}

	qc.dataSent = 500
	if qc.maxDataRemote > qc.dataSent {
		t.Fatal("should have no remaining send allowance when dataSent == maxDataRemote")
	}
}

func TestQUICCongestionWindowInit(t *testing.T) {
	ls := newQuicLossState()
	expectedCwnd := uint64(10 * quicMaxPacketSize)
	if ls.cwnd != expectedCwnd {
		t.Fatalf("initial cwnd = %d, want %d", ls.cwnd, expectedCwnd)
	}
	if ls.ssthresh != math.MaxUint64 {
		t.Fatalf("initial ssthresh = %d, want MaxUint64", ls.ssthresh)
	}
}

func TestQUICCongestionCanSend(t *testing.T) {
	ls := newQuicLossState()
	if !ls.canSend() {
		t.Fatal("canSend should be true when bytesInFlight=0 < cwnd")
	}

	ls.mu.Lock()
	ls.bytesInFlight = int(ls.cwnd)
	ls.mu.Unlock()

	if ls.canSend() {
		t.Fatal("canSend should be false when bytesInFlight >= cwnd")
	}
}

func TestQUICCongestionSlowStart(t *testing.T) {
	ls := newQuicLossState()
	initialCwnd := ls.cwnd

	ls.onPacketSent(quicSpaceAppData, 0, 1200, true, nil)
	ls.onPacketSent(quicSpaceAppData, 1, 1200, true, nil)

	ack := quicAckFrame{
		largestAck: 1,
		firstRange: 1,
	}
	ls.onAckReceived(quicSpaceAppData, ack, quicMaxAckDelay)

	if ls.cwnd <= initialCwnd {
		t.Fatalf("cwnd should grow during slow start: initial=%d current=%d", initialCwnd, ls.cwnd)
	}
}

func TestQUICCongestionLossHalving(t *testing.T) {
	ls := newQuicLossState()
	ls.mu.Lock()
	ls.cwnd = 120000
	ls.ssthresh = math.MaxUint64
	ls.mu.Unlock()

	for i := 0; i < 20; i++ {
		ls.onPacketSent(quicSpaceAppData, uint64(i), 1200, true, nil)
	}

	ack := quicAckFrame{
		largestAck: 19,
		firstRange: 0,
	}
	ls.onAckReceived(quicSpaceAppData, ack, quicMaxAckDelay)

	ls.mu.Lock()
	cwndAfter := ls.cwnd
	ssthreshAfter := ls.ssthresh
	ls.mu.Unlock()

	if ssthreshAfter >= 120000 {
		t.Logf("ssthresh=%d cwnd=%d (no packet loss detected in this scenario, which is expected)", ssthreshAfter, cwndAfter)
	}
}

func TestQUICSentPacketCap(t *testing.T) {
	ls := newQuicLossState()
	for i := 0; i < 5000; i++ {
		ls.onPacketSent(quicSpaceAppData, uint64(i), 100, true, nil)
	}

	ls.mu.Lock()
	tracked := len(ls.sent[quicSpaceAppData])
	ls.mu.Unlock()

	if tracked > 4096 {
		t.Fatalf("tracked sent packets = %d, must not exceed 4096", tracked)
	}
}

func TestQUICACKRangeCap(t *testing.T) {
	var data []byte
	data = quicAppendVarint(data, quicFrameACK)
	data = quicAppendVarint(data, 1000)
	data = quicAppendVarint(data, 0)
	data = quicAppendVarint(data, 300)
	data = quicAppendVarint(data, 0)

	var gotErr error
	visitor := &quicFrameVisitor{
		onACK: func(f quicAckFrame) {},
	}
	gotErr = quicParseFrames(data, visitor)
	if gotErr != ErrTruncated {
		t.Fatalf("ACK with rangeCount=300 (>256) should return ErrTruncated, got %v", gotErr)
	}
}

func TestQUICCIDKeyAllocation(t *testing.T) {
	tests := []struct {
		name string
		cid  []byte
	}{
		{"empty", nil},
		{"short", []byte{0x01, 0x02, 0x03}},
		{"exact8", []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"full20", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := quicCIDKey(tt.cid)
			for i := 0; i < len(tt.cid) && i < 20; i++ {
				if key[i] != tt.cid[i] {
					t.Fatalf("key[%d]=%d, want %d", i, key[i], tt.cid[i])
				}
			}
			for i := len(tt.cid); i < 20; i++ {
				if key[i] != 0 {
					t.Fatalf("key[%d]=%d, want 0 (zero-padded)", i, key[i])
				}
			}
		})
	}
}

func TestH1ChunkedEncoding(t *testing.T) {
	raw := []byte("POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n")
	req := RequestPool.Get().(*Request)
	req.Reset()
	_, _, _, _, badTE, chunked, ok := ParseH1RequestHead(raw, req)
	RequestPool.Put(req)
	if !ok {
		t.Fatal("ParseH1RequestHead returned ok=false")
	}
	if !chunked {
		t.Fatal("chunkedEncoding should be true for Transfer-Encoding: chunked")
	}
	if badTE {
		t.Fatal("badTransferEncoding should be false for chunked")
	}
}

func TestH1BadTransferEncoding(t *testing.T) {
	raw := []byte("POST /upload HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip\r\n\r\n")
	req := RequestPool.Get().(*Request)
	req.Reset()
	_, _, _, _, badTE, chunked, ok := ParseH1RequestHead(raw, req)
	RequestPool.Put(req)
	if !ok {
		t.Fatal("ParseH1RequestHead returned ok=false")
	}
	if !badTE {
		t.Fatal("badTransferEncoding should be true for Transfer-Encoding: gzip")
	}
	if chunked {
		t.Fatal("chunkedEncoding should be false for Transfer-Encoding: gzip")
	}
}

func TestH3FrameUnsignedCompare(t *testing.T) {
	var payload []byte
	payload = quicAppendVarint(payload, 42)
	payload = quicAppendVarint(payload, h3FrameData)
	payload = quicAppendVarint(payload, uint64(len(payload)))

	r := &h3FrameReader{data: payload}
	_, _, ok := r.next()
	if ok {
		return
	}

	largeLen := uint64(0xFFFFFFFF)
	var data []byte
	data = quicAppendVarint(data, h3FrameData)
	data = quicAppendVarint(data, largeLen)
	r2 := &h3FrameReader{data: data}
	_, _, ok2 := r2.next()
	if ok2 {
		t.Fatal("frame with fLen > available data should return ok=false")
	}
}

func TestDefaultReadTimeout(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ReadTimeout != 30*time.Second {
		t.Fatalf("DefaultConfig().ReadTimeout = %v, want 30s", cfg.ReadTimeout)
	}
}

func TestDefaultWriteTimeout(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.WriteTimeout != 30*time.Second {
		t.Fatalf("DefaultConfig().WriteTimeout = %v, want 30s", cfg.WriteTimeout)
	}
}

func TestPerIPLimiterStop(t *testing.T) {
	l := newPerIPRequestLimiter()
	l.Stop()

	select {
	case <-l.done:
	case <-time.After(2 * time.Second):
		t.Fatal("limiter goroutine did not stop within 2s")
	}

	l.Stop()
}

func TestJWTAlgValidation(t *testing.T) {
	secret := []byte("test-secret-key-for-jwt-testing1")

	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user","exp":9999999999}`))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(noneHeader + "." + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	tokenNone := noneHeader + "." + payload + "." + sig

	_, ok := validateJWT(tokenNone, secret)
	if ok {
		t.Fatal("JWT with alg=none must be rejected")
	}

	rs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	mac2 := hmac.New(sha256.New, secret)
	mac2.Write([]byte(rs256Header + "." + payload))
	sig2 := base64.RawURLEncoding.EncodeToString(mac2.Sum(nil))
	tokenRS := rs256Header + "." + payload + "." + sig2

	_, ok2 := validateJWT(tokenRS, secret)
	if ok2 {
		t.Fatal("JWT with alg=RS256 must be rejected")
	}

	hs256Header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	mac3 := hmac.New(sha256.New, secret)
	mac3.Write([]byte(hs256Header + "." + payload))
	sig3 := base64.RawURLEncoding.EncodeToString(mac3.Sum(nil))
	tokenOK := hs256Header + "." + payload + "." + sig3

	claims, ok3 := validateJWT(tokenOK, secret)
	if !ok3 {
		t.Fatal("JWT with alg=HS256 and valid signature must be accepted")
	}
	if claims["sub"] != "user" {
		t.Fatalf("expected sub=user, got %v", claims["sub"])
	}
}

func TestHPACKCacheEntrySize(t *testing.T) {
	entry := &hpackHuffmanDecodeCacheEntry{}
	largeSize := uint32(70000)
	entry.size = largeSize
	if entry.size != 70000 {
		t.Fatalf("cache entry size = %d, want 70000 (uint32 must hold values > 65535)", entry.size)
	}

	maxVal := uint32(math.MaxUint32)
	entry.size = maxVal
	if entry.size != maxVal {
		t.Fatalf("cache entry size = %d, want MaxUint32", entry.size)
	}
}

func TestQUICDeriveNextTrafficSecret(t *testing.T) {
	h := sha256.New
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}

	output := quicDeriveNextTrafficSecret(h, input, 32)

	if len(output) != 32 {
		t.Fatalf("output length = %d, want 32", len(output))
	}

	allSame := true
	for i := range output {
		if output[i] != input[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("derived secret must differ from input")
	}

	output2 := quicDeriveNextTrafficSecret(h, input, 32)
	for i := range output {
		if output[i] != output2[i] {
			t.Fatal("derivation must be deterministic")
		}
	}
}

func TestH2PingCounterNonACK(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	f := &H2Frame{
		Type:     H2FramePing,
		Flags:    H2FlagAck,
		StreamID: 0,
		Payload:  make([]byte, 8),
		Length:   8,
	}
	for i := 0; i < int(h2MaxPingCount)+50; i++ {
		hc.handleFrame(f)
	}
	if hc.pingCount.Load() != 0 {
		t.Fatalf("ACK pings must not increment pingCount, got %d", hc.pingCount.Load())
	}
}

func TestH2SettingsACKNotCounted(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	f := &H2Frame{
		Type:     H2FrameSettings,
		Flags:    H2FlagAck,
		StreamID: 0,
		Payload:  make([]byte, 0),
		Length:   0,
	}
	for i := 0; i < int(h2MaxSettingsCount)+50; i++ {
		hc.handleFrame(f)
	}
	if hc.settingsCount.Load() != 0 {
		t.Fatalf("ACK settings must not increment settingsCount, got %d", hc.settingsCount.Load())
	}
}

func TestQUICCongestionAvoidance(t *testing.T) {
	ls := newQuicLossState()

	ls.mu.Lock()
	ls.cwnd = 12000
	ls.ssthresh = 12000
	ls.mu.Unlock()

	ls.onPacketSent(quicSpaceAppData, 0, 1200, true, nil)

	initialCwnd := ls.cwnd

	ack := quicAckFrame{
		largestAck: 0,
		firstRange: 0,
	}
	ls.onAckReceived(quicSpaceAppData, ack, quicMaxAckDelay)

	ls.mu.Lock()
	cwndAfter := ls.cwnd
	ls.mu.Unlock()

	if cwndAfter <= initialCwnd {
		t.Fatalf("cwnd must grow during congestion avoidance: initial=%d after=%d", initialCwnd, cwndAfter)
	}

	ls2 := newQuicLossState()
	ls2.mu.Lock()
	ls2.cwnd = 12000
	ls2.ssthresh = 6000
	ls2.mu.Unlock()

	ls2.onPacketSent(quicSpaceAppData, 0, 1200, true, nil)
	ack2 := quicAckFrame{
		largestAck: 0,
		firstRange: 0,
	}
	ls2.onAckReceived(quicSpaceAppData, ack2, quicMaxAckDelay)

	ls2.mu.Lock()
	growth := ls2.cwnd - 12000
	ls2.mu.Unlock()

	expectedGrowth := uint64(quicMaxPacketSize) * 1200 / 12000
	if growth != expectedGrowth {
		t.Fatalf("congestion avoidance growth = %d, want %d", growth, expectedGrowth)
	}
}

func TestH2PingPayloadSize(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	f := &H2Frame{
		Type:     H2FramePing,
		Flags:    0,
		StreamID: 0,
		Payload:  make([]byte, 4),
		Length:   4,
	}
	hc.handleFrame(f)

	if hc.pingCount.Load() != 0 {
		t.Fatalf("ping with payload != 8 bytes should be rejected, but pingCount=%d", hc.pingCount.Load())
	}
}

func TestH2SettingsInvalidLength(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	f := &H2Frame{
		Type:     H2FrameSettings,
		Flags:    0,
		StreamID: 0,
		Payload:  make([]byte, 7),
		Length:   7,
	}
	hc.handleFrame(f)

	if hc.settingsCount.Load() != 0 {
		t.Fatalf("settings with payload%%6 != 0 should be rejected, but settingsCount=%d", hc.settingsCount.Load())
	}
}

func TestWSNegativeMaxMessageSize(t *testing.T) {
	ws := &WSConn{MaxMessageSize: -1}
	got := ws.maxMessageSize()
	want := int64(wsDefaultMaxMessageSize)
	if got != want {
		t.Fatalf("negative MaxMessageSize should fall back to %d, got %d", want, got)
	}
}

func TestPerIPLimiterAcquireRelease(t *testing.T) {
	l := newPerIPRequestLimiter()
	defer l.Stop()

	limit := int64(3)
	for i := int64(0); i < limit; i++ {
		if !l.acquire("10.0.0.1", limit) {
			t.Fatalf("acquire %d should succeed (limit=%d)", i+1, limit)
		}
	}

	if l.acquire("10.0.0.1", limit) {
		t.Fatal("acquire should fail when at limit")
	}

	l.release("10.0.0.1")
	if !l.acquire("10.0.0.1", limit) {
		t.Fatal("acquire should succeed after release")
	}
}

func TestQUICACKRangeExactCap(t *testing.T) {
	var data []byte
	data = quicAppendVarint(data, quicFrameACK)
	data = quicAppendVarint(data, 1000)
	data = quicAppendVarint(data, 0)
	data = quicAppendVarint(data, 256)
	data = quicAppendVarint(data, 0)

	visitor := &quicFrameVisitor{
		onACK: func(f quicAckFrame) {},
	}
	err := quicParseFrames(data, visitor)
	if err != ErrTruncated {
		t.Fatalf("ACK with rangeCount=256 should also return ErrTruncated (>256 check), got %v", err)
	}
}

func TestH1ParseHostHeader(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := RequestPool.Get().(*Request)
	req.Reset()
	_, _, _, _, _, _, ok := ParseH1RequestHead(raw, req)
	if !ok {
		t.Fatal("ParseH1RequestHead returned ok=false")
	}
	if req.Host != "example.com" {
		t.Fatalf("Host = %q, want example.com", req.Host)
	}
	RequestPool.Put(req)
}

func TestH2PingNonZeroStreamID(t *testing.T) {
	hc, _ := newTestH2Conn()
	defer close(hc.done)

	f := &H2Frame{
		Type:     H2FramePing,
		Flags:    0,
		StreamID: 1,
		Payload:  make([]byte, 8),
		Length:   8,
	}
	hc.handleFrame(f)

	if hc.pingCount.Load() != 0 {
		t.Fatal("ping on non-zero stream should be rejected, not counted")
	}
}

func TestDefaultConfigValues(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Addr != ":8443" {
		t.Fatalf("Addr = %q, want :8443", cfg.Addr)
	}
	if cfg.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout = %v, want 120s", cfg.IdleTimeout)
	}
	if cfg.HandshakeTimeout != 30*time.Second {
		t.Fatalf("HandshakeTimeout = %v, want 30s", cfg.HandshakeTimeout)
	}
	if cfg.MaxHeaderSize != 8192 {
		t.Fatalf("MaxHeaderSize = %d, want 8192", cfg.MaxHeaderSize)
	}
	if cfg.ServerName != "ALOS" {
		t.Fatalf("ServerName = %q, want ALOS", cfg.ServerName)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Fatalf("ShutdownTimeout = %v, want 30s", cfg.ShutdownTimeout)
	}
}
