package core

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRateLimitCounter_NoLostIncrements(t *testing.T) {
	var state atomic.Uint64
	now := int64(1_000_000_000_000)
	window := int64(time.Second)
	const workers = 50
	const each = 200
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				rlBumpCount(&state, now, window)
			}
		}()
	}
	wg.Wait()
	final := int64(state.Load() & rlCountMask)
	if final != workers*each {
		t.Fatalf("lost increments: final count %d, want %d", final, workers*each)
	}
}

func TestRateLimitCounter_WindowRoll(t *testing.T) {
	var state atomic.Uint64
	window := int64(time.Second)
	if c := rlBumpCount(&state, window*5, window); c != 1 {
		t.Fatalf("first request in window: got %d want 1", c)
	}
	if c := rlBumpCount(&state, window*5+1, window); c != 2 {
		t.Fatalf("second request same window: got %d want 2", c)
	}
	if c := rlBumpCount(&state, window*6, window); c != 1 {
		t.Fatalf("request in next window should reset: got %d want 1", c)
	}
}

func TestProxyCache_EntryEvictionNoWipeNoFreeze(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{MaxEntries: 10})
	pc.UpdateConfig(ProxyCacheConfig{MaxEntries: 10, MaxTotalBytes: 0})
	defer close(pc.stopCh)
	for i := 0; i < 40; i++ {
		pc.PutManual("GET", "h", fmt.Sprintf("/p%d", i), 200, nil, "text/plain", []byte("body"), time.Minute, 0, false, 0)
	}
	deadline := time.Now().Add(2 * time.Second)
	var n int64
	for time.Now().Before(deadline) {
		n = pc.totalEntries.Load()
		if n > 0 && n <= 10 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if n <= 0 {
		t.Fatalf("cache wiped to %d entries (eviction target bug)", n)
	}
	if n > 10 {
		t.Fatalf("cache exceeded MaxEntries=10: %d (freeze/overcount bug)", n)
	}
}

func TestQUICStreamReassembly_OutOfOrder(t *testing.T) {
	s := &QUICStream{maxRecv: 1 << 20}
	s.handleStreamFrame(quicStreamFrame{offset: 5, data: []byte("WORLD")})
	if len(s.recvBuf) != 0 {
		t.Fatalf("out-of-order frame should not be readable yet, got %q", s.recvBuf)
	}
	s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("HELLO"), fin: true})
	if string(s.recvBuf) != "HELLOWORLD" {
		t.Fatalf("expected reassembled \"HELLOWORLD\", got %q", s.recvBuf)
	}
	if s.recvOff != 10 {
		t.Fatalf("expected recvOff 10, got %d", s.recvOff)
	}
}

func TestQUICStreamReassembly_Duplicate(t *testing.T) {
	s := &QUICStream{maxRecv: 1 << 20}
	s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("ABCDEF")})
	s.handleStreamFrame(quicStreamFrame{offset: 2, data: []byte("CDE")})
	if string(s.recvBuf) != "ABCDEF" {
		t.Fatalf("duplicate/overlapping frame corrupted buffer, got %q", s.recvBuf)
	}
	if s.recvOff != 6 {
		t.Fatalf("expected recvOff 6, got %d", s.recvOff)
	}
}

func TestQUICStreamReassembly_MultiGap(t *testing.T) {
	s := &QUICStream{maxRecv: 1 << 20}
	s.handleStreamFrame(quicStreamFrame{offset: 8, data: []byte("IJ")})
	s.handleStreamFrame(quicStreamFrame{offset: 4, data: []byte("EFGH")})
	s.handleStreamFrame(quicStreamFrame{offset: 0, data: []byte("ABCD")})
	if string(s.recvBuf) != "ABCDEFGHIJ" {
		t.Fatalf("expected \"ABCDEFGHIJ\", got %q", s.recvBuf)
	}
}

func TestRecordRecvPN_DuplicateDetection(t *testing.T) {
	qc := &QUICConn{}
	if !qc.recordRecvPN(quicSpaceAppData, 5) {
		t.Fatal("first sighting of pn 5 should report new")
	}
	if qc.recordRecvPN(quicSpaceAppData, 5) {
		t.Fatal("duplicate pn 5 should report not-new")
	}
	if !qc.recordRecvPN(quicSpaceAppData, 6) {
		t.Fatal("new pn 6 should report new")
	}
	if qc.recordRecvPN(quicSpaceAppData, 6) {
		t.Fatal("duplicate pn 6 should report not-new")
	}
}

func TestParseH1RequestHead_LineValidation(t *testing.T) {
	check := func(name string, data []byte, wantBad bool) {
		var req Request
		_, _, _, _, badTE, _, _, ok := ParseH1RequestHead(data, &req, 0, 0)
		if wantBad {
			if !badTE {
				t.Fatalf("%s: expected badTE (400), got badTE=%v ok=%v", name, badTE, ok)
			}
		} else {
			if !ok || badTE {
				t.Fatalf("%s: expected clean parse, got ok=%v badTE=%v", name, ok, badTE)
			}
		}
	}
	check("valid 1.1", []byte("GET /p HTTP/1.1\r\nHost: x\r\n\r\n"), false)
	check("valid 1.0", []byte("GET /p HTTP/1.0\r\nHost: x\r\n\r\n"), false)
	check("no version", []byte("GET /p\r\nHost: x\r\n\r\n"), true)
	check("bad version", []byte("GET /p HTTP/2.0\r\nHost: x\r\n\r\n"), true)
	check("control in method", []byte("G\x01T /p HTTP/1.1\r\nHost: x\r\n\r\n"), true)
}

func TestHuffman_ValidRoundTripAndBadPadding(t *testing.T) {
	enc := hpackHuffmanAppend(nil, "hello-world-example.com")
	got, ok := hpackHuffmanDecode(enc)
	if !ok || got != "hello-world-example.com" {
		t.Fatalf("valid huffman rejected or wrong: ok=%v got=%q", ok, got)
	}
	if _, ok := hpackHuffmanDecode([]byte{0x00}); ok {
		t.Fatal("huffman with non-EOS padding (byte 0x00) was accepted")
	}
}

func TestReadMessage_RejectsReservedOpcode(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	ws := &WSConn{conn: c1, writeTimeout: 150 * time.Millisecond, MaxMessageSize: wsDefaultMaxMessageSize}
	go func() {
		c2.Write([]byte{0x83, 0x80})
		io.Copy(io.Discard, c2)
	}()
	if _, _, err := ws.ReadMessage(); err != ErrWebSocketProtocol {
		t.Fatalf("expected ErrWebSocketProtocol for reserved opcode 0x3, got %v", err)
	}
}
