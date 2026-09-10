package core

import (
	"bytes"
	"testing"
	"time"
)

func TestQUICStreamGrantsCreditAsDataArrives(t *testing.T) {
	srv := New(Config{MaxBodySize: 1 << 20, MaxConnsPerIP: -1, QUICMaxStreamData: 64 << 10})
	qc := newTestQUIC(srv)
	s := getPooledStream(0, qc)
	if s.recvGranted != 64<<10 || s.maxRecv <= s.recvGranted {
		t.Fatalf("initial grant %d cap %d", s.recvGranted, s.maxRecv)
	}
	chunk := bytes.Repeat([]byte("a"), 16<<10)
	var off uint64
	for i := 0; i < 3; i++ {
		if _, flags := s.handleStreamFrame(quicStreamFrame{offset: off, data: chunk}); flags&quicRecvAccepted == 0 {
			t.Fatalf("frame %d rejected", i)
		}
		off += uint64(len(chunk))
	}
	if g := s.streamCreditToGrant(); g == 0 {
		t.Fatal("half the window consumed but no MAX_STREAM_DATA grant produced")
	} else if g != off+64<<10 {
		t.Fatalf("grant %d, want %d", g, off+64<<10)
	}
	if s.streamCreditToGrant() != 0 {
		t.Fatal("grant repeated without new data")
	}
}

func TestQUICStreamDataBeyondGrantIsAViolation(t *testing.T) {
	srv := New(Config{MaxBodySize: 1 << 20, MaxConnsPerIP: -1, QUICMaxStreamData: 4096})
	s := getPooledStream(0, newTestQUIC(srv))
	_, flags := s.handleStreamFrame(quicStreamFrame{offset: 0, data: make([]byte, 5000)})
	if flags&quicRecvViolation == 0 {
		t.Fatal("data past the advertised window was accepted silently instead of a FLOW_CONTROL_ERROR")
	}
}

func TestQUICStreamOverflowEndsStreamAsTooLarge(t *testing.T) {
	srv := New(Config{MaxBodySize: 8192, MaxHeaderSize: 1024, MaxConnsPerIP: -1, QUICMaxStreamData: 4096})
	s := getPooledStream(0, newTestQUIC(srv))
	wantCap := uint64(8192 + 1024 + quicStreamRecvFrameSlack)
	if s.maxRecv != wantCap {
		t.Fatalf("cap %d, want %d", s.maxRecv, wantCap)
	}
	var off uint64
	for off < wantCap {
		n := uint64(4096)
		if off+n > wantCap {
			n = wantCap - off
		}
		if g := s.streamCreditToGrant(); g > 0 && g > wantCap {
			t.Fatalf("grant %d exceeds cap %d", g, wantCap)
		}
		_, flags := s.handleStreamFrame(quicStreamFrame{offset: off, data: make([]byte, n)})
		if flags&quicRecvAccepted == 0 {
			t.Fatalf("frame at %d rejected (granted %d)", off, s.recvGranted)
		}
		off += n
		if flags&quicRecvEndOfData != 0 {
			break
		}
	}
	if !s.overflowed() {
		t.Fatal("stream filled to the cap without FIN was not flagged as overflow")
	}
	if s.streamCreditToGrant() != 0 {
		t.Fatal("credit granted past the cap")
	}
}

func TestQUICStreamFinBeforeEarlierChunkIsNotComplete(t *testing.T) {
	srv := New(Config{MaxBodySize: 1 << 20, MaxConnsPerIP: -1})
	s := getPooledStream(0, newTestQUIC(srv))
	first := bytes.Repeat([]byte("a"), 8192)
	last := bytes.Repeat([]byte("b"), 8192)
	_, flags := s.handleStreamFrame(quicStreamFrame{offset: 8192, data: last, fin: true})
	if flags&quicRecvEndOfData != 0 {
		t.Fatal("stream reported complete while the first 8192 bytes are still missing")
	}
	done := make(chan []byte, 1)
	go func() {
		b, _ := s.ReadAll()
		done <- b
	}()
	select {
	case b := <-done:
		t.Fatalf("ReadAll returned %d bytes before the gap was filled", len(b))
	case <-time.After(150 * time.Millisecond):
	}
	_, flags = s.handleStreamFrame(quicStreamFrame{offset: 0, data: first})
	if flags&quicRecvEndOfData == 0 {
		t.Fatal("stream not complete after the gap was filled")
	}
	b := <-done
	if len(b) != 16384 || b[0] != 'a' || b[16383] != 'b' {
		t.Fatalf("ReadAll = %d bytes", len(b))
	}
}
