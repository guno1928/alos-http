package core

import "testing"

func TestReportedFloodConfigNowHasIndependentSafetyCeilings(t *testing.T) {
	srv := New(Config{
		PlainHTTP:         true,
		ProxyMode:         true,
		MaxBodySize:       100 << 20,
		MaxConnsPerIP:     18,
		MaxConcurrentReqs: 99_000_000,
		MinPrealloc:       50_000,
	})
	if got, want := srv.effectiveReadCap(), 2<<20; got != want {
		t.Fatalf("reported config read cap = %d, want %d", got, want)
	}
	if got, want := srv.config.MaxConns, int64(8192); got != want {
		t.Fatalf("reported config connection cap = %d, want %d", got, want)
	}
	if got, want := srv.config.MinPrealloc, 8192; got != want {
		t.Fatalf("reported config preallocation = %d, want clamp %d", got, want)
	}
	if got, want := srv.config.MaxInFlightBodyBytes, int64(64<<20); got != want {
		t.Fatalf("reported config body budget = %d, want %d", got, want)
	}
}

func TestEffectiveReadCapDoesNotFollowBodyLimit(t *testing.T) {
	s := New(Config{MaxBodySize: 100 << 20, MaxReadSize: 0, MaxConnsPerIP: -1})
	if got, want := s.effectiveReadCap(), 2<<20; got != want {
		t.Fatalf("effective read cap = %d, want independent default %d", got, want)
	}
	if !s.requestBodyTooLarge(2<<20 + 1) {
		t.Fatal("protocol body accumulation must honor the read-memory cap")
	}
	if s.requestBodyTooLarge(2 << 20) {
		t.Fatal("body at the read-memory cap should be accepted")
	}
}

func TestRequestResetReleasesFloodSizedBackingStorage(t *testing.T) {
	r := &Request{
		Headers: make([][2]string, 128),
		Body:    make([]byte, 8<<20),
	}
	r.Headers[0] = [2]string{"x-large", string(make([]byte, 1<<20))}
	headerBacking := r.Headers
	r.Params[0] = Param{Key: "id", Value: string(make([]byte, 1<<20))}
	r.ParamCount = 1
	r.Reset()
	if cap(r.Body) > bufferShrinkThreshold {
		t.Fatalf("request retained oversized body: cap=%d", cap(r.Body))
	}
	if r.Params[0] != (Param{}) {
		t.Fatal("request retained route strings")
	}
	for i := range headerBacking {
		if headerBacking[i] != ([2]string{}) {
			t.Fatal("request retained header strings")
		}
	}
}

func TestH2StreamResetReleasesFloodSizedBackingStorage(t *testing.T) {
	s := &H2Stream{
		Headers:   make([][2]string, 16),
		Body:      make([]byte, 8<<20),
		headerBuf: make([]byte, 1<<20),
	}
	s.Headers[0] = [2]string{"x-large", string(make([]byte, 1<<20))}
	headerBacking := s.Headers
	s.Reset()
	if cap(s.Body) > bufferShrinkThreshold || cap(s.headerBuf) > bufferShrinkThreshold {
		t.Fatalf("stream retained oversized buffers: body=%d header=%d", cap(s.Body), cap(s.headerBuf))
	}
	for i := range headerBacking {
		if headerBacking[i] != ([2]string{}) {
			t.Fatal("stream retained header strings")
		}
	}
}

func TestQUICFloodBuffersStaySmallByDefault(t *testing.T) {
	if quicPktBufCap > 2048 {
		t.Fatalf("default QUIC packet pool is too large: %d", quicPktBufCap)
	}
	if quicInboundQueueSize > 32 {
		t.Fatalf("per-connection QUIC ingress queue is too large: %d", quicInboundQueueSize)
	}
	srv := New(Config{QUICMaxStreamData: 512 << 10, MaxConnsPerIP: -1})
	qc := &QUICConn{server: srv}
	if got := quicStreamRecvLimit(qc); got != 512<<10 {
		t.Fatalf("QUIC receive limit = %d, want %d", got, 512<<10)
	}
}

func TestInFlightBodyBudgetIsAggregateAndReleased(t *testing.T) {
	srv := New(Config{MaxInFlightBodyBytes: 1024, MaxConnsPerIP: -1})
	if !srv.tryReserveBodyBytes(768) {
		t.Fatal("initial body reservation should fit")
	}
	if srv.tryReserveBodyBytes(257) {
		t.Fatal("aggregate body reservation exceeded the configured budget")
	}
	s := &H2Stream{bodyOwner: srv, bodyAccounted: 768, Body: make([]byte, 768)}
	s.Reset()
	if got := srv.inFlightBodyBytes.Load(); got != 0 {
		t.Fatalf("stream reset left %d body bytes reserved", got)
	}
	if !srv.tryReserveBodyBytes(1024) {
		t.Fatal("released body budget was not reusable")
	}
	srv.releaseBodyBytes(1024)
}

func TestSafeConnectionDefaultsAndPreallocClamp(t *testing.T) {
	srv := New(Config{MinPrealloc: 50_000, MaxConnsPerIP: -1})
	if got, want := srv.config.MaxConns, int64(8192); got != want {
		t.Fatalf("default MaxConns = %d, want %d", got, want)
	}
	if got, want := srv.config.MinPrealloc, 8192; got != want {
		t.Fatalf("MinPrealloc = %d, want clamp to MaxConns %d", got, want)
	}
	unlimited := New(Config{MaxConns: -1, MaxConnsPerIP: -1})
	if unlimited.config.MaxConns != -1 {
		t.Fatal("negative MaxConns should remain the explicit unlimited opt-out")
	}
}
