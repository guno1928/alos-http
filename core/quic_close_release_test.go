//go:build linux && amd64

package core

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/guno1928/turbo"
)

const (
	quicCloseProbeBudget    = 64 << 10
	quicCloseProbeBodyBytes = 20000
	quicCloseProbeConns     = 3
	quicCloseProbeReserve   = 8 << 10
)

func quicCloseConn(t *testing.T) *QUICConn {
	t.Helper()
	server := &Server{config: Config{MaxInFlightBodyBytes: 1 << 20}, Router: NewRouter()}
	limits := limitsFromConfig(&server.config).withDefaults()
	server.limits.Store(&limits)
	qc := &QUICConn{
		server: server, done: make(chan struct{}), streams: make(map[uint64]*QUICStream),
		maxBidiRemote: quicMaxBidiStreams, maxUniRemote: quicMaxUniStreams,
		nextUniRemote: 2, nextUniLocal: 3, dataRecvGranted: 1 << 20,
	}
	qc.recvFlowLimit.Store(1 << 20)
	t.Cleanup(qc.close)
	return qc
}

func quicCloseBufferedStream(t *testing.T, qc *QUICConn) *QUICStream {
	t.Helper()
	qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 0, data: []byte("payload")})
	s := qc.acquireStream(0)
	if s == nil {
		t.Fatal("buffered stream was not admitted")
	}
	if held := qc.server.inFlightBodyBytes.Load(); held != 7 {
		t.Fatalf("global budget before close = %d, want 7", held)
	}
	if held := qc.bodyReserved.Load(); held != 7 {
		t.Fatalf("connection budget before close = %d, want 7", held)
	}
	return s
}

func quicCloseBudget(t *testing.T, qc *QUICConn, want int64) {
	t.Helper()
	if held := qc.server.inFlightBodyBytes.Load(); held != want {
		t.Fatalf("global budget = %d, want %d", held, want)
	}
	if held := qc.bodyReserved.Load(); held != want {
		t.Fatalf("connection budget = %d, want %d", held, want)
	}
}

func quicCloseAwait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	deadline := turbo.Deadline(quicPeerWait)
	for {
		select {
		case <-done:
			return
		default:
		}
		if turbo.Until(deadline) <= 0 {
			t.Fatalf("timed out waiting for %s", what)
		}
		turbo.Sleep(quicPeerPoll)
	}
}

func TestQUICClosePeerCloseReleasesPartialBodies(t *testing.T) {
	srv := New(Config{MaxInFlightBodyBytes: quicCloseProbeBudget})
	srv.Router.Build()
	request := h3AppendHeadersFrame(nil, quicFixGET("/upload"))
	request = quicAppendVarint(request, h3FrameData)
	request = quicAppendVarint(request, 2*quicCloseProbeBodyBytes)
	request = append(request, make([]byte, quicCloseProbeBodyBytes)...)
	for conn := 1; conn <= quicCloseProbeConns; conn++ {
		p := newQUICTestPeerFor(t, srv)
		p.send(quicStreamBytes(0, 0, request, false))
		if held := srv.inFlightBodyBytes.Load(); held < quicCloseProbeBodyBytes {
			t.Fatalf("conn %d: partial request reserved %d bytes, want at least %d", conn, held, quicCloseProbeBodyBytes)
		}
		p.send(quicAppendConnCloseFrame(nil, 0, 0, ""))
		if !p.qc.closed.Load() {
			t.Fatalf("conn %d: peer CONNECTION_CLOSE did not close the connection", conn)
		}
		if held := srv.inFlightBodyBytes.Load(); held != 0 {
			t.Fatalf("conn %d: global body budget leaked after close: %d of %d bytes", conn, held, quicCloseProbeBudget)
		}
		if held := p.qc.bodyReserved.Load(); held != 0 {
			t.Fatalf("conn %d: connection body budget leaked after close: %d", conn, held)
		}
	}
	if !srv.tryReserveBodyBytes(quicCloseProbeReserve) {
		t.Fatal("body budget exhausted after all connections closed")
	}
	srv.releaseBodyBytes(quicCloseProbeReserve)
}

func TestQUICCloseReleasesUnfinishedBody(t *testing.T) {
	qc := quicCloseConn(t)
	s := quicCloseBufferedStream(t, qc)
	qc.releaseStream(s)
	qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 0, offset: 12, data: []byte("tail")})
	if held := qc.bodyReserved.Load(); held <= 7 {
		t.Fatalf("out-of-order data did not reserve additional budget: %d", held)
	}
	qc.close()
	qc.close()
	quicCloseBudget(t, qc, 0)
	if len(qc.streams) != 0 {
		t.Fatalf("closed connection retained %d streams", len(qc.streams))
	}
}

func TestQUICCloseRetainsAcquiredReader(t *testing.T) {
	qc := quicCloseConn(t)
	s := quicCloseBufferedStream(t, qc)
	type readResult struct {
		body []byte
		err  error
	}
	read := make(chan readResult, 1)
	go func() {
		body, err := s.ReadAll()
		read <- readResult{body: body, err: err}
	}()
	deadline := turbo.Deadline(quicPeerWait)
	for {
		s.mu.Lock()
		waiting := s.recvReady != nil
		s.mu.Unlock()
		if waiting {
			break
		}
		if turbo.Until(deadline) <= 0 {
			t.Fatal("reader did not block before close")
		}
		turbo.Sleep(quicPeerPoll)
	}
	qc.close()
	var result readResult
	deadline = turbo.Deadline(quicPeerWait)
	for received := false; !received; {
		select {
		case result = <-read:
			received = true
		default:
			if turbo.Until(deadline) <= 0 {
				t.Fatal("close did not wake reader")
			}
			turbo.Sleep(quicPeerPoll)
		}
	}
	if result.err != nil || !bytes.Equal(result.body, []byte("payload")) {
		t.Fatalf("reader result = %q, %v; want payload, nil", result.body, result.err)
	}
	quicCloseBudget(t, qc, 7)
	if s.conn != qc || s.refCount.Load() != 1 {
		t.Fatalf("reader lost stream ownership: conn=%p refs=%d", s.conn, s.refCount.Load())
	}
	qc.releaseStream(s)
	quicCloseBudget(t, qc, 0)
}

func TestQUICCloseAndFinishReleaseOnce(t *testing.T) {
	for _, order := range []string{"close-first", "finish-first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			qc := quicCloseConn(t)
			s := quicCloseBufferedStream(t, qc)
			s.dispatched.Store(true)
			s.mu.Lock()
			s.awaitingCleanup = true
			s.mu.Unlock()
			switch order {
			case "close-first":
				qc.close()
				qc.finishRequestStream(s)
			case "finish-first":
				qc.finishRequestStream(s)
				qc.close()
			case "concurrent":
				var workers sync.WaitGroup
				workers.Add(2)
				go func() { defer workers.Done(); qc.close() }()
				go func() { defer workers.Done(); qc.finishRequestStream(s) }()
				workers.Wait()
			}
			qc.close()
			qc.finishRequestStream(s)
			if refs := s.refCount.Load(); refs != 1 {
				t.Fatalf("observer references after close and finish = %d, want 1", refs)
			}
			quicCloseBudget(t, qc, 7)
			qc.releaseStream(s)
			quicCloseBudget(t, qc, 0)
		})
	}
}

func TestQUICCloseRetainsRunningHandler(t *testing.T) {
	qc := quicCloseConn(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	cause := make(chan error, 1)
	qc.server.Router.GET("/block", func(req *Request, resp *Response) {
		close(entered)
		<-release
		cause <- req.CancelCause()
		resp.Status(200).String("late response")
	})
	qc.server.Router.Build()
	qc.server.fastDispatch.Store(true)
	request := h3AppendDataFrame(h3AppendHeadersFrame(nil, quicFixGET("/block")), []byte("payload"))
	qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 0, data: request, fin: true})
	s := qc.acquireStream(0)
	if s == nil || qc.bodyReserved.Load() <= 0 {
		t.Fatal("handler fixture did not buffer a request")
	}
	qc.h3 = &H3Conn{qconn: qc, server: qc.server}
	s.dispatched.Store(true)
	qc.activeReqStreams.Add(1)
	go func() { qc.serveRequestStream(s); close(finished) }()
	quicCloseAwait(t, entered, "handler start")
	qc.close()
	if held := qc.bodyReserved.Load(); held != int64(len(request)) || s.conn != qc || s.refCount.Load() != 1 {
		close(release)
		<-finished
		t.Fatalf("close lost running handler ownership: held=%d refs=%d", held, s.refCount.Load())
	}
	close(release)
	quicCloseAwait(t, finished, "handler finish")
	if err := <-cause; !errors.Is(err, ErrClientGone) {
		t.Fatalf("handler cancel cause = %v, want client gone", err)
	}
	quicCloseBudget(t, qc, 0)
}

func TestQUICRetirePreservesReplacement(t *testing.T) {
	qc := quicCloseConn(t)
	old := quicCloseBufferedStream(t, qc)
	qc.streamsMu.Lock()
	delete(qc.streams, old.id)
	qc.streamsMu.Unlock()
	qc.releaseStream(old)
	replacement := getPooledStream(old.id, qc)
	replacement.refCount.Store(1)
	qc.streams[old.id] = replacement
	qc.retireStream(old)
	if got := qc.acquireStream(0); got != replacement {
		t.Fatal("stale retirement removed replacement stream")
	} else {
		qc.releaseStream(got)
	}
	if refs := old.refCount.Load(); refs != 1 {
		t.Fatalf("stale retirement released an unowned map reference: %d", refs)
	}
	qc.releaseStream(old)
	qc.close()
	quicCloseBudget(t, qc, 0)
}

func TestQUICCloseRejectsNewStreams(t *testing.T) {
	qc := quicCloseConn(t)
	qc.close()
	qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 0, data: []byte("late")})
	if len(qc.streams) != 0 {
		t.Fatal("peer stream admitted after close")
	}
	if s := qc.openLocalUniStream(); s != nil {
		t.Fatal("local stream admitted after close")
	}
	quicCloseBudget(t, qc, 0)
}

func TestQUICCloseLocalStreamOwnership(t *testing.T) {
	qc := quicCloseConn(t)
	s := qc.openLocalUniStream()
	if s == nil || s.refCount.Load() != 2 {
		t.Fatalf("local stream must hold map and caller references, got %v", s)
	}
	qc.close()
	if s.conn != qc || s.refCount.Load() != 1 {
		t.Fatal("close recycled a local stream with an active caller")
	}
	if _, err := s.Read(nil); err != io.EOF {
		t.Fatalf("closed local stream Read error = %v, want EOF", err)
	}
	qc.releaseStream(s)
}

func TestQUICCloseRacesLocalStreamCreation(t *testing.T) {
	qc := quicCloseConn(t)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); qc.close() }()
	go func() {
		defer workers.Done()
		if s := qc.openLocalUniStream(); s != nil {
			if err := s.Write([]byte("control")); err != nil && !errors.Is(err, ErrStreamClosed) {
				t.Errorf("local stream write: %v", err)
			}
			qc.releaseStream(s)
		}
	}()
	workers.Wait()
	if len(qc.streams) != 0 {
		t.Fatal("local stream creation raced past close")
	}
}

func TestQUICCloseReleasesBlockedResponse(t *testing.T) {
	qc := quicCloseConn(t)
	s := quicCloseBufferedStream(t, qc)
	s.dispatched.Store(true)
	s.mu.Lock()
	s.awaitingCleanup = true
	s.mu.Unlock()
	if err := s.Write([]byte("blocked response")); err != nil {
		t.Fatal(err)
	}
	qc.stalledSendBytes.Add(s.beginStalledAccounting(1))
	if qc.stalledSendBytes.Load() <= 0 {
		t.Fatal("fixture did not reserve stalled output")
	}
	qc.close()
	if !s.sendBufDrained() || qc.stalledSendBytes.Load() != 0 {
		t.Fatal("close retained unsendable response or stalled accounting")
	}
	if s.refCount.Load() != 1 {
		t.Fatalf("close retained blocked response ownership: %d", s.refCount.Load())
	}
	quicCloseBudget(t, qc, 7)
	qc.releaseStream(s)
	quicCloseBudget(t, qc, 0)
}

func TestQUICCloseH3StartupOwnership(t *testing.T) {
	qc := quicCloseConn(t)
	h3 := &H3Conn{qconn: qc, server: qc.server}
	h3.start()
	if len(qc.streams) != 3 {
		t.Fatalf("H3 startup opened %d streams, want 3", len(qc.streams))
	}
	for _, s := range qc.streams {
		if s.refCount.Load() != 1 {
			t.Fatalf("H3 startup retained caller ownership: %d references", s.refCount.Load())
		}
	}
	qc.close()
	h3.start()
}

func TestQUICCloseRacesH3Startup(t *testing.T) {
	qc := quicCloseConn(t)
	h3 := &H3Conn{qconn: qc, server: qc.server}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); qc.close() }()
	go func() { defer workers.Done(); h3.start() }()
	workers.Wait()
	if len(qc.streams) != 0 {
		t.Fatal("H3 startup admitted streams after close")
	}
}

func TestQUICCloseDuringQPACKStartup(t *testing.T) {
	qc := quicCloseConn(t)
	h3 := &H3Conn{qconn: qc, server: qc.server}
	qc.writeMu.Lock()
	finished := make(chan struct{})
	go func() { h3.sendQPACKStreams(); close(finished) }()
	deadline := turbo.Deadline(quicPeerWait)
	for {
		encoder := qc.acquireStream(3)
		if encoder != nil {
			qc.releaseStream(encoder)
			break
		}
		if turbo.Until(deadline) <= 0 {
			qc.writeMu.Unlock()
			<-finished
			t.Fatal("QPACK encoder was not admitted before close")
		}
		turbo.Sleep(quicPeerPoll)
	}
	qc.close()
	qc.writeMu.Unlock()
	quicCloseAwait(t, finished, "QPACK startup to stop after close")
	if len(qc.streams) != 0 {
		t.Fatal("QPACK decoder was admitted after close")
	}
}

func TestQUICCloseRacesPeerStreamCreation(t *testing.T) {
	qc := quicCloseConn(t)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); qc.close() }()
	go func() {
		defer workers.Done()
		qc.handleStreamFrameIncoming(quicStreamFrame{streamID: 0, data: []byte("payload")})
	}()
	workers.Wait()
	if len(qc.streams) != 0 {
		t.Fatal("peer stream creation raced past close")
	}
	quicCloseBudget(t, qc, 0)
}
