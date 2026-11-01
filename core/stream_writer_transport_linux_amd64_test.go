package core

import (
	"bufio"
	"bytes"
	"net/http"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type streamTransportFixture struct {
	worker *epollWorker
	conn   *epollConn
	req    *Request
	resp   *Response
	stream *H2Stream
	gen    uint32
}

func newStreamTransportFixture(t *testing.T, protocol string, requestTLS bool) *streamTransportFixture {
	t.Helper()
	worker := newWorkerForBackendTest(t)
	worker.taskCh = make(chan func(*epollWorker), 4)
	worker.server.altSvc.Store(newAltSvcHeader(443))
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := worker.pool.get()
	conn.fd, conn.worker, conn.tls, conn.inFlight = pair[0], worker, requestTLS, 1
	worker.conns = make([]*epollConn, conn.fd+1)
	worker.conns[conn.fd] = conn
	fixture := &streamTransportFixture{worker: worker, conn: conn, req: &conn.req, resp: &conn.resp, gen: conn.generation}
	conn.protocol = plainConnProtoH1
	if protocol == "h2" {
		conn.protocol = plainConnProtoH2
		fixture.stream = StreamPool.Get().(*H2Stream)
		fixture.stream.Reset()
		fixture.stream.ID, fixture.stream.dispatchGen, fixture.stream.asyncBusy = 1, conn.generation, true
		fixture.req, fixture.resp = &fixture.stream.req, &fixture.stream.resp
		conn.h2.linkBusy(fixture.stream)
	}
	fixture.req.Reset()
	fixture.resp.Reset()
	fixture.req.h2Stream = fixture.stream
	fixture.req.Method, fixture.req.IsTLS = "GET", requestTLS
	fixture.req.server, fixture.req.swFactory = worker.server, conn
	fixture.resp.lazyReq = fixture.req
	t.Cleanup(func() {
		if conn.fd >= 0 {
			worker.closeConn(conn)
		}
		for len(worker.taskCh) > 0 {
			(<-worker.taskCh)(worker)
		}
		if fixture.stream != nil {
			conn.finishH2Dispatch(worker, fixture.gen, 1, fixture.stream)
		} else {
			conn.finishH1Dispatch(worker, fixture.gen, false)
		}
		_ = unix.Close(pair[1])
	})
	return fixture
}

func streamTransportHeaders(t *testing.T, fixture *streamTransportFixture, requestTLS bool) {
	t.Helper()
	if fixture.req.IsTLS != requestTLS {
		t.Fatal("request transport snapshot changed during close")
	}
	var fields [][2]string
	switch writer := fixture.resp.sw.(type) {
	case *epollH1StreamWriter:
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(writer.pending)), nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatalf("stream status = %d, want 200", response.StatusCode)
		}
		for name, values := range response.Header {
			for _, value := range values {
				fields = append(fields, [2]string{name, value})
			}
		}
	case *epollH2StreamWriter:
		var err error
		fields, err = NewHpackDecoder().Decode(writer.header)
		if err != nil {
			t.Fatal(err)
		}
		status := ""
		for _, field := range fields {
			if field[0] == ":status" {
				status = field[1]
			}
		}
		if status != "200" {
			t.Fatalf("stream status = %q, want 200", status)
		}
	default:
		t.Fatalf("lazy SSE did not create a stream writer: %T", fixture.resp.sw)
	}
	contentType, altCount := "", 0
	for _, field := range fields {
		if EqualFoldASCII(field[0], "content-type") {
			contentType = field[1]
		}
		if EqualFoldASCII(field[0], "alt-svc") {
			altCount++
			if field[1] != `h3=":443"; ma=86400` {
				t.Fatalf("Alt-Svc = %q, want advertised H3 endpoint", field[1])
			}
		}
	}
	if contentType != "text/event-stream" {
		t.Fatalf("content type = %q, want real SSE response", contentType)
	}
	wantAlt := 0
	if requestTLS {
		wantAlt = 1
	}
	if altCount != wantAlt {
		t.Fatalf("request TLS=%v: Alt-Svc count = %d, want %d", requestTLS, altCount, wantAlt)
	}
}

func TestStreamWriterUsesRequestTransport(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, requestTLS := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "/plain", true: "/tls"}[requestTLS], func(t *testing.T) {
				fixture := newStreamTransportFixture(t, protocol, requestTLS)
				fixture.conn.tls = !requestTLS
				if fixture.resp.SSE() == nil {
					t.Fatal("SSE writer unavailable")
				}
				streamTransportHeaders(t, fixture, requestTLS)
			})
		}
	}
}

func TestStreamWriterAfterCloseKeepsRequestTransport(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, requestTLS := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "/plain", true: "/tls"}[requestTLS], func(t *testing.T) {
				fixture := newStreamTransportFixture(t, protocol, requestTLS)
				fixture.worker.closeConn(fixture.conn)
				if fixture.conn.fd >= 0 || fixture.conn.tls || fixture.conn.inFlight != 1 {
					t.Fatal("worker close did not reset transport while preserving handler ownership")
				}
				if fixture.resp.SSE() == nil {
					t.Fatal("lazy SSE writer unavailable after close")
				}
				streamTransportHeaders(t, fixture, requestTLS)
			})
		}
	}
}

func TestStreamWriterRacesClose(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		for _, requestTLS := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "/plain", true: "/tls"}[requestTLS], func(t *testing.T) {
				fixture := newStreamTransportFixture(t, protocol, requestTLS)
				start := make(chan struct{})
				var workers sync.WaitGroup
				workers.Add(2)
				go func() {
					defer workers.Done()
					<-start
					fixture.worker.closeConn(fixture.conn)
				}()
				go func() {
					defer workers.Done()
					<-start
					if fixture.resp.SSE() == nil {
						t.Error("lazy SSE writer unavailable during close")
					}
				}()
				close(start)
				workers.Wait()
				if fixture.conn.fd >= 0 || fixture.conn.tls || fixture.conn.inFlight != 1 {
					t.Fatal("close race did not preserve pending handler completion")
				}
				streamTransportHeaders(t, fixture, requestTLS)
			})
		}
	}
}
