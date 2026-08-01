//go:build linux && amd64

package core

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// newWorkerForBackendTest builds an epoll worker without a listener, so the
// backend half can be exercised on its own. The worker's run loop is not
// started; the test drives epoll_wait itself to observe dispatch directly.
func newWorkerForBackendTest(t *testing.T) *epollWorker {
	t.Helper()
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create1: %v", err)
	}
	w := &epollWorker{
		server:     New(Config{HTTPAddr: "-", LogRequests: false}),
		epfd:       epfd,
		listenerFD: -1,
		wakeFd:     -1,
		conns:      make([]*epollConn, 64),
		events:     make([]unix.EpollEvent, epollEventBatch),
	}
	w.initBackendLoop()
	t.Cleanup(func() {
		w.be.closeAll()
		_ = unix.Close(epfd)
	})
	return w
}

// A backend socket registered by the worker's beLoop must come back from
// epoll_wait tagged as a backend, and must never be looked up in w.conns --
// that array is indexed by the same descriptor numbers and holds client
// connections.
func TestWorkerBackendEventCarriesClassTag(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			accepted <- c
		}
	}()

	w := newWorkerForBackendTest(t)
	addr := ln.Addr().(*net.TCPAddr)
	var ip [4]byte
	copy(ip[:], addr.IP.To4())

	ex := &Exchange{req: &fpRequest{}}
	ex.ip = ip
	ex.port = uint16(addr.Port)
	ex.key = poolKey{authority: addr.String()}
	ex.deadline = w.be.nowNano() + int64(5*time.Second)
	ex.done = make(chan struct{})

	w.be.newConn(ex)
	if w.be.liveConns != 1 {
		t.Fatalf("liveConns = %d, want 1", w.be.liveConns)
	}

	var beFD = -1
	for fd, c := range w.be.conns {
		if c != nil {
			beFD = fd
		}
	}
	if beFD < 0 {
		t.Fatal("backend conn was not registered in the beLoop table")
	}
	if beFD < len(w.conns) && w.conns[beFD] != nil {
		t.Fatal("backend descriptor must not occupy the client conn table")
	}

	srvConn := <-accepted
	defer srvConn.Close()

	// The connect completion arrives as EPOLLOUT on the backend descriptor.
	events := make([]unix.EpollEvent, 16)
	deadline := time.Now().Add(3 * time.Second)
	sawBackendTag := false
	for time.Now().Before(deadline) && !sawBackendTag {
		n, werr := unix.EpollWait(w.epfd, events, 200)
		if werr == unix.EINTR {
			continue
		}
		if werr != nil {
			t.Fatalf("epoll_wait: %v", werr)
		}
		for i := 0; i < n; i++ {
			if int(events[i].Fd) != beFD {
				continue
			}
			if events[i].Pad != epollFDClassBackend {
				t.Fatalf("Pad = %d for a backend descriptor, want %d",
					events[i].Pad, epollFDClassBackend)
			}
			sawBackendTag = true
		}
	}
	if !sawBackendTag {
		t.Fatal("no tagged event was delivered for the backend descriptor")
	}
}

// Dialling now happens inside the event-processing loop, so a descriptor closed
// by one event in a batch can be handed straight back by socket() to a
// connection created later in the same batch. Any leftover event for that
// descriptor belongs to the previous owner and must be dropped, or it lands on
// an unrelated connection.
func TestWorkerBackendIntraBatchFDReuseIsDropped(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			defer c.Close()
		}
	}()

	w := newWorkerForBackendTest(t)
	addr := ln.Addr().(*net.TCPAddr)
	var ip [4]byte
	copy(ip[:], addr.IP.To4())

	newExchange := func() *Exchange {
		ex := &Exchange{req: &fpRequest{}}
		ex.ip = ip
		ex.port = uint16(addr.Port)
		ex.key = poolKey{authority: addr.String()}
		ex.deadline = w.be.nowNano() + int64(5*time.Second)
		ex.done = make(chan struct{})
		return ex
	}

	// Batch N: create a connection, then close it and immediately dial again.
	// The replacement very often lands on the same descriptor.
	w.be.seq++
	first := newExchange()
	w.be.newConn(first)
	var firstFD = -1
	for fd, c := range w.be.conns {
		if c != nil {
			firstFD = fd
		}
	}
	if firstFD < 0 {
		t.Fatal("no backend conn registered")
	}
	w.be.closeConn(w.be.conns[firstFD], fpErrConnClosed)

	second := newExchange()
	w.be.newConn(second)

	replacement := w.be.conns[firstFD]
	if replacement == nil {
		t.Skip("the kernel handed back a different descriptor; reuse not exercised")
	}
	if !w.be.staleInBatch(replacement) {
		t.Fatal("a conn created during the current batch must be flagged stale for that batch")
	}

	// A leftover event from the previous owner must not reach the replacement.
	before := replacement.state
	w.backendEvent(firstFD, unix.EPOLLERR)
	if replacement.state != before {
		t.Fatal("a stale intra-batch event was applied to the replacement connection")
	}

	// On the next batch the replacement is legitimate and events apply again.
	w.be.seq++
	if w.be.staleInBatch(replacement) {
		t.Fatal("the replacement must be live once the batch advances")
	}
	w.backendEvent(firstFD, unix.EPOLLERR)
	if replacement.state != connClosed {
		t.Fatal("a real error event should have closed the replacement connection")
	}
}
