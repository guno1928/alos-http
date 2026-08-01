//go:build linux

package core

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	loopEventBatch  = 256
	loopScratchSize = 64 * 1024
	maxEpollWaitMs  = 1000
)

type eventLoop struct {
	beLoop
	wakeFd      int
	q           mpscQueue
	sleeping    atomic.Int32
	quit        atomic.Int32
	exFree      *Exchange
	events      []unix.EpollEvent
	wakeBuf     [8]byte
}

func newEventLoop(cfg *fpConfig) (*eventLoop, error) {
	ep, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	wakeFd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		_ = unix.Close(ep)
		return nil, err
	}
	l := &eventLoop{
		wakeFd: wakeFd,
		events: make([]unix.EpollEvent, loopEventBatch),
	}
	l.beLoop.init(ep, cfg, l)
	l.q.init()
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(wakeFd)}
	if err := unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, wakeFd, &ev); err != nil {
		_ = unix.Close(ep)
		_ = unix.Close(wakeFd)
		return nil, err
	}
	return l, nil
}

func (l *eventLoop) submit(ex *Exchange) {
	l.q.push(&ex.node)
	if l.sleeping.Swap(0) == 1 {
		var one = [8]byte{1, 0, 0, 0, 0, 0, 0, 0}
		_, _ = unix.Write(l.wakeFd, one[:])
	}
}

func exchangeFromNode(n *mpscNode) *Exchange {
	return (*Exchange)(unsafe.Pointer(n))
}

// stop asks the loop to exit and wakes it so it notices promptly.
func (l *eventLoop) stop() {
	l.quit.Store(1)
	var one = [8]byte{1, 0, 0, 0, 0, 0, 0, 0}
	_, _ = unix.Write(l.wakeFd, one[:])
}

// release closes the connections this loop owns along with its epoll and wake
// descriptors, so a closed client does not leak a thread and two fds per loop.
func (l *eventLoop) release() {
	l.closeAll()
	_ = unix.Close(l.ep)
	_ = unix.Close(l.wakeFd)
}

// run drives this loop's epoll set. The loop keeps no thread affine state, so
// it deliberately does not lock an OS thread: letting the scheduler place it
// measured faster and avoids oversubscribing cores when loops outnumber them.
func (l *eventLoop) run() {
	for {
		if l.quit.Load() == 1 {
			l.release()
			return
		}
		drained := false
		for {
			n := l.q.pop()
			if n == nil {
				break
			}
			drained = true
			l.startExchange(exchangeFromNode(n))
		}
		timeout := l.nextTimeoutMs()
		if !drained && timeout != 0 {
			l.sleeping.Store(1)
			if n := l.q.pop(); n != nil {
				l.sleeping.Store(0)
				l.startExchange(exchangeFromNode(n))
				timeout = 0
			}
		}
		l.seq++
		nev, err := unix.EpollWait(l.ep, l.events, timeout)
		l.sleeping.Store(0)
		if err != nil && err != unix.EINTR {
			return
		}
		for i := 0; i < nev; i++ {
			fd := int(l.events[i].Fd)
			evs := l.events[i].Events
			if fd == l.wakeFd {
				_, _ = unix.Read(l.wakeFd, l.wakeBuf[:])
				continue
			}
			if fd < 0 || fd >= len(l.conns) {
				continue
			}
			c := l.conns[fd]
			if c == nil || c.state == connClosed || l.staleInBatch(c) {
				continue
			}
			if evs&unix.EPOLLERR != 0 {
				err := socketError(c.fd)
				if err == nil {
					err = fpErrConnClosed
				}
				if c.state == connConnecting {
					err = fpErrDialFailed
				}
				l.closeConn(c, err)
				continue
			}
			if c.state == connConnecting && evs&(unix.EPOLLOUT|unix.EPOLLHUP) != 0 {
				l.onConnConnected(c)
				if c.state == connClosed {
					continue
				}
			}
			if evs&(unix.EPOLLIN|unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 {
				l.readable(c)
				if c.state == connClosed {
					continue
				}
			}
			if evs&unix.EPOLLOUT != 0 && c.wbuf.length() > 0 {
				l.flushWrites(c)
			}
		}
		l.maybeSweep(l.nowNano())
	}
}

// exchangeDone is the beSink terminal callback. This loop is an outbound
// client, so a finished exchange with no waiter simply returns to the freelist.
func (l *eventLoop) exchangeDone(ex *Exchange) {
	l.exPut(ex)
}

func (l *eventLoop) exGet() *Exchange {
	ex := l.exFree
	if ex != nil {
		l.exFree = ex.pnext
		*ex = Exchange{req: ex.req}
		return ex
	}
	return &Exchange{req: &fpRequest{}}
}

func (l *eventLoop) exPut(ex *Exchange) {
	req := ex.req
	*req = fpRequest{}
	*ex = Exchange{req: req}
	ex.pnext = l.exFree
	l.exFree = ex
}

// The remaining sink methods describe where a response goes. This loop serves
// the outbound client, so a caller that supplied an UpstreamStream receives the
// response as it arrives and everything else gets it buffered.

func (l *eventLoop) shouldStreamResponse(c *backendConn, contentLen int64) bool {
	return c.cur != nil && c.cur.sink != nil
}

func (l *eventLoop) beginStreamResponse(c *backendConn, p *h1Parser, contentLen int64) {
	ex := c.cur
	if ex == nil || ex.sink == nil || ex.sink.OnHeaders == nil {
		return
	}
	if err := ex.sink.OnHeaders(p.status, p.stringHeaders()); err != nil {
		l.closeConn(c, err)
	}
}

func (l *eventLoop) streamResponseChunk(c *backendConn, data []byte) {
	ex := c.cur
	if ex == nil || ex.sink == nil || ex.sink.OnBody == nil {
		return
	}
	if err := ex.sink.OnBody(data); err != nil {
		l.closeConn(c, err)
	}
}

func (l *eventLoop) endStreamResponse(ex *Exchange) {
	if ex.done != nil {
		close(ex.done)
		return
	}
	l.exPut(ex)
}

// Upgrades are not part of the outbound client contract, so a 101 here is a
// protocol error rather than a tunnel.
func (l *eventLoop) beginTunnel(c *backendConn, p *h1Parser) bool { return false }

func (l *eventLoop) tunnelToClient(c *backendConn, data []byte) {}

func (l *eventLoop) closeTunnelPeer(c *backendConn) {}
