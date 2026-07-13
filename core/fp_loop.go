//go:build linux

package core

import (
	"runtime"
	"sync/atomic"
	"unsafe"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	loopEventBatch  = 256
	loopScratchSize = 64 * 1024
	maxEpollWaitMs  = 1000
)

type eventLoop struct {
	ep       int
	wakeFd   int
	q        mpscQueue
	sleeping atomic.Int32
	cfg          *fpConfig
	conns        []*backendConn
	inconns      []*inConn
	listenFd     int
	proxyRoutes *routeTable
	idle         map[poolKey][]*backendConn
	h2conns      map[poolKey]*backendConn
	lastSweep    int64
	liveConns    int
	exFree       *Exchange
	events   []unix.EpollEvent
	scratch  []byte
	serBuf   []byte
	h1proto  h1Proto
	h2proto  h2Proto
	wakeBuf  [8]byte
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
		ep:       ep,
		wakeFd:   wakeFd,
		listenFd: -1,
		cfg:      cfg,
		idle:     make(map[poolKey][]*backendConn),
		h2conns:  make(map[poolKey]*backendConn),
		events:   make([]unix.EpollEvent, loopEventBatch),
		scratch:  make([]byte, loopScratchSize),
	}
	l.q.init()
	ev := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(wakeFd)}
	if err := unix.EpollCtl(ep, unix.EPOLL_CTL_ADD, wakeFd, &ev); err != nil {
		_ = unix.Close(ep)
		_ = unix.Close(wakeFd)
		return nil, err
	}
	return l, nil
}

func (l *eventLoop) nowNano() int64 {
	return turbo.UnixNano()
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

func (l *eventLoop) run() {
	runtime.LockOSThread()
	for {
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
			if fd == l.listenFd {
				l.acceptLoop()
				continue
			}
			if fd >= 0 && fd < len(l.inconns) {
				if ic := l.inconns[fd]; ic != nil {
					if evs&(unix.EPOLLIN|unix.EPOLLRDHUP|unix.EPOLLHUP) != 0 {
						l.inboundReadable(ic)
					}
					if !ic.closed && evs&unix.EPOLLOUT != 0 {
						l.inboundWritable(ic)
					}
					continue
				}
			}
			if fd < 0 || fd >= len(l.conns) {
				continue
			}
			c := l.conns[fd]
			if c == nil || c.state == connClosed {
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

func (l *eventLoop) ensureFD(fd int) {
	for fd >= len(l.conns) {
		l.conns = append(l.conns, nil)
	}
}

func (l *eventLoop) startExchange(ex *Exchange) {
	now := l.nowNano()
	if now >= ex.deadline {
		l.finish(ex, fpErrTimeout)
		return
	}
	if ex.key.h2 {
		if c := l.h2conns[ex.key]; c != nil && c.state != connClosed && !c.h2.goAway {
			l.assign(c, ex)
			return
		}
		l.newConn(ex)
		return
	}
	list := l.idle[ex.key]
	for len(list) > 0 {
		c := list[len(list)-1]
		list = list[:len(list)-1]
		l.idle[ex.key] = list
		c.inIdle = false
		if c.state != connReady {
			continue
		}
		if now > c.idleDeadline {
			l.closeConn(c, nil)
			continue
		}
		c.reused = true
		l.assign(c, ex)
		return
	}
	l.newConn(ex)
}

func (l *eventLoop) newTransport(ex *Exchange) transport {
	if ex.key.tls {
		return newTLSTransport(ex)
	}
	return &plainTransport{h2: ex.key.h2}
}

func (l *eventLoop) removeIdle(c *backendConn) {
	if !c.inIdle {
		return
	}
	c.inIdle = false
	list := l.idle[c.key]
	for i, v := range list {
		if v == c {
			list[i] = list[len(list)-1]
			list[len(list)-1] = nil
			l.idle[c.key] = list[:len(list)-1]
			return
		}
	}
}

func (l *eventLoop) idlePut(c *backendConn) {
	list := l.idle[c.key]
	if len(list) >= l.cfg.MaxIdlePerBackend {
		l.closeConn(c, nil)
		return
	}
	c.inIdle = true
	c.reused = false
	c.idleDeadline = l.nowNano() + l.cfg.IdleTimeout.Nanoseconds()
	l.idle[c.key] = append(list, c)
}

func (l *eventLoop) completeH1(c *backendConn) {
	ex := c.cur
	c.cur = nil
	p := &c.h1
	ex.resp.Status = p.status
	if ex.inbound != nil {
		ex.resp.Headers = p.headers
	} else {
		ex.resp.Headers = append([][2]string(nil), p.headers...)
	}
	ex.resp.Body = p.body
	p.body = nil
	l.finish(ex, nil)
	if c.proto.canIdle(c) {
		l.idlePut(c)
		return
	}
	l.closeConn(c, nil)
}
