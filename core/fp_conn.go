//go:build linux

package core

import (
	"golang.org/x/sys/unix"
)

const (
	connConnecting = iota
	connHandshaking
	connReady
	connClosed
)

const fpMaxBackendConns = 4096

type transport interface {
	start(c *backendConn) error
	feed(c *backendConn, raw []byte) error
	wrapOut(c *backendConn, plain []byte) error
	negotiatedALPN() string
}

type protoHandler interface {
	connReady(c *backendConn) error
	attach(c *backendConn) error
	onData(c *backendConn, data []byte) error
	onPeerClose(c *backendConn)
	canIdle(c *backendConn) bool
}

type backendConn struct {
	fd           int
	loop         *eventLoop
	key          poolKey
	state        int8
	reused       bool
	gotBytes     bool
	inIdle       bool
	transport    transport
	proto        protoHandler
	cur          *Exchange
	h2           *h2Conn
	wbuf         byteBuffer
	rbuf         byteBuffer
	h1           h1Parser
	idleDeadline int64
}

func (l *eventLoop) newConn(ex *Exchange) {
	if l.liveConns >= fpMaxBackendConns {
		l.finish(ex, fpErrTooManyConns)
		return
	}
	fd, err := dialNonBlocking(ex.ip, ex.port)
	if err != nil {
		l.finish(ex, fpErrDialFailed)
		return
	}
	c := &backendConn{fd: fd, loop: l, key: ex.key, state: connConnecting}
	c.transport = l.newTransport(ex)
	if ex.key.h2 {
		c.proto = &l.h2proto
		c.h2init()
		l.h2conns[ex.key] = c
	} else {
		c.proto = &l.h1proto
	}
	l.ensureFD(fd)
	l.conns[fd] = c
	l.liveConns++
	ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLOUT | unix.EPOLLRDHUP | unix.EPOLLET, Fd: int32(fd)}
	if err := unix.EpollCtl(l.ep, unix.EPOLL_CTL_ADD, fd, &ev); err != nil {
		l.conns[fd] = nil
		_ = unix.Close(fd)
		l.finish(ex, fpErrDialFailed)
		return
	}
	l.assign(c, ex)
}

func (l *eventLoop) assign(c *backendConn, ex *Exchange) {
	if c.key.h2 {
		c.h2.pending = append(c.h2.pending, ex)
		if c.state == connReady {
			l.h2proto.flushPending(c)
		}
		return
	}
	c.cur = ex
	if c.state == connReady {
		if err := l.h1proto.attach(c); err != nil {
			l.closeConn(c, err)
		}
	}
}

func (c *backendConn) send(p []byte) {
	_ = c.transport.wrapOut(c, p)
}

func (l *eventLoop) onConnConnected(c *backendConn) {
	if err := socketError(c.fd); err != nil {
		l.closeConn(c, fpErrDialFailed)
		return
	}
	c.state = connHandshaking
	if err := c.transport.start(c); err != nil {
		l.closeConn(c, err)
		return
	}
	l.flushWrites(c)
}

func (l *eventLoop) onTransportReady(c *backendConn) {
	c.state = connReady
	if err := c.proto.connReady(c); err != nil {
		l.closeConn(c, err)
	}
}

func (l *eventLoop) readable(c *backendConn) {
	for c.state != connClosed {
		n, err := unix.Read(c.fd, l.scratch)
		if n > 0 {
			c.gotBytes = true
			if ferr := c.transport.feed(c, l.scratch[:n]); ferr != nil {
				l.closeConn(c, ferr)
				return
			}
			if n < len(l.scratch) {
				return
			}
			continue
		}
		if n == 0 {
			l.peerClosed(c)
			return
		}
		if err == unix.EAGAIN {
			return
		}
		if err == unix.EINTR {
			continue
		}
		l.closeConn(c, err)
		return
	}
}

func (l *eventLoop) peerClosed(c *backendConn) {
	if c.state == connReady && !c.key.h2 && c.cur != nil {
		c.proto.onPeerClose(c)
		if c.state == connClosed {
			return
		}
	}
	l.closeConn(c, fpErrConnClosed)
}

func (l *eventLoop) flushWrites(c *backendConn) {
	for c.state != connClosed {
		p := c.wbuf.unread()
		if len(p) == 0 {
			return
		}
		n, err := unix.Write(c.fd, p)
		if n > 0 {
			c.wbuf.consume(n)
			continue
		}
		if err == unix.EAGAIN {
			c.wbuf.compact()
			return
		}
		if err == unix.EINTR {
			continue
		}
		l.closeConn(c, err)
		return
	}
}

func (l *eventLoop) closeConn(c *backendConn, err error) {
	if c.state == connClosed {
		return
	}
	c.state = connClosed
	l.liveConns--
	if c.fd >= 0 {
		_ = unix.Close(c.fd)
		if c.fd < len(l.conns) {
			l.conns[c.fd] = nil
		}
		c.fd = -1
	}
	l.removeIdle(c)
	if c.key.h2 && l.h2conns[c.key] == c {
		delete(l.h2conns, c.key)
	}
	if c.h2 != nil {
		c.h2.failAll(l, c, err)
		return
	}
	if ex := c.cur; ex != nil {
		c.cur = nil
		l.failOrRetry(ex, err, c)
	}
}

func (l *eventLoop) failOrRetry(ex *Exchange, err error, c *backendConn) {
	if err == nil {
		err = fpErrConnClosed
	}
	if c.reused && !c.gotBytes && !ex.retried && err != fpErrTimeout {
		ex.retried = true
		l.startExchange(ex)
		return
	}
	l.finish(ex, err)
}

func (l *eventLoop) finish(ex *Exchange, err error) {
	if ex.finished {
		return
	}
	ex.finished = true
	ex.err = err
	if ex.inbound != nil {
		l.onForwardDone(ex)
		return
	}
	close(ex.done)
}
