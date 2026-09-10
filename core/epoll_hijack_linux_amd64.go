//go:build linux && amd64

package core

import (
	"bytes"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func epollDetachToConn(fd int) (net.Conn, error) {
	f := os.NewFile(uintptr(fd), "epoll-conn")
	if f == nil {
		return nil, os.ErrInvalid
	}
	nc, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return nc, nil
}

func (w *epollWorker) detachConnFd(c *epollConn) (net.Conn, bool) {
	if c.fd < 0 {
		return nil, false
	}
	fd := c.fd
	_ = unix.EpollCtl(w.epfd, unix.EPOLL_CTL_DEL, fd, nil)
	if fd < len(w.conns) {
		w.conns[fd] = nil
	}
	nc, err := epollDetachToConn(fd)
	c.fd = -1
	if err != nil {
		return nil, false
	}
	return nc, true
}

func (w *epollWorker) h1Attacher(c *epollConn, gen uint32) func(*Request) net.Conn {
	return func(req *Request) net.Conn {
		if req.connTakenOver {
			return req.conn
		}
		done := make(chan struct{})
		w.postTask(func(w *epollWorker) {
			defer close(done)
			if c.fd < 0 || c.generation != gen {
				return
			}
			w.handoffH1Conn(c, req)
		})
		<-done
		return req.conn
	}
}

func (w *epollWorker) inlineH1Attacher(c *epollConn) func(*Request) net.Conn {
	return func(req *Request) net.Conn {
		if req.connTakenOver {
			return req.conn
		}
		if c.fd >= 0 {
			w.handoffH1Conn(c, req)
		}
		return req.conn
	}
}

func (w *epollWorker) handoffH1Conn(c *epollConn, req *Request) {
	var rawPrefix, decryptedPrefix []byte
	if c.tls {
		rawPrefix = append([]byte(nil), c.readBuf[:c.readN]...)
		if c.appBufOff < len(c.appBuf) {
			decryptedPrefix = append([]byte(nil), c.appBuf[c.appBufOff:]...)
		}
	} else {
		rawPrefix = append([]byte(nil), c.readBuf[c.h1Off:c.readN]...)
	}
	reader := c.appReader
	writer := c.appWriter
	nc, ok := w.detachConnFd(c)
	if !ok {
		return
	}
	if c.tls {
		req.tlsReader = reader
		req.tlsWriter = writer
		req.hdrBuf = make([]byte, 5)
		req.hijackReadBuf = decryptedPrefix
	}
	handed := net.Conn(nc)
	if len(rawPrefix) > 0 {
		handed = &prefixConn{Conn: nc, reader: io.MultiReader(bytes.NewReader(rawPrefix), nc)}
	}
	ipKey, fromInFlight := w.handoffIPSlot(c, req)
	tracked := w.server.trackHandoffConn(handed, ipKey, fromInFlight)
	if tracked == nil {
		_ = nc.Close()
		return
	}
	c.ipHeld = false
	c.ipKey = ""
	req.connTakenOver = true
	req.attachConn = nil
	req.conn = tracked
}

func (w *epollWorker) handoffIPSlot(c *epollConn, req *Request) (string, bool) {
	if w.server.trustedProxies.active {
		if w.server.perIPLimiter == nil {
			return "", false
		}
		return extractIP(req.RemoteAddr), true
	}
	return c.ipKey, false
}
