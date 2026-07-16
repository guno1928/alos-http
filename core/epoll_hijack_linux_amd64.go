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

func (w *epollWorker) tlsH1Attacher(c *epollConn, consumed int) func(*Request) net.Conn {
	return func(req *Request) net.Conn {
		if req.connTakenOver {
			return req.conn
		}
		reader := c.appReader
		writer := c.appWriter
		rawPrefix := append([]byte(nil), c.readBuf[:c.readN]...)
		decOff := c.appBufOff + consumed
		var decryptedPrefix []byte
		if decOff < len(c.appBuf) {
			decryptedPrefix = append([]byte(nil), c.appBuf[decOff:]...)
		}
		nc, ok := w.detachConnFd(c)
		if !ok {
			return nil
		}
		req.tlsReader = reader
		req.tlsWriter = writer
		req.hdrBuf = make([]byte, 5)
		req.hijackReadBuf = decryptedPrefix
		handed := net.Conn(nc)
		if len(rawPrefix) > 0 {
			handed = &prefixConn{Conn: nc, reader: io.MultiReader(bytes.NewReader(rawPrefix), nc)}
		}
		tracked := w.server.trackHandoffConn(handed)
		if tracked == nil {
			_ = nc.Close()
			return nil
		}
		req.connTakenOver = true
		req.attachConn = nil
		req.conn = tracked
		return tracked
	}
}

func (w *epollWorker) plainH1Attacher(c *epollConn, gen uint32) func(*Request) net.Conn {
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
			prefix := append([]byte(nil), c.readBuf[c.h1Off:c.readN]...)
			nc, ok := w.detachConnFd(c)
			if !ok {
				return
			}
			handed := nc
			if len(prefix) > 0 {
				handed = &prefixConn{Conn: nc, reader: io.MultiReader(bytes.NewReader(prefix), nc)}
			}
			tracked := w.server.trackHandoffConn(handed)
			if tracked == nil {
				_ = nc.Close()
				return
			}
			req.connTakenOver = true
			req.attachConn = nil
			req.conn = tracked
		})
		<-done
		return req.conn
	}
}
