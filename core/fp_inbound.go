//go:build linux

package core

import (
	"bytes"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	inPhaseHeaders = iota
	inPhaseBody
)

const (
	fpMaxInboundBody = 8 << 20
	fpInboundIdleNS  = int64(15 * 1e9)
)

type inConn struct {
	fd        int
	loop      *eventLoop
	rbuf      byteBuffer
	wbuf      byteBuffer
	ex        *Exchange
	phase     int8
	keepAlive bool
	deadline  int64
	remaining int64
	method    string
	path      string
	host      string
	clientIP  string
	headers   [][2]string
	body      []byte
	closed    bool
	wantWrite bool
}

func (l *eventLoop) acceptLoop() {
	for {
		fd, sa, err := unix.Accept4(l.listenFd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
		if err != nil {
			return
		}
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		ic := &inConn{fd: fd, loop: l, keepAlive: true}
		ic.deadline = l.nowNano() + fpInboundIdleNS
		if in4, ok := sa.(*unix.SockaddrInet4); ok {
			ic.clientIP = ipv4String(in4.Addr)
		}
		l.ensureInFD(fd)
		l.inconns[fd] = ic
		l.liveInconns++
		ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLRDHUP | unix.EPOLLET, Fd: int32(fd)}
		if unix.EpollCtl(l.ep, unix.EPOLL_CTL_ADD, fd, &ev) != nil {
			l.inconns[fd] = nil
			l.liveInconns--
			_ = unix.Close(fd)
		}
	}
}

func (l *eventLoop) inboundReadable(ic *inConn) {
	ic.deadline = l.nowNano() + fpInboundIdleNS
	for {
		n, err := unix.Read(ic.fd, l.scratch)
		if n > 0 {
			ic.rbuf.write(l.scratch[:n])
			if n < len(l.scratch) {
				break
			}
			continue
		}
		if n == 0 {
			l.closeInbound(ic)
			return
		}
		if err == unix.EAGAIN {
			break
		}
		if err == unix.EINTR {
			continue
		}
		l.closeInbound(ic)
		return
	}
	if err := l.inboundParse(ic); err != nil {
		l.closeInbound(ic)
	}
}

func (l *eventLoop) inboundParse(ic *inConn) error {
	for ic.ex == nil {
		switch ic.phase {
		case inPhaseHeaders:
			data := ic.rbuf.unread()
			idx := bytes.Index(data, fpCrlfcrlf)
			if idx < 0 {
				if len(data) > l.cfg.MaxHeaderBytes {
					return fpErrHeaderTooLarge
				}
				return nil
			}
			if err := ic.parseRequest(data[:idx]); err != nil {
				return err
			}
			ic.rbuf.consume(idx + 4)
			if ic.remaining > 0 {
				ic.phase = inPhaseBody
				continue
			}
			l.forward(ic)
			return nil
		case inPhaseBody:
			data := ic.rbuf.unread()
			if len(data) == 0 {
				return nil
			}
			take := ic.remaining
			if int64(len(data)) < take {
				take = int64(len(data))
			}
			ic.body = append(ic.body, data[:take]...)
			ic.rbuf.consume(int(take))
			ic.remaining -= take
			if ic.remaining == 0 {
				ic.phase = inPhaseHeaders
				l.forward(ic)
				return nil
			}
			return nil
		}
	}
	return nil
}

func (ic *inConn) parseRequest(block []byte) error {
	ic.headers = ic.headers[:0]
	ic.body = nil
	ic.remaining = 0
	lineEnd := bytes.IndexByte(block, '\n')
	if lineEnd < 0 {
		return fpErrBadResponse
	}
	line := block[:lineEnd]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return fpErrBadResponse
	}
	sp2 := bytes.IndexByte(line[sp1+1:], ' ')
	if sp2 < 0 {
		return fpErrBadResponse
	}
	ic.method = string(line[:sp1])
	ic.path = string(line[sp1+1 : sp1+1+sp2])
	ic.keepAlive = true
	rest := block[lineEnd+1:]
	for len(rest) > 0 {
		le := bytes.IndexByte(rest, '\n')
		var hl []byte
		if le < 0 {
			hl = rest
			rest = nil
		} else {
			hl = rest[:le]
			rest = rest[le+1:]
		}
		if len(hl) > 0 && hl[len(hl)-1] == '\r' {
			hl = hl[:len(hl)-1]
		}
		if len(hl) == 0 {
			continue
		}
		colon := bytes.IndexByte(hl, ':')
		if colon <= 0 {
			return fpErrBadResponse
		}
		name := hl[:colon]
		value := hl[colon+1:]
		for len(value) > 0 && (value[0] == ' ' || value[0] == '\t') {
			value = value[1:]
		}
		if asciiEqualFold(name, "content-length") {
			v, err := strconv.ParseInt(string(value), 10, 64)
			if err != nil || v < 0 || v > fpMaxInboundBody {
				return fpErrBadResponse
			}
			ic.remaining = v
		}
		if asciiEqualFold(name, "connection") {
			if fpContainsTokenFold(value, "close") {
				ic.keepAlive = false
			}
		}
		if asciiEqualFold(name, "host") {
			ic.host = string(value)
		}
		if fpIsHopByHop(name) {
			continue
		}
		ic.headers = append(ic.headers, [2]string{string(name), string(value)})
	}
	return nil
}

func fpIsHopByHop(name []byte) bool {
	switch {
	case asciiEqualFold(name, "connection"),
		asciiEqualFold(name, "keep-alive"),
		asciiEqualFold(name, "proxy-connection"),
		asciiEqualFold(name, "transfer-encoding"),
		asciiEqualFold(name, "upgrade"),
		asciiEqualFold(name, "te"),
		asciiEqualFold(name, "host"),
		asciiEqualFold(name, "content-length"):
		return true
	}
	return false
}

func (l *eventLoop) inboundWritable(ic *inConn) {
	l.flushInbound(ic)
}

func (l *eventLoop) flushInbound(ic *inConn) {
	for !ic.closed {
		p := ic.wbuf.unread()
		if len(p) == 0 {
			if ic.wantWrite {
				ic.wantWrite = false
				l.inboundModEvents(ic, false)
			}
			return
		}
		n, err := unix.Write(ic.fd, p)
		if n > 0 {
			ic.wbuf.consume(n)
			continue
		}
		if err == unix.EAGAIN {
			ic.wbuf.compact()
			if !ic.wantWrite {
				ic.wantWrite = true
				l.inboundModEvents(ic, true)
			}
			return
		}
		if err == unix.EINTR {
			continue
		}
		l.closeInbound(ic)
		return
	}
}

func (l *eventLoop) inboundModEvents(ic *inConn, wantWrite bool) {
	events := uint32(unix.EPOLLIN | unix.EPOLLRDHUP | unix.EPOLLET)
	if wantWrite {
		events |= unix.EPOLLOUT
	}
	ev := unix.EpollEvent{Events: events, Fd: int32(ic.fd)}
	_ = unix.EpollCtl(l.ep, unix.EPOLL_CTL_MOD, ic.fd, &ev)
}

func (l *eventLoop) closeInbound(ic *inConn) {
	if ic.closed {
		return
	}
	ic.closed = true
	l.liveInconns--
	if ic.fd >= 0 {
		_ = unix.Close(ic.fd)
		if ic.fd < len(l.inconns) {
			l.inconns[ic.fd] = nil
		}
		ic.fd = -1
	}
	if ic.ex != nil {
		ic.ex.inbound = nil
		ic.ex = nil
	}
}

func (l *eventLoop) ensureInFD(fd int) {
	for fd >= len(l.inconns) {
		l.inconns = append(l.inconns, nil)
	}
}
