//go:build linux

package core

import (
	"strconv"
	"sync/atomic"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

type FastProxyServer struct {
	client *fpClient
	routes *routeTable
}

type FastBackend struct {
	Addr       string
	TLS        bool
	H2         bool
	SkipVerify bool
}

type FastRoute struct {
	Host     string
	Backends []FastBackend
}

type fpBackend struct {
	authority  string
	scheme     string
	ip         [4]byte
	port       uint16
	tls        bool
	h2         bool
	skipVerify bool
	healthy    atomic.Bool
}

type backendGroup struct {
	backends []*fpBackend
	next     atomic.Uint32
}

func (g *backendGroup) pick() *fpBackend {
	n := len(g.backends)
	if n == 0 {
		return nil
	}
	start := int(g.next.Add(1))
	for i := 0; i < n; i++ {
		be := g.backends[(start+i)%n]
		if be.healthy.Load() {
			return be
		}
	}
	return g.backends[start%n]
}

type routeTable struct {
	hosts    map[string]*backendGroup
	fallback *backendGroup
}

func (rt *routeTable) lookup(host string) *backendGroup {
	if rt.hosts != nil {
		if g := rt.hosts[host]; g != nil {
			return g
		}
	}
	return rt.fallback
}

func buildFastBackend(fb FastBackend) (*fpBackend, error) {
	scheme := "http"
	if fb.TLS {
		scheme = "https"
	}
	host, port, err := splitAuthority(fb.Addr, scheme)
	if err != nil {
		return nil, err
	}
	ip, err := fpResolveIPv4(host)
	if err != nil {
		return nil, err
	}
	be := &fpBackend{
		authority:  fb.Addr,
		scheme:     scheme,
		ip:         ip,
		port:       port,
		tls:        fb.TLS,
		h2:         fb.H2,
		skipVerify: fb.SkipVerify,
	}
	be.healthy.Store(true)
	return be, nil
}

func buildGroup(bes []FastBackend) (*backendGroup, error) {
	g := &backendGroup{}
	for _, fb := range bes {
		be, err := buildFastBackend(fb)
		if err != nil {
			return nil, err
		}
		g.backends = append(g.backends, be)
	}
	return g, nil
}

func ListenAndFastProxy(listenAddr string, routes []FastRoute, fallback []FastBackend, loops int) (*FastProxyServer, error) {
	rt := &routeTable{hosts: make(map[string]*backendGroup)}
	for _, r := range routes {
		g, err := buildGroup(r.Backends)
		if err != nil {
			return nil, err
		}
		rt.hosts[r.Host] = g
	}
	if len(fallback) > 0 {
		g, err := buildGroup(fallback)
		if err != nil {
			return nil, err
		}
		rt.fallback = g
	} else if len(routes) == 1 {
		rt.fallback = rt.hosts[routes[0].Host]
	}

	var cfg fpConfig
	cfg.fill(loops)
	c := &fpClient{cfg: cfg}
	ps := &FastProxyServer{client: c, routes: rt}

	lip, lport, err := parseListenAddr(listenAddr)
	if err != nil {
		return nil, err
	}

	for i := 0; i < cfg.Loops; i++ {
		l, err := newEventLoop(&c.cfg)
		if err != nil {
			return nil, err
		}
		lfd, err := reusePortListener(lip, lport)
		if err != nil {
			return nil, err
		}
		l.listenFd = lfd
		l.proxyRoutes = rt
		ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(lfd)}
		if err := unix.EpollCtl(l.ep, unix.EPOLL_CTL_ADD, lfd, &ev); err != nil {
			return nil, err
		}
		c.loops = append(c.loops, l)
		go l.run()
	}
	return ps, nil
}

func (l *eventLoop) forward(ic *inConn) {
	g := l.proxyRoutes.lookup(stripPort(ic.host))
	if g == nil {
		l.writeProxyError(ic, fpErrBadAuthority)
		return
	}
	be := g.pick()
	if be == nil {
		l.writeProxyError(ic, fpErrBadAuthority)
		return
	}

	hostHdr := ic.host
	if hostHdr == "" {
		hostHdr = be.authority
	}
	if ic.clientIP != "" {
		ic.headers = append(ic.headers, [2]string{"x-forwarded-for", ic.clientIP})
	}

	ex := l.exGet()
	req := ex.req
	req.Scheme = be.scheme
	req.Authority = be.authority
	req.Method = ic.method
	req.Path = ic.path
	req.HostHeader = hostHdr
	req.Headers = ic.headers
	req.Body = ic.body
	req.SkipVerify = be.skipVerify
	req.H2 = be.h2
	ex.deadline = turbo.UnixNano() + l.cfg.RequestTimeout.Nanoseconds()
	ex.ip = be.ip
	ex.port = be.port
	ex.inbound = ic
	ex.key = poolKey{authority: be.authority, tls: be.tls, h2: be.h2, skipVerify: be.skipVerify}
	ic.ex = ex
	l.startExchange(ex)
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

func (l *eventLoop) onForwardDone(ex *Exchange) {
	ic := ex.inbound
	ex.inbound = nil
	if ic == nil || ic.closed {
		return
	}
	ic.ex = nil
	if ex.err != nil {
		l.writeProxyError(ic, ex.err)
		return
	}
	l.writeProxyResponse(ic, &ex.resp)
	keepAlive := ic.keepAlive
	l.exPut(ex)
	if !keepAlive {
		l.flushInbound(ic)
		l.closeInbound(ic)
		return
	}
	l.flushInbound(ic)
	if !ic.closed {
		if err := l.inboundParse(ic); err != nil {
			l.closeInbound(ic)
		}
	}
}

func (l *eventLoop) writeProxyResponse(ic *inConn, resp *fpResponse) {
	dst := ic.wbuf.b
	dst = append(dst, "HTTP/1.1 "...)
	dst = strconv.AppendInt(dst, int64(resp.Status), 10)
	dst = append(dst, ' ')
	dst = append(dst, statusText(resp.Status)...)
	dst = append(dst, '\r', '\n')
	for _, h := range resp.Headers {
		if isHopByHopStr(h[0]) {
			continue
		}
		dst = append(dst, h[0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, h[1]...)
		dst = append(dst, '\r', '\n')
	}
	dst = append(dst, "content-length: "...)
	dst = strconv.AppendInt(dst, int64(len(resp.Body)), 10)
	dst = append(dst, '\r', '\n', '\r', '\n')
	dst = append(dst, resp.Body...)
	ic.wbuf.b = dst
}

func (l *eventLoop) writeProxyError(ic *inConn, err error) {
	status := 502
	if err == fpErrTimeout {
		status = 504
	} else if err == fpErrTooManyConns {
		status = 503
	}
	body := "proxy error"
	dst := ic.wbuf.b
	dst = append(dst, "HTTP/1.1 "...)
	dst = strconv.AppendInt(dst, int64(status), 10)
	dst = append(dst, ' ')
	dst = append(dst, statusText(status)...)
	dst = append(dst, "\r\ncontent-length: "...)
	dst = strconv.AppendInt(dst, int64(len(body)), 10)
	dst = append(dst, '\r', '\n', '\r', '\n')
	dst = append(dst, body...)
	ic.wbuf.b = dst
	l.flushInbound(ic)
	l.closeInbound(ic)
}

func isHopByHopStr(name string) bool {
	switch name {
	case "connection", "keep-alive", "transfer-encoding",
		"upgrade", "proxy-connection", "content-length":
		return true
	}
	return false
}

func reusePortListener(ip [4]byte, port uint16) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	sa := &unix.SockaddrInet4{Port: int(port)}
	sa.Addr = ip
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Listen(fd, 1024); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func parseListenAddr(addr string) ([4]byte, uint16, error) {
	if len(addr) > 0 && addr[0] == ':' {
		p, err := strconv.Atoi(addr[1:])
		if err != nil {
			return [4]byte{}, 0, fpErrBadAuthority
		}
		return [4]byte{0, 0, 0, 0}, uint16(p), nil
	}
	host, port, err := splitAuthority(addr, "http")
	if err != nil {
		return [4]byte{}, 0, err
	}
	ip, ok := parseIPv4(host)
	if !ok {
		return [4]byte{}, 0, fpErrBadAuthority
	}
	return ip, port, nil
}

func parseBackendURL(raw string) (string, string, error) {
	scheme := "http"
	rest := raw
	if len(raw) >= 8 && raw[:8] == "https://" {
		scheme = "https"
		rest = raw[8:]
	} else if len(raw) >= 7 && raw[:7] == "http://" {
		rest = raw[7:]
	}
	if i := indexByteStr(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return "", "", fpErrBadAuthority
	}
	return scheme, rest, nil
}

func indexByteStr(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
