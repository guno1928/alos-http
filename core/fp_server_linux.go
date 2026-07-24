//go:build linux

package core

import (
	"log"
	"runtime"

	"golang.org/x/sys/unix"
)

func startProxyLoops(rt *routeTable, lip [4]byte, lport uint16, cfg fpConfig) (*fpClient, error) {
	c := &fpClient{cfg: cfg}
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
	return c, nil
}

func buildProxyRouteTable(domains []DomainConfig) (*routeTable, error) {
	rt := &routeTable{hosts: make(map[string]*backendGroup)}
	for _, d := range domains {
		var bes []FastBackend
		for _, bc := range d.Backends {
			b := bc
			normalizeBackendAddr(&b)
			bes = append(bes, FastBackend{
				Addr:       b.Addr,
				TLS:        b.TLS,
				SkipVerify: b.TLSSkipVerify,
				Weight:     b.Weight,
			})
		}
		g, err := buildGroup(bes, d.LoadBalancer)
		if err != nil {
			return nil, err
		}
		if d.Domain == "" || d.Domain == "*" {
			rt.fallback = g
		} else {
			rt.hosts[d.Domain] = g
		}
	}
	return rt, nil
}

func (s *Server) serveEpollProxy(addr string) (bool, error) {
	rt, err := buildProxyRouteTable(s.proxyDomains)
	if err != nil {
		return true, err
	}
	if pe := s.proxy.Load(); pe != nil {
		rt.onRequest = pe.OnRequest
		rt.onResponse = pe.OnResponse
		rt.onError = pe.OnError
		rt.cache = pe.Cache
	}
	for _, d := range s.proxyDomains {
		if !d.HealthCheck.Enabled {
			continue
		}
		g := rt.fallback
		if d.Domain != "" && d.Domain != "*" {
			g = rt.hosts[d.Domain]
		}
		if g != nil {
			startFPHealthChecker(g.backends, d.HealthCheck, s.done)
		}
	}
	lip, lport, err := parseListenAddr(addr)
	if err != nil {
		return true, err
	}
	loops := s.config.Listeners
	if loops <= 0 {
		loops = runtime.NumCPU()
	}
	var cfg fpConfig
	cfg.fill(loops)
	if _, err := startProxyLoops(rt, lip, lport, cfg); err != nil {
		return true, err
	}
	log.Println("=== ALOS Reverse Proxy (fully custom epoll, in + out) ===")
	log.Printf("Listening on http://%s (epoll proxy loops=%d, domains=%d)", addr, cfg.Loops, len(s.proxyDomains))
	<-s.done
	return true, nil
}
