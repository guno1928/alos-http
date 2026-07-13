//go:build linux

package core

import (
	"runtime"
	"sync/atomic"

	"github.com/guno1928/turbo"
)

type fpClient struct {
	cfg    fpConfig
	loops  []*eventLoop
	next   atomic.Uint64
	closed atomic.Bool
}

func fpNew(cfg fpConfig) (*fpClient, error) {
	cfg.fill(runtime.GOMAXPROCS(0))
	c := &fpClient{cfg: cfg}
	for i := 0; i < cfg.Loops; i++ {
		l, err := newEventLoop(&c.cfg)
		if err != nil {
			return nil, err
		}
		c.loops = append(c.loops, l)
		go l.run()
	}
	return c, nil
}

func (c *fpClient) Do(req *fpRequest) (*fpResponse, error) {
	if c.closed.Load() {
		return nil, fpErrClientClosed
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	host, port, err := splitAuthority(req.Authority, req.Scheme)
	if err != nil {
		return nil, err
	}
	ip, err := fpResolveIPv4(host)
	if err != nil {
		return nil, err
	}
	ex := &Exchange{
		req:      req,
		done:     make(chan struct{}),
		deadline: turbo.UnixNano() + c.cfg.RequestTimeout.Nanoseconds(),
		ip:       ip,
		port:     port,
		key: poolKey{
			authority:  req.Authority,
			tls:        req.Scheme == "https",
			h2:         req.H2,
			skipVerify: req.SkipVerify,
		},
	}
	l := c.loops[int(c.next.Add(1))%len(c.loops)]
	l.submit(ex)
	<-ex.done
	if ex.err != nil {
		return nil, ex.err
	}
	return &ex.resp, nil
}

func (c *fpClient) Close() {
	c.closed.Store(true)
}
