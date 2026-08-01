//go:build linux

package core

import (
	"runtime"
	"sync/atomic"

	"github.com/guno1928/turbo"
	"github.com/zeebo/xxh3"
)

type fpClient struct {
	cfg        fpConfig
	loops      []*eventLoop
	listenIP   [4]byte
	listenPort uint16
	closed     atomic.Bool
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

// Do sends req to the appropriate backend and blocks until a response is
// received or the request fails (for example if the client is closed, the
// authority cannot be resolved, or the request times out).
func (c *fpClient) Do(req *fpRequest) (*fpResponse, error) {
	ex, err := c.exchange(req, nil)
	if err != nil {
		return nil, err
	}
	return &ex.resp, nil
}

// DoStream sends req and delivers the response to sink as it arrives instead
// of buffering the body. It blocks until the response completes or fails.
func (c *fpClient) DoStream(req *UpstreamRequest, sink *UpstreamStream) (int, error) {
	ex, err := c.exchange(req, sink)
	if err != nil {
		return 0, err
	}
	return ex.resp.Status, nil
}

func (c *fpClient) exchange(req *fpRequest, sink *UpstreamStream) (*Exchange, error) {
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
		sink:     sink,
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
	l := c.loopFor(ex.key)
	l.submit(ex)
	<-ex.done
	if ex.err != nil {
		return nil, ex.err
	}
	return ex, nil
}

// loopFor maps an origin onto a bounded set of event loops, trading pooled
// connection reuse against parallelism via LoopsPerOrigin.
func (c *fpClient) loopFor(key poolKey) *eventLoop {
	n := uint64(len(c.loops))
	if n == 1 {
		return c.loops[0]
	}
	h := xxh3.HashString(key.authority)
	if key.tls {
		h ^= 0x9e3779b97f4a7c15
	}
	if key.h2 {
		h ^= 0xc2b2ae3d27d4eb4f
	}
	if key.skipVerify {
		h ^= 0x165667b19e3779f9
	}
	base := h % n
	shards := uint64(c.cfg.LoopsPerOrigin)
	if shards <= 1 {
		return c.loops[base]
	}
	if shards > n {
		shards = n
	}
	return c.loops[(base+turbo.Uint64n(shards))%n]
}

// Close marks the client as closed, causing subsequent calls to Do to
// return fpErrClientClosed.
func (c *fpClient) Close() {
	if c.closed.Swap(true) {
		return
	}
	for _, l := range c.loops {
		l.stop()
	}
}
