//go:build linux && amd64

package core

import (
	"errors"
	"io"
	"net/netip"
	"sync/atomic"
	"time"
)

var (
	errFPTimeout        = errors.New("outbound: request timeout")
	errFPConnClosed     = errors.New("outbound: backend connection closed")
	errFPDialFailed     = errors.New("outbound: dial failed")
	errFPBadResponse    = errors.New("outbound: malformed response")
	errFPBodyTooLarge   = errors.New("outbound: response body too large")
	errFPHeaderTooLarge = errors.New("outbound: response headers too large")
	errFPClientClosed   = errors.New("outbound: client closed")
	errFPBadAuthority   = errors.New("outbound: bad authority")
	errFPDNSFailed      = errors.New("outbound: dns lookup failed")
	errFPTooManyConns   = errors.New("outbound: backend connection limit reached")
	errFPDialBlocked    = errors.New("outbound: destination address not allowed")
)

type fpRequest struct {
	Scheme      string
	Authority   string
	Method      string
	Path        string
	HostHeader  string
	Headers     [][2]string
	Body        []byte
	BodySource  io.Reader
	BodyLength  int64
	Upgrade     string
	SkipVerify  bool
	trust       *upstreamTrust
	H2          bool
	DialTimeout time.Duration
	ReadTimeout time.Duration
}

type fpResponse struct {
	Status  int
	Headers [][2]string
	Body    []byte
	// hdrRaw is the parser's own view of the headers, set for consumers that
	// write the response out before the connection reads the next one. Headers
	// stays authoritative for anyone whose use outlives the exchange, and is the
	// only form an external caller ever sees.
	hdrRaw [][2][]byte
}

// headers prefers the allocation-free form and falls back to strings, which is
// what an HTTP/2 backend produces.
func (r *fpResponse) headers() respHeaders {
	if r.hdrRaw != nil {
		return respHeaders{raw: r.hdrRaw}
	}
	return respHeaders{str: r.Headers}
}

type poolKey struct {
	authority  string
	tls        bool
	h2         bool
	skipVerify bool
	trust      *upstreamTrust
}

// Exchange represents a single outbound request/response cycle as it is
// processed by an event loop, from submission through backend connection
// handling to completion.
type Exchange struct {
	node     mpscNode
	req      *fpRequest
	resp     fpResponse
	err      error
	done     chan struct{}
	deadline int64
	ip       netip.Addr
	// rawRequest is a fully serialised request line, headers and body. When it
	// is set the H1 protocol writes it verbatim instead of building one from
	// req, which lets the caller own header filtering and sanitisation.
	rawRequest []byte
	bc         *backendConn
	// Per-domain limits carried with the exchange, so the connection it lands
	// on adopts the settings of the domain that asked for it.
	connectTimeoutNano int64
	readTimeoutNano    int64
	idleTimeoutNano    int64
	maxIdle            int
	port               uint16
	key                poolKey
	sink               *UpstreamStream
	body               *upstreamBody
	pipe               *respPipe
	h2st               *h2Stream
	pnext              *Exchange
	retried            bool
	finished           bool
	started            bool
	wroteRequest       bool
	replayable         bool

	queued       atomic.Bool
	bodyReady    atomic.Bool
	resumeWanted atomic.Bool
	abortWanted  atomic.Bool
}

type fpConfig struct {
	Loops             int
	LoopsPerOrigin    int
	MaxIdlePerBackend int
	DialTimeout       time.Duration
	RequestTimeout    time.Duration
	IdleTimeout       time.Duration
	MaxResponseBody   int
	MaxHeaderBytes    int
	AllowAddr         func(netip.Addr) bool
}

const (
	defaultDialTimeout    = 5 * time.Second
	defaultRequestTimeout = 30 * time.Second
	defaultIdleTimeout    = 60 * time.Second
	defaultMaxIdle        = 512
	defaultMaxBody        = 64 << 20
	defaultMaxHeader      = 64 << 10
)

func (c *fpConfig) fill(loopsDefault int) {
	if c.Loops <= 0 {
		c.Loops = loopsDefault
	}
	if c.LoopsPerOrigin <= 0 {
		c.LoopsPerOrigin = c.Loops / 2
		if c.LoopsPerOrigin < 1 {
			c.LoopsPerOrigin = 1
		}
	}
	if c.MaxIdlePerBackend <= 0 {
		c.MaxIdlePerBackend = defaultMaxIdle
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = defaultDialTimeout
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = defaultRequestTimeout
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultIdleTimeout
	}
	if c.MaxResponseBody <= 0 {
		c.MaxResponseBody = defaultMaxBody
	}
	if c.MaxHeaderBytes <= 0 {
		c.MaxHeaderBytes = defaultMaxHeader
	}
}
