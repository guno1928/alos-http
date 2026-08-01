//go:build linux

package core

import (
	"errors"
	"time"
)

var (
	fpErrTimeout        = errors.New("outbound: request timeout")
	fpErrConnClosed     = errors.New("outbound: backend connection closed")
	fpErrDialFailed     = errors.New("outbound: dial failed")
	fpErrBadResponse    = errors.New("outbound: malformed response")
	fpErrBodyTooLarge   = errors.New("outbound: response body too large")
	fpErrHeaderTooLarge = errors.New("outbound: response headers too large")
	fpErrClientClosed   = errors.New("outbound: client closed")
	fpErrBadAuthority   = errors.New("outbound: bad authority")
	fpErrDNSFailed      = errors.New("outbound: dns lookup failed")
	fpErrTooManyConns   = errors.New("outbound: backend connection limit reached")
	fpErrBlocked        = errors.New("outbound: request blocked by interceptor")
)

type fpRequest struct {
	Scheme     string
	Authority  string
	Method     string
	Path       string
	HostHeader string
	Headers    [][2]string
	Body       []byte
	Upgrade    string
	SkipVerify bool
	H2         bool
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
	ip [4]byte
	// rawRequest is a fully serialised request line, headers and body. When it
	// is set the H1 protocol writes it verbatim instead of building one from
	// req, which lets the caller own header filtering and sanitisation.
	rawRequest []byte
	// Per-domain limits carried with the exchange, so the connection it lands
	// on adopts the settings of the domain that asked for it.
	connectTimeoutNano int64
	readTimeoutNano    int64
	idleTimeoutNano    int64
	maxIdle            int
	port               uint16
	key                poolKey
	sink     *UpstreamStream
	pnext    *Exchange
	retried  bool
	finished bool
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
