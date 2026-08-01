//go:build linux

package core

// UpstreamClient issues outbound requests over the epoll event loops, reusing
// pooled keep-alive connections per origin. It is the client side counterpart
// to the inbound server: no stdlib net/http Transport is involved.
type UpstreamClient = fpClient

// UpstreamRequest describes one outbound request. Authority is host:port.
type UpstreamRequest = fpRequest

// UpstreamResponse is the complete upstream response.
type UpstreamResponse = fpResponse

// UpstreamConfig tunes the loops, pooling and timeouts. Zero fields take
// documented defaults.
type UpstreamConfig = fpConfig

// NewUpstreamClient starts the event loops and returns a client ready to use.
// Callers should keep one client for the lifetime of the process so that
// connections stay pooled across requests.
func NewUpstreamClient(cfg UpstreamConfig) (*UpstreamClient, error) {
	return fpNew(cfg)
}

// UpstreamStream receives an upstream response as it arrives instead of
// buffering it. OnHeaders runs once, then OnBody runs for each chunk in order.
// Both run on the event loop that owns the connection, so they must not block;
// returning an error aborts the exchange.
type UpstreamStream struct {
	OnHeaders func(status int, headers [][2]string) error
	OnBody    func(chunk []byte) error
}
