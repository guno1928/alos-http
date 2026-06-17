package core

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }

var (
	ErrRecordTooLarge     = &staticError{"record too large"}
	ErrNotClientHello     = &staticError{"not a ClientHello"}
	ErrTruncated          = &staticError{"message truncated"}
	ErrBodyTooShort       = &staticError{"body too short"}
	ErrNoSessionID        = &staticError{"no session_id"}
	ErrSessionIDTruncated = &staticError{"session_id truncated"}
	ErrNoCipherSuites     = &staticError{"no cipher_suites"}
	ErrBadCSLen           = &staticError{"cipher_suites bad length"}
	ErrNoCompression      = &staticError{"no compression"}
	ErrNoExtensions       = &staticError{"no extensions"}
	ErrExtsTruncated      = &staticError{"extensions truncated"}
	ErrNoX25519           = &staticError{"no x25519 key_share"}
	ErrBadKeyShare        = &staticError{"bad x25519 key_share"}
	ErrAllZeroInner       = &staticError{"all-zero inner plaintext"}
	ErrSigVerifyFailed    = &staticError{"signature self-verification failed"}
	ErrH2BadPreface       = &staticError{"invalid h2 preface"}
	ErrH2FrameTooLarge    = &staticError{"h2 frame too large"}
	ErrH2StreamClosed     = &staticError{"h2 stream closed"}
	ErrH2FlowControl      = &staticError{"h2 flow control violation"}
	ErrH2BadHeader        = &staticError{"h2 bad header"}
	ErrH2GoAway           = &staticError{"h2 goaway received"}
	ErrConnectionClosed   = &staticError{"connection closed"}

	// ErrBodyTooLarge is returned when a request body exceeds the configured
	// MaxBodySize or the BodyLimit middleware threshold.
	ErrBodyTooLarge = &staticError{"body too large"}

	// ErrRateLimited is returned when a request is rejected by the rate limiter.
	ErrRateLimited = &staticError{"rate limited"}

	// ErrStreamClosed is returned when writing to a StreamWriter whose
	// underlying connection has already been closed.
	ErrStreamClosed = &staticError{"stream closed"}

	ErrWindowExhausted = &staticError{"flow control window exhausted"}

	// ErrNoCertForSNI is returned during TLS handshake when no certificate
	// matches the client's Server Name Indication.
	ErrNoCertForSNI = &staticError{"no certificate for server name"}

	// ErrProxyBadResponse is returned when the upstream backend sends an
	// unparseable or malformed HTTP response.
	ErrProxyBadResponse = &staticError{"proxy: bad upstream response"}

	// ErrProxyNoBackend is returned when no healthy backend is available
	// to handle a proxied request.
	ErrProxyNoBackend = &staticError{"proxy: no healthy backend"}

	// ErrProxyTimeout is returned when the upstream backend does not
	// respond within the configured ReadTimeout.
	ErrProxyTimeout = &staticError{"proxy: upstream timeout"}

	// ErrProxyConnFailed is returned when the proxy cannot establish a
	// TCP connection to any backend.
	ErrProxyConnFailed = &staticError{"proxy: connection failed"}

	// ErrIOUringRequired is returned by ListenAndServe on platforms
	// where the io_uring worker backend is not available.
	ErrIOUringRequired = &staticError{"io_uring worker backend required"}

	ErrInternal = &staticError{"internal error"}

	// ErrRateLimit is returned when the server-wide rate limit is exceeded.
	ErrRateLimit = &staticError{"rate limit exceeded"}

	ErrTooManyHeaders         = &staticError{"too many headers"}
	ErrHpackTableSizeExceeded = &staticError{"hpack: dynamic table size exceeds protocol limit"}

	// ErrWebSocketProtocol is returned when a WebSocket frame violates
	// RFC 6455 (bad opcode, missing mask, unexpected continuation, etc.).
	ErrWebSocketProtocol = &staticError{"websocket protocol error"}

	// errQuicAckInvalid is returned when a peer ACK frame is structurally
	// invalid: a range bound that would underflow on uint64, or an
	// acknowledgement of a packet number the endpoint never sent. The QUIC
	// connection is closed with FRAME_ENCODING_ERROR in response.
	errQuicAckInvalid = &staticError{"quic: invalid ACK frame"}
)
