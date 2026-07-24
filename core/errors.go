package core

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }

var (
	// ErrRecordTooLarge is returned when a TLS record's declared length exceeds MaxRecordSize.
	ErrRecordTooLarge = &staticError{"record too large"}
	// ErrNotClientHello is returned when data does not begin with a valid TLS
	// ClientHello, or (in QUIC packet parsing) a long-header packet.
	ErrNotClientHello = &staticError{"not a ClientHello"}
	// ErrTruncated is returned when a message ends before all of its declared or expected bytes are present.
	ErrTruncated = &staticError{"message truncated"}
	// ErrBodyTooShort is returned when a parsed TLS ClientHello body is shorter than the minimum required length.
	ErrBodyTooShort = &staticError{"body too short"}
	// ErrNoSessionID is returned when a TLS ClientHello ends before its session_id length byte.
	ErrNoSessionID = &staticError{"no session_id"}
	// ErrSessionIDTruncated is returned when a TLS ClientHello's declared session_id length extends past the message end.
	ErrSessionIDTruncated = &staticError{"session_id truncated"}
	// ErrNoCipherSuites is returned when a TLS ClientHello ends before its cipher_suites length field.
	ErrNoCipherSuites = &staticError{"no cipher_suites"}
	// ErrBadCSLen is returned when a TLS ClientHello's cipher_suites length is odd or extends past the message end.
	ErrBadCSLen = &staticError{"cipher_suites bad length"}
	// ErrNoCompression is returned when a TLS ClientHello ends before its compression_methods field.
	ErrNoCompression = &staticError{"no compression"}
	// ErrNoExtensions is returned when a TLS ClientHello ends before its extensions length field.
	ErrNoExtensions = &staticError{"no extensions"}
	// ErrExtsTruncated is returned when a TLS ClientHello's declared extensions length extends past the message end.
	ErrExtsTruncated = &staticError{"extensions truncated"}
	// ErrNoX25519 indicates a TLS ClientHello key_share extension has no x25519 entry.
	ErrNoX25519 = &staticError{"no x25519 key_share"}
	// ErrBadKeyShare indicates a TLS ClientHello's x25519 key_share entry is malformed.
	ErrBadKeyShare = &staticError{"bad x25519 key_share"}
	// ErrAllZeroInner is returned when a decrypted TLS 1.3 record's inner plaintext is all zero padding with no content-type byte.
	ErrAllZeroInner = &staticError{"all-zero inner plaintext"}
	// ErrSigVerifyFailed indicates a certificate's self-signature failed verification.
	ErrSigVerifyFailed = &staticError{"signature self-verification failed"}
	// ErrH2BadPreface indicates an HTTP/2 connection did not start with the expected client preface.
	ErrH2BadPreface = &staticError{"invalid h2 preface"}
	// ErrH2FrameTooLarge is returned when an HTTP/2 frame's declared length exceeds the maximum frame size, or there isn't enough data to read a complete frame.
	ErrH2FrameTooLarge = &staticError{"h2 frame too large"}
	// ErrH2StreamClosed indicates an operation targeted an HTTP/2 stream that is already closed.
	ErrH2StreamClosed = &staticError{"h2 stream closed"}
	// ErrH2FlowControl indicates an HTTP/2 peer violated flow-control window limits.
	ErrH2FlowControl = &staticError{"h2 flow control violation"}
	// ErrH2BadHeader is returned when an HPACK header block fails to decode: a malformed integer, an invalid table index, or a corrupt Huffman-encoded string.
	ErrH2BadHeader = &staticError{"h2 bad header"}
	// ErrH2GoAway is returned when a TLS alert record is received while reading HTTP/2 application data, signaling the peer is closing the connection.
	ErrH2GoAway = &staticError{"h2 goaway received"}
	// ErrConnectionClosed indicates an operation was attempted on a connection that has already been closed.
	ErrConnectionClosed = &staticError{"connection closed"}

	// ErrBodyTooLarge is returned when a request body exceeds the configured
	// MaxBodySize or the BodyLimit middleware threshold.
	ErrBodyTooLarge = &staticError{"body too large"}

	// ErrRateLimited is returned when a request is rejected by the rate limiter.
	ErrRateLimited = &staticError{"rate limited"}

	// ErrStreamClosed is returned when writing to a StreamWriter whose
	// underlying connection has already been closed.
	ErrStreamClosed = &staticError{"stream closed"}

	// ErrWindowExhausted indicates a write cannot proceed because the flow-control window is exhausted.
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

	// ErrEpollUnsupported is returned by the epoll-backed ListenAndServe*
	// methods on platforms other than linux/amd64.
	ErrEpollUnsupported = &staticError{"epoll backend requires linux/amd64"}

	// ErrInternal represents an unexpected internal failure that doesn't fit a more specific error.
	ErrInternal = &staticError{"internal error"}

	// ErrRateLimit is returned when the server-wide rate limit is exceeded.
	ErrRateLimit = &staticError{"rate limit exceeded"}

	// ErrTooManyHeaders is returned when a decoded HPACK or QPACK header block contains more than 128 headers.
	ErrTooManyHeaders = &staticError{"too many headers"}
	// ErrHpackTableSizeExceeded is returned when an HPACK dynamic table size update exceeds the protocol maximum.
	ErrHpackTableSizeExceeded = &staticError{"hpack: dynamic table size exceeds protocol limit"}

	// ErrWebSocketProtocol is returned when a WebSocket frame violates
	// RFC 6455 (bad opcode, missing mask, unexpected continuation, etc.).
	ErrWebSocketProtocol = &staticError{"websocket protocol error"}
)
