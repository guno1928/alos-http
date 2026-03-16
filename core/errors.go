package core

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }

var (
	ErrRecordTooLarge         = &staticError{"record too large"}
	ErrNotClientHello         = &staticError{"not a ClientHello"}
	ErrTruncated              = &staticError{"message truncated"}
	ErrBodyTooShort           = &staticError{"body too short"}
	ErrNoSessionID            = &staticError{"no session_id"}
	ErrSessionIDTruncated     = &staticError{"session_id truncated"}
	ErrNoCipherSuites         = &staticError{"no cipher_suites"}
	ErrBadCSLen               = &staticError{"cipher_suites bad length"}
	ErrNoCompression          = &staticError{"no compression"}
	ErrNoExtensions           = &staticError{"no extensions"}
	ErrExtsTruncated          = &staticError{"extensions truncated"}
	ErrNoX25519               = &staticError{"no x25519 key_share"}
	ErrAllZeroInner           = &staticError{"all-zero inner plaintext"}
	ErrSigVerifyFailed        = &staticError{"signature self-verification failed"}
	ErrH2BadPreface           = &staticError{"invalid h2 preface"}
	ErrH2FrameTooLarge        = &staticError{"h2 frame too large"}
	ErrH2StreamClosed         = &staticError{"h2 stream closed"}
	ErrH2FlowControl          = &staticError{"h2 flow control violation"}
	ErrH2BadHeader            = &staticError{"h2 bad header"}
	ErrH2GoAway               = &staticError{"h2 goaway received"}
	ErrConnectionClosed       = &staticError{"connection closed"}
	ErrBodyTooLarge           = &staticError{"body too large"}
	ErrRateLimited            = &staticError{"rate limited"}
	ErrStreamClosed           = &staticError{"stream closed"}
	ErrWindowExhausted        = &staticError{"flow control window exhausted"}
	ErrNoCertForSNI           = &staticError{"no certificate for server name"}
	ErrProxyBadResponse       = &staticError{"proxy: bad upstream response"}
	ErrProxyNoBackend         = &staticError{"proxy: no healthy backend"}
	ErrProxyTimeout           = &staticError{"proxy: upstream timeout"}
	ErrProxyConnFailed        = &staticError{"proxy: connection failed"}
	ErrInternal               = &staticError{"internal error"}
	ErrRateLimit              = &staticError{"rate limit exceeded"}
	ErrTooManyHeaders         = &staticError{"too many headers"}
	ErrHpackTableSizeExceeded = &staticError{"hpack: dynamic table size exceeds protocol limit"}
)
