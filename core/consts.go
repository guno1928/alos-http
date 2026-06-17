package core

const (
	MaxRecordPayload           = 16384
	MaxRecordOverhead          = 256
	MaxRecordSize              = MaxRecordPayload + MaxRecordOverhead
	CacheLineSize              = 64
	ioUringCompletionBatchSize = 256
	writeRequestBatchSize      = 96

	H2PrefaceLen           = 24
	H2DefaultWindowSize    = 65535
	H2DefaultMaxFrameSize  = 16384
	H2MaxFrameSize         = 16777215
	H2HeaderTableSize      = 4096
	H2MaxConcurrentStream  = 256
	H2MaxHeaderListSize    = 8192
	H2ConnectionWindowSize = 4194304
	H2StreamWindowSize     = 4194304

	// HTTP/2 per-connection flood defenses (C6). Peer input is hostile;
	// these bound per-connection work driven by it and fail closed
	// (GOAWAY + close) when exceeded.
	//
	// H2MaxRapidResets caps the running count of streams that opened and
	// were reset/cancelled before completing normal work (CVE-2023-44487,
	// "Rapid Reset"). Modeled on the Go stdlib net/http2 approach, which
	// allows roughly MaxConcurrentStreams plus a small constant of
	// in-flight resets before treating the peer as abusive. The counter
	// rises on each abnormal reset and falls as legitimate work completes,
	// so a well-behaved client that occasionally cancels never trips it;
	// a HEADERS(END_STREAM)+RST_STREAM loop does.
	H2MaxRapidResets = H2MaxConcurrentStream + 100

	// H2MaxSettingsFrames / H2MaxPingFrames cap SETTINGS and PING frames
	// over the connection lifetime via a leaky bucket: the allowance
	// refills at the *PerSec rate, so sustained legitimate keep-alive
	// traffic is fine but a flood that outruns the refill trips
	// GOAWAY(ENHANCE_YOUR_CALM) + close. Burst allowances are generous
	// (handshake + keep-alive) yet far below what a flood needs.
	H2MaxSettingsFrames       = 100
	H2SettingsRefillPerSec    = 5
	H2MaxPingFrames           = 100
	H2PingRefillPerSec        = 10
	H2MaxEmptyFrames          = 1000
	H2EmptyFramesRefillPerSec = 50

	// H2MaxContinuationFrames caps CONTINUATION frames per header block
	// (CVE-2024-27316 shape: a stream of zero-length CONTINUATION frames
	// that never completes the block). Combined with the MaxHeaderSize
	// byte cap, either limit alone is sufficient to stop the attack.
	H2MaxContinuationFrames = 64

	H2FrameData         byte = 0x0
	H2FrameHeaders      byte = 0x1
	H2FramePriority     byte = 0x2
	H2FrameRSTStream    byte = 0x3
	H2FrameSettings     byte = 0x4
	H2FramePushPromise  byte = 0x5
	H2FramePing         byte = 0x6
	H2FrameGoAway       byte = 0x7
	H2FrameWindowUpdate byte = 0x8
	H2FrameContinuation byte = 0x9

	H2FlagEndStream  byte = 0x1
	H2FlagEndHeaders byte = 0x4
	H2FlagPadded     byte = 0x8
	H2FlagPriority   byte = 0x20
	H2FlagAck        byte = 0x1

	H2ErrNoError         uint32 = 0x0
	H2ErrProtocol        uint32 = 0x1
	H2ErrInternal        uint32 = 0x2
	H2ErrFlowControl     uint32 = 0x3
	H2ErrSettingsTimeout uint32 = 0x4
	H2ErrStreamClosed    uint32 = 0x5
	H2ErrFrameSize       uint32 = 0x6
	H2ErrRefusedStream   uint32 = 0x7
	H2ErrCancel          uint32 = 0x8
	H2ErrCompression     uint32 = 0x9
	H2ErrConnect         uint32 = 0xa
	H2ErrEnhanceYourCalm uint32 = 0xb
	H2ErrInadequateSec   uint32 = 0xc
	H2ErrHTTP11Required  uint32 = 0xd

	H2SettingHeaderTableSize      uint16 = 0x1
	H2SettingEnablePush           uint16 = 0x2
	H2SettingMaxConcurrentStreams uint16 = 0x3
	H2SettingInitialWindowSize    uint16 = 0x4
	H2SettingMaxFrameSize         uint16 = 0x5
	H2SettingMaxHeaderListSize    uint16 = 0x6
)
