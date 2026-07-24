package core

const (
	// MaxRecordPayload is the maximum TLS record plaintext payload size in bytes.
	MaxRecordPayload = 16384
	// MaxRecordOverhead is the maximum TLS record overhead (header, IV, and auth tag) in bytes.
	MaxRecordOverhead = 256
	// MaxRecordSize is the maximum total size of a TLS record (payload plus overhead) in bytes.
	MaxRecordSize = MaxRecordPayload + MaxRecordOverhead
	// CacheLineSize is the assumed CPU cache line size in bytes, used to pad structs and avoid false sharing.
	CacheLineSize         = 64
	writeRequestBatchSize = 96

	// H2PrefaceLen is the length in bytes of the HTTP/2 connection preface.
	H2PrefaceLen = 24
	// H2DefaultWindowSize is the default HTTP/2 flow-control window size in bytes.
	H2DefaultWindowSize = 65535
	// H2DefaultMaxFrameSize is the default maximum HTTP/2 frame size in bytes.
	H2DefaultMaxFrameSize = 16384
	// H2MaxFrameSize is the largest HTTP/2 frame size permitted by the spec, in bytes.
	H2MaxFrameSize = 16777215
	// H2HeaderTableSize is the default HPACK dynamic header table size in bytes.
	H2HeaderTableSize = 4096
	// H2MaxConcurrentStream is the maximum number of concurrent HTTP/2 streams advertised per connection.
	H2MaxConcurrentStream = 256
	// H2MaxHeaderListSize is the maximum uncompressed HTTP/2 header list size in bytes.
	H2MaxHeaderListSize = 8192
	// H2ConnectionWindowSize is the initial HTTP/2 connection-level flow-control window size in bytes.
	H2ConnectionWindowSize = 4194304
	// H2StreamWindowSize is the initial HTTP/2 stream-level flow-control window size in bytes.
	H2StreamWindowSize = 4194304

	// H2FrameData is the HTTP/2 DATA frame type.
	H2FrameData byte = 0x0
	// H2FrameHeaders is the HTTP/2 HEADERS frame type.
	H2FrameHeaders byte = 0x1
	// H2FramePriority is the HTTP/2 PRIORITY frame type.
	H2FramePriority byte = 0x2
	// H2FrameRSTStream is the HTTP/2 RST_STREAM frame type.
	H2FrameRSTStream byte = 0x3
	// H2FrameSettings is the HTTP/2 SETTINGS frame type.
	H2FrameSettings byte = 0x4
	// H2FramePushPromise is the HTTP/2 PUSH_PROMISE frame type.
	H2FramePushPromise byte = 0x5
	// H2FramePing is the HTTP/2 PING frame type.
	H2FramePing byte = 0x6
	// H2FrameGoAway is the HTTP/2 GOAWAY frame type.
	H2FrameGoAway byte = 0x7
	// H2FrameWindowUpdate is the HTTP/2 WINDOW_UPDATE frame type.
	H2FrameWindowUpdate byte = 0x8
	// H2FrameContinuation is the HTTP/2 CONTINUATION frame type.
	H2FrameContinuation byte = 0x9

	// H2FlagEndStream is the HTTP/2 END_STREAM frame flag.
	H2FlagEndStream byte = 0x1
	// H2FlagEndHeaders is the HTTP/2 END_HEADERS frame flag.
	H2FlagEndHeaders byte = 0x4
	// H2FlagPadded is the HTTP/2 PADDED frame flag.
	H2FlagPadded byte = 0x8
	// H2FlagPriority is the HTTP/2 PRIORITY frame flag, set on HEADERS frames.
	H2FlagPriority byte = 0x20
	// H2FlagAck is the HTTP/2 ACK frame flag, set on SETTINGS and PING frames.
	H2FlagAck byte = 0x1

	// H2ErrNoError is the HTTP/2 NO_ERROR error code.
	H2ErrNoError uint32 = 0x0
	// H2ErrProtocol is the HTTP/2 PROTOCOL_ERROR error code.
	H2ErrProtocol uint32 = 0x1
	// H2ErrInternal is the HTTP/2 INTERNAL_ERROR error code.
	H2ErrInternal uint32 = 0x2
	// H2ErrFlowControl is the HTTP/2 FLOW_CONTROL_ERROR error code.
	H2ErrFlowControl uint32 = 0x3
	// H2ErrSettingsTimeout is the HTTP/2 SETTINGS_TIMEOUT error code.
	H2ErrSettingsTimeout uint32 = 0x4
	// H2ErrStreamClosed is the HTTP/2 STREAM_CLOSED error code.
	H2ErrStreamClosed uint32 = 0x5
	// H2ErrFrameSize is the HTTP/2 FRAME_SIZE_ERROR error code.
	H2ErrFrameSize uint32 = 0x6
	// H2ErrRefusedStream is the HTTP/2 REFUSED_STREAM error code.
	H2ErrRefusedStream uint32 = 0x7
	// H2ErrCancel is the HTTP/2 CANCEL error code.
	H2ErrCancel uint32 = 0x8
	// H2ErrCompression is the HTTP/2 COMPRESSION_ERROR error code.
	H2ErrCompression uint32 = 0x9
	// H2ErrConnect is the HTTP/2 CONNECT_ERROR error code.
	H2ErrConnect uint32 = 0xa
	// H2ErrEnhanceYourCalm is the HTTP/2 ENHANCE_YOUR_CALM error code.
	H2ErrEnhanceYourCalm uint32 = 0xb
	// H2ErrInadequateSec is the HTTP/2 INADEQUATE_SECURITY error code.
	H2ErrInadequateSec uint32 = 0xc
	// H2ErrHTTP11Required is the HTTP/2 HTTP_1_1_REQUIRED error code.
	H2ErrHTTP11Required uint32 = 0xd

	// H2SettingHeaderTableSize is the HTTP/2 SETTINGS_HEADER_TABLE_SIZE identifier.
	H2SettingHeaderTableSize uint16 = 0x1
	// H2SettingEnablePush is the HTTP/2 SETTINGS_ENABLE_PUSH identifier.
	H2SettingEnablePush uint16 = 0x2
	// H2SettingMaxConcurrentStreams is the HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS identifier.
	H2SettingMaxConcurrentStreams uint16 = 0x3
	// H2SettingInitialWindowSize is the HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE identifier.
	H2SettingInitialWindowSize uint16 = 0x4
	// H2SettingMaxFrameSize is the HTTP/2 SETTINGS_MAX_FRAME_SIZE identifier.
	H2SettingMaxFrameSize uint16 = 0x5
	// H2SettingMaxHeaderListSize is the HTTP/2 SETTINGS_MAX_HEADER_LIST_SIZE identifier.
	H2SettingMaxHeaderListSize uint16 = 0x6
)
