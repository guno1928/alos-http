//go:build linux && amd64

package core

func (c *epollConn) epollProcessH2FramesTLS(srv *Server) int {
	st := &c.h2
	if !st.prefaceReceived {
		if len(c.appBuf)-c.appBufOff < H2PrefaceLen {
			return epollActionNeedRead
		}
		for i := 0; i < H2PrefaceLen; i++ {
			if c.appBuf[c.appBufOff+i] != H2ClientPreface[i] {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
				return epollActionCloseAfterFlush
			}
		}
		st.prefaceReceived = true
		c.appBufOff += H2PrefaceLen
		st.appBufOff = c.appBufOff
	}

	for {
		if len(c.writeBuf) > epollMaxPendingWrite {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrEnhanceYourCalm)
			return epollActionCloseAfterFlush
		}
		avail := len(c.appBuf) - c.appBufOff
		if avail < 9 {
			st.appBufOff = c.appBufOff
			return epollActionNeedRead
		}
		base := c.appBufOff
		frameLen := int(c.appBuf[base])<<16 | int(c.appBuf[base+1])<<8 | int(c.appBuf[base+2])
		frameType := c.appBuf[base+3]
		frameFlags := c.appBuf[base+4]
		streamID := (uint32(c.appBuf[base+5])<<24 | uint32(c.appBuf[base+6])<<16 | uint32(c.appBuf[base+7])<<8 | uint32(c.appBuf[base+8])) & 0x7fffffff
		if frameLen > int(srv.h2MaxFrameSize()) {
			c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrFrameSize)
			return epollActionCloseAfterFlush
		}
		totalLen := 9 + frameLen
		if avail < totalLen {
			st.appBufOff = c.appBufOff
			return epollActionNeedRead
		}
		payload := c.appBuf[base+9 : base+totalLen]

		if st.expectContinuation != 0 {
			if frameType != H2FrameContinuation || streamID != st.expectContinuation {
				c.writeBuf = appendH2GoAwayFrame(c.writeBuf, st.lastStreamID, H2ErrProtocol)
				return epollActionCloseAfterFlush
			}
			closeConn := c.epollH2Continuation(srv, streamID, frameFlags, payload)
			c.appBufOff += totalLen
			if closeConn {
				return epollActionCloseAfterFlush
			}
			continue
		}

		closeConn := c.epollH2Frame(srv, frameType, frameFlags, streamID, payload)
		c.appBufOff += totalLen
		if closeConn {
			return epollActionCloseAfterFlush
		}
	}
}
