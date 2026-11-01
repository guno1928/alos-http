//go:build linux && amd64

package core

var tlsCompatCCS = [1]byte{0x01}

func (c *epollConn) awaitsRetryCCS() bool {
	return c.tlsRetry != nil && c.cipherInput()[0] == tlsRecChangeCipher
}

func (c *epollConn) nextClientHelloRecord() ([]byte, int, int, bool) {
	for {
		if in := c.cipherInput(); len(in) > 0 && in[0] != tlsRecHandshake && !c.awaitsRetryCCS() {
			return nil, 0, epollActionCloseAfterFlush, false
		}
		ct, payload, totalLen, ok, err := nextTLSRecord(c.cipherInput())
		if err != nil {
			return nil, 0, c.failTLS(alertRecordOverflow), false
		}
		if !ok {
			return nil, 0, epollActionNeedRead, false
		}
		if ct == tlsRecHandshake {
			if handshakeMessageLen(payload) == len(payload) {
				return payload, totalLen, 0, true
			}
			return c.reassembleClientHello()
		}
		if len(payload) != len(tlsCompatCCS) || payload[0] != tlsCompatCCS[0] {
			return nil, 0, c.failTLS(alertUnexpectedMessage), false
		}
		if !c.skipUselessRecord(totalLen) {
			return nil, 0, c.failTLS(alertUnexpectedMessage), false
		}
	}
}

const (
	tlsMaxClientHelloLen     = 64 << 10
	tlsMaxClientHelloRecords = 16
)

func handshakeMessageLen(msg []byte) int {
	if len(msg) < tlsHandshakeHeaderLen {
		return -1
	}
	return tlsHandshakeHeaderLen + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
}

func (c *epollConn) reassembleClientHello() ([]byte, int, int, bool) {
	in := c.cipherInput()
	var header [tlsHandshakeHeaderLen]byte
	gathered, consumed, want := 0, 0, -1
	for records := 0; want < 0 || gathered < want; records++ {
		if records == tlsMaxClientHelloRecords {
			return nil, 0, c.failTLS(alertDecodeError), false
		}
		ct, payload, totalLen, ok, err := nextTLSRecord(in[consumed:])
		if err != nil {
			return nil, 0, c.failTLS(alertRecordOverflow), false
		}
		if !ok {
			return nil, 0, epollActionNeedRead, false
		}
		if ct != tlsRecHandshake || len(payload) == 0 {
			return nil, 0, c.failTLS(alertUnexpectedMessage), false
		}
		if gathered < tlsHandshakeHeaderLen {
			copy(header[gathered:], payload)
		}
		gathered += len(payload)
		consumed += totalLen
		if want < 0 && gathered >= tlsHandshakeHeaderLen {
			want = handshakeMessageLen(header[:])
		}
		if want > tlsMaxClientHelloLen {
			return nil, 0, c.failTLS(alertDecodeError), false
		}
	}
	if gathered != want {
		return nil, 0, c.failTLS(alertUnexpectedMessage), false
	}
	hello := make([]byte, 0, want)
	for off := 0; off < consumed; {
		_, payload, totalLen, _, _ := nextTLSRecord(in[off:])
		hello = append(hello, payload...)
		off += totalLen
	}
	return hello, consumed, 0, true
}

func (c *epollConn) negotiateTLS13(srv *Server, payload []byte, totalLen int) (*CipherSuiteConfig, keyShareChoice, int, bool) {
	if c.tlsRetry != nil {
		share, alert, ok := c.tlsRetry.acceptSecondHello(c.clientHello)
		if !ok {
			return nil, keyShareChoice{}, c.failTLS(alert), false
		}
		return c.tlsRetry.suite, keyShareChoice{group: c.tlsRetry.group, share: share}, 0, true
	}
	cs := NegotiateSuite(c.clientHello.CipherSuites)
	if cs == nil {
		return nil, keyShareChoice{}, c.failTLS(alertHandshakeFailure), false
	}
	choice, ok := selectKeyShare(c.clientHello, srv.config.TLSPreferPostQuantum)
	if !ok {
		return nil, keyShareChoice{}, c.failTLS(alertHandshakeFailure), false
	}
	if choice.retry {
		return nil, keyShareChoice{}, c.sendHelloRetry(cs, choice.group, payload, totalLen), false
	}
	return cs, choice, 0, true
}

func (c *epollConn) sendSessionTicket(srv *Server) {
	p := c.ticket
	if p == nil {
		return
	}
	c.ticket = nil
	hdr := len(c.writeBuf)
	out := ensureTailCap(c.writeBuf, tlsRecordHeaderLen+tlsSessionTicketRecordHint)
	out, ok := srv.appendSessionTicketMessage(out[:hdr+tlsRecordHeaderLen], p)
	if !ok {
		c.writeBuf = out[:hdr]
		return
	}
	out = append(out, tlsRecHandshake)
	if len(out)-hdr-tlsRecordHeaderLen > MaxRecordPayload {
		inner := append([]byte(nil), out[hdr+tlsRecordHeaderLen:]...)
		c.writeBuf = appendTLSInnerRecords(out[:hdr], c.appWriter, inner)
		return
	}
	out = ensureTailCap(out, c.appWriter.Overhead())
	c.writeBuf = sealTLSInnerInPlace(out, c.appWriter, hdr)
}

const tlsSessionTicketRecordHint = 256

func (c *epollConn) appendTLS12ServerFinish(srv *Server, dst []byte) []byte {
	st := c.tls12
	if st.issueTicket {
		if nst := srv.tls12NewSessionTicket(st, c.selectedALPN); nst != nil {
			dst = AppendRecord(dst, tlsRecHandshake, nst)
			st.transcript.Write(nst)
		}
	}
	var thBuf [64]byte
	fin := tls12Handshake(tlsHSFinished, tls12Finished(st.suite.newHash, st.master, "server finished", st.transcript.Sum(thBuf[:0])))
	st.transcript.Write(fin)
	dst = AppendRecord(dst, tlsRecChangeCipher, tlsCompatCCS[:])
	st.serverCCSSent = true
	return append(dst, st.writer.seal(tlsRecHandshake, fin)...)
}

func (c *epollConn) epollTLS12Resume(srv *Server, payload []byte, totalLen int, selectedALPN string, r *tls12Resumption) int {
	suite, t := r.suite, &r.ticket
	st := &tls12State{
		suite:       suite,
		transcript:  suite.newHash(),
		ems:         t.ems,
		resumed:     true,
		issueTicket: c.clientHello.sessionTicketOffered,
		sni:         c.clientHello.ServerName,
		master:      t.secret,
		peerCerts:   r.peerCerts,
		peerChain:   r.peerChain,
	}
	st.clientRandom = c.clientHello.Random
	if !st.newServerRandom() || !st.installKeys() {
		return c.failTLS(alertInternalError)
	}
	shMsg := buildTLS12ServerHello(st.serverRandom[:], suite.id, tls12HelloOptions{
		alpn:                 selectedALPN,
		sessionID:            c.clientHello.SessionID,
		extendedMasterSecret: st.ems,
		secureRenegotiation:  c.clientHello.secureRenegotiation,
		sessionTicket:        st.issueTicket,
	})
	st.transcript.Write(payload)
	st.transcript.Write(shMsg)
	c.tls12 = st
	c.selectedALPN = selectedALPN
	c.phase = tlsConnPhase12ClientFinish
	flight := AppendRecord(c.writeBuf, tlsRecHandshake, shMsg)
	c.writeBuf = c.appendTLS12ServerFinish(srv, flight)
	c.consumeCipher(totalLen)
	c.releaseClientHello()
	return epollActionNeedRead
}

func (c *epollConn) sendHelloRetry(cs *CipherSuiteConfig, group tlsGroup, firstHello []byte, totalLen int) int {
	retry, hrr := newHelloRetry(cs, group, c.clientHello, firstHello)
	c.tlsRetry = retry
	c.writeBuf = AppendRecord(c.writeBuf, tlsRecHandshake, hrr)
	c.writeBuf = AppendRecord(c.writeBuf, tlsRecChangeCipher, tlsCompatCCS[:])
	c.consumeCipher(totalLen)
	c.releaseClientHello()
	return epollActionNeedRead
}
