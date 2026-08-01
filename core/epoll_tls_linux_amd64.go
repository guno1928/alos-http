//go:build linux && amd64

package core

import (
	"crypto/hmac"
	"crypto/rand"
)

func (c *epollConn) compactCipher(consumed int) {
	if consumed <= 0 {
		return
	}
	remaining := c.readN - consumed
	if remaining > 0 {
		copy(c.readBuf, c.readBuf[consumed:c.readN])
	}
	c.readN = remaining
}

func (c *epollConn) compactApp(consumed int) {
	if consumed <= 0 {
		return
	}
	remaining := len(c.appBuf) - consumed
	if remaining > 0 {
		copy(c.appBuf, c.appBuf[consumed:])
	}
	c.appBuf = c.appBuf[:remaining]
}

func (c *epollConn) epollProcessTLS(srv *Server) int {
	if c.plainBuf == nil {
		c.plainBuf = acquireIOBuf()
	}
	if c.appBuf == nil {
		c.appBuf = acquireIOBuf()
	}
	for {
		var action int
		switch c.phase {
		case tlsConnPhaseClientHello:
			action = c.epollTLSClientHello(srv)
		case tlsConnPhaseClientFinished:
			action = c.epollTLSClientFinished(srv)
		case tlsConnPhase12ClientFinish:
			action = c.epollTLS12ClientFinish(srv)
		case tlsConnPhaseApplication:
			action = c.epollTLSApplication(srv)
		case tlsConnPhaseH2Native:
			action = c.epollTLSApplicationH2(srv)
		default:
			return epollActionCloseAfterFlush
		}
		switch action {
		case epollTLSContinue:
			continue
		case epollActionNeedRead:
			return epollActionNeedRead
		default:
			return action
		}
	}
}

const epollTLSContinue = 100

func (c *epollConn) epollTLSClientHello(srv *Server) int {
	ct, payload, totalLen, ok, err := nextTLSRecord(c.readBuf[:c.readN])
	if err != nil || (ok && ct != 0x16) {
		return epollActionCloseAfterFlush
	}
	if !ok {
		return epollActionNeedRead
	}
	if c.clientHello == nil {
		c.clientHello = clientHelloPool.Get().(*ParsedClientHello)
	}
	if err := ParseClientHello(payload, c.clientHello); err != nil {
		return epollActionCloseAfterFlush
	}
	selectedALPN := srv.negotiateALPN(c.clientHello.ALPNProtos)
	certEntry := srv.certStore.Lookup(c.clientHello.ServerName)
	if certEntry == nil || certEntry.PrivKey == nil {
		return epollActionCloseAfterFlush
	}
	if !c.clientHello.SupportsTLS13() {
		return c.epollTLS12ClientHello(srv, payload, totalLen, selectedALPN, certEntry)
	}
	if c.clientHello.X25519PubKey == nil {
		return epollActionCloseAfterFlush
	}
	cs := NegotiateSuite(c.clientHello.CipherSuites)
	if cs == nil {
		return epollActionCloseAfterFlush
	}
	transcript := cs.HashFn()
	transcript.Write(payload)

	serverKey, err := srv.x25519Pool.Get()
	if err != nil {
		return epollActionCloseAfterFlush
	}
	defer serverKey.zero()

	shared, ok2 := deriveX25519SharedSecret(&serverKey.priv, &c.clientHello.x25519PubKeyBuf)
	if !ok2 {
		return epollActionCloseAfterFlush
	}
	defer func() {
		for i := range shared {
			shared[i] = 0
		}
	}()

	var srvRandom [32]byte
	if _, err := rand.Read(srvRandom[:]); err != nil {
		return epollActionCloseAfterFlush
	}
	shMsg := BuildServerHello(srvRandom[:], c.clientHello.SessionID, cs.ID, serverKey.pub[:])
	transcript.Write(shMsg)

	var handshakeSecretBuf [64]byte
	handshakeSecret := TLSExtractTo(cs.HashFn, cs.derivedFromEarly, shared[:], handshakeSecretBuf[:0])
	var hsHashBuf [64]byte
	hsHash := transcript.Sum(hsHashBuf[:0])
	var clientHSSecretBuf [64]byte
	clientHSSecret := cs.DeriveSecretTo(&cs.labelClientHSTraffic, handshakeSecret, hsHash, clientHSSecretBuf[:0])
	var serverHSSecretBuf [64]byte
	serverHSSecret := cs.DeriveSecretTo(&cs.labelServerHSTraffic, handshakeSecret, hsHash, serverHSSecretBuf[:0])

	serverHSWriter, err := NewTrafficAEAD(cs.HashFn, serverHSSecret, cs)
	if err != nil {
		return epollActionCloseAfterFlush
	}
	clientHSReader, err := NewTrafficAEAD(cs.HashFn, clientHSSecret, cs)
	if err != nil {
		return epollActionCloseAfterFlush
	}

	eeCert := certEntry.CachedEECert(selectedALPN)
	transcript.Write(eeCert)
	var cvHashBuf [64]byte
	cvScheme, sig, err := SignCertificateVerify(certEntry.PrivKey, transcript.Sum(cvHashBuf[:0]))
	if err != nil {
		return epollActionCloseAfterFlush
	}

	inner := c.plainBuf[:0]
	inner = append(inner, eeCert...)
	cvStart := len(inner)
	inner = appendCertificateVerify(inner, cvScheme, sig)
	cv := inner[cvStart:]
	transcript.Write(cv)
	var finHashBuf [64]byte
	var srvVerifyBuf [64]byte
	srvVerifyData := cs.ComputeFinishedTo(serverHSSecret, transcript.Sum(finHashBuf[:0]), srvVerifyBuf[:0])
	finStart := len(inner)
	inner = appendFinished(inner, srvVerifyData)
	fin := inner[finStart:]
	transcript.Write(fin)
	inner = append(inner, 0x16)
	c.plainBuf = inner

	flight := c.writeBuf
	flight = AppendRecord(flight, 0x16, shMsg)
	flight = AppendRecord(flight, 0x14, []byte{0x01})
	flight = appendTLSInnerRecord(flight, serverHSWriter, inner)

	var derivedFromHSBuf [64]byte
	derivedFromHS := cs.DeriveSecretTo(&cs.labelDerived, handshakeSecret, cs.emptyTranscriptHash, derivedFromHSBuf[:0])
	var masterSecretBuf [64]byte
	masterSecret := TLSExtractTo(cs.HashFn, derivedFromHS, cs.zeroHashInput, masterSecretBuf[:0])
	var appHashBuf [64]byte
	appHash := transcript.Sum(appHashBuf[:0])
	var clientAppSecretBuf [64]byte
	clientAppSecret := cs.DeriveSecretTo(&cs.labelClientAppTraffic, masterSecret, appHash, clientAppSecretBuf[:0])
	var serverAppSecretBuf [64]byte
	serverAppSecret := cs.DeriveSecretTo(&cs.labelServerAppTraffic, masterSecret, appHash, serverAppSecretBuf[:0])
	clientAppReader, err := NewTrafficAEAD(cs.HashFn, clientAppSecret, cs)
	if err != nil {
		return epollActionCloseAfterFlush
	}
	serverAppWriter, err := NewTrafficAEAD(cs.HashFn, serverAppSecret, cs)
	if err != nil {
		return epollActionCloseAfterFlush
	}
	c.writeBuf = flight
	if len(flight) == c.writeSent {
		return epollActionCloseAfterFlush
	}
	verify := cs.ComputeFinishedTo(clientHSSecret, appHash, c.expectedFin[:0])
	c.expectedFinN = len(verify)
	c.hsReader = clientHSReader
	c.appReader = clientAppReader
	c.appWriter = serverAppWriter
	c.selectedALPN = selectedALPN
	c.phase = tlsConnPhaseClientFinished
	c.compactCipher(totalLen)
	c.releaseClientHello()
	return epollActionNeedRead
}

func (c *epollConn) epollTLSClientFinished(srv *Server) int {
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(c.readBuf[:c.readN])
		if err != nil {
			return epollActionCloseAfterFlush
		}
		if !ok {
			return epollActionNeedRead
		}
		if ct == 0x14 {
			c.compactCipher(totalLen)
			continue
		}
		if ct != 0x17 {
			return epollActionCloseAfterFlush
		}
		finPt, err := c.hsReader.Decrypt(payload)
		if err != nil {
			return epollActionCloseAfterFlush
		}
		finContent, finCT, err := StripInnerPlaintext(finPt)
		if err != nil || finCT != 0x16 {
			return epollActionCloseAfterFlush
		}
		if len(finContent) < 4 || finContent[0] != 0x14 {
			return epollActionCloseAfterFlush
		}
		clientVerify := finContent[4:]
		if !hmac.Equal(clientVerify, c.expectedFin[:c.expectedFinN]) {
			return epollActionCloseAfterFlush
		}
		c.compactCipher(totalLen)
		c.hsReader = nil
		if c.selectedALPN == "h2" {
			c.phase = tlsConnPhaseH2Native
			c.h2.init()
			plain := appendH2ServerSettingsFlight(nil, srv)
			c.writeBuf = buildTLSAppDataRecords(c.writeBuf, c.appWriter, plain)
			Stats.H2Conns.Add(1)
			return epollTLSContinue
		}
		c.phase = tlsConnPhaseApplication
		Stats.H1Conns.Add(1)
		return epollTLSContinue
	}
}

func (c *epollConn) epollTLSDecryptToApp(srv *Server) (int, bool) {
	if c.tls12 != nil {
		return c.epollTLS12DecryptToApp(srv)
	}
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(c.readBuf[:c.readN])
		if err != nil {
			return epollActionCloseAfterFlush, false
		}
		if !ok {
			return epollActionNeedRead, false
		}
		switch ct {
		case 0x14:
			c.compactCipher(totalLen)
			continue
		case 0x15:
			return epollActionCloseAfterFlush, false
		case 0x17:
			pt, err := c.appReader.Decrypt(payload)
			if err != nil {
				return epollActionCloseAfterFlush, false
			}
			appContent, appCT, err := StripInnerPlaintext(pt)
			if err != nil {
				return epollActionCloseAfterFlush, false
			}
			switch appCT {
			case 0x15:
				c.compactCipher(totalLen)
				return epollActionCloseAfterFlush, false
			case 0x17:
				if len(appContent) > srv.effectiveReadCap()-len(c.appBuf) {
					return epollActionCloseAfterFlush, false
				}
				c.appBuf = append(c.appBuf, appContent...)
				c.compactCipher(totalLen)
				return epollTLSContinue, true
			default:
				c.compactCipher(totalLen)
				continue
			}
		default:
			c.compactCipher(totalLen)
			continue
		}
	}
}

func (c *epollConn) epollTLSApplication(srv *Server) int {
	for {
		if len(c.appBuf) > 0 {
			if act := c.epollTLSHTTP1(srv); act != epollTLSContinue {
				return act
			}
		}
		action, gotData := c.epollTLSDecryptToApp(srv)
		if action == epollActionNeedRead || action == epollActionCloseAfterFlush {
			return action
		}
		if !gotData {
			return epollActionNeedRead
		}
	}
}

func (c *epollConn) epollTLS12ClientHello(srv *Server, payload []byte, totalLen int, selectedALPN string, certEntry *CertEntry) int {
	kt, ok := tls12KeyTypeOf(certEntry.PrivKey)
	if !ok {
		return epollActionCloseAfterFlush
	}
	suite := negotiateTLS12Suite(c.clientHello.CipherSuites, kt)
	if suite == nil {
		return epollActionCloseAfterFlush
	}
	curve, ok := selectTLS12Curve(c.clientHello.SupportedGroups)
	if !ok {
		return epollActionCloseAfterFlush
	}
	ecdhePriv, ecdhePub, err := tls12GenerateECDHE(curve)
	if err != nil {
		return epollActionCloseAfterFlush
	}

	st := &tls12State{
		suite:      suite,
		curve:      curve,
		ecdhePriv:  ecdhePriv,
		transcript: suite.newHash(),
	}
	st.clientRandom = c.clientHello.Random
	if _, err := rand.Read(st.serverRandom[:]); err != nil {
		return epollActionCloseAfterFlush
	}

	shMsg := buildTLS12ServerHello(st.serverRandom[:], suite.id, selectedALPN)
	certMsg := buildTLS12Certificate(certEntry.ChainDER)
	skeMsg, err := buildTLS12ServerKeyExchange(certEntry.PrivKey, st.clientRandom[:], st.serverRandom[:], curve, ecdhePub)
	if err != nil {
		return epollActionCloseAfterFlush
	}
	shdMsg := buildTLS12ServerHelloDone()

	st.transcript.Write(payload)
	st.transcript.Write(shMsg)
	st.transcript.Write(certMsg)
	st.transcript.Write(skeMsg)
	st.transcript.Write(shdMsg)

	flight := c.writeBuf
	flight = AppendRecord(flight, 0x16, shMsg)
	flight = AppendRecord(flight, 0x16, certMsg)
	flight = AppendRecord(flight, 0x16, skeMsg)
	flight = AppendRecord(flight, 0x16, shdMsg)
	c.writeBuf = flight

	c.tls12 = st
	c.selectedALPN = selectedALPN
	c.phase = tlsConnPhase12ClientFinish
	c.compactCipher(totalLen)
	c.releaseClientHello()
	return epollActionNeedRead
}

func (c *epollConn) epollTLS12ClientFinish(srv *Server) int {
	st := c.tls12
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(c.readBuf[:c.readN])
		if err != nil {
			return epollActionCloseAfterFlush
		}
		if !ok {
			return epollActionNeedRead
		}
		switch {
		case ct == 0x16 && !st.gotCCS:
			peer, pok := parseTLS12ClientKeyExchange(payload)
			if !pok || !st.deriveKeys(peer) {
				return epollActionCloseAfterFlush
			}
			st.transcript.Write(payload)
			c.compactCipher(totalLen)
		case ct == 0x14:
			st.gotCCS = true
			c.compactCipher(totalLen)
		case ct == 0x16 && st.gotCCS:
			if st.reader == nil {
				return epollActionCloseAfterFlush
			}
			typ, pt, ook := st.reader.open(c.readBuf[:totalLen])
			if !ook || typ != 0x16 || len(pt) < 4 || pt[0] != 0x14 {
				return epollActionCloseAfterFlush
			}
			var thBuf [64]byte
			expected := tls12Finished(st.suite.newHash, st.master, "client finished", st.transcript.Sum(thBuf[:0]))
			if !hmac.Equal(pt[4:], expected) {
				return epollActionCloseAfterFlush
			}
			st.transcript.Write(pt)
			var th2Buf [64]byte
			srvVerify := tls12Finished(st.suite.newHash, st.master, "server finished", st.transcript.Sum(th2Buf[:0]))
			c.writeBuf = AppendRecord(c.writeBuf, 0x14, []byte{0x01})
			c.writeBuf = append(c.writeBuf, st.writer.seal(0x16, tls12Handshake(0x14, srvVerify))...)
			c.compactCipher(totalLen)
			if c.selectedALPN == "h2" {
				c.phase = tlsConnPhaseH2Native
				c.h2.init()
				plain := appendH2ServerSettingsFlight(nil, srv)
				c.writeBuf = buildTLS12AppDataRecords(c.writeBuf, st.writer, plain)
				Stats.H2Conns.Add(1)
				return epollTLSContinue
			}
			c.phase = tlsConnPhaseApplication
			Stats.H1Conns.Add(1)
			return epollTLSContinue
		default:
			return epollActionCloseAfterFlush
		}
	}
}

func (c *epollConn) epollTLS12DecryptToApp(srv *Server) (int, bool) {
	st := c.tls12
	for {
		ct, _, totalLen, ok, err := nextTLSRecord(c.readBuf[:c.readN])
		if err != nil {
			return epollActionCloseAfterFlush, false
		}
		if !ok {
			return epollActionNeedRead, false
		}
		switch ct {
		case 0x17:
			_, pt, ook := st.reader.open(c.readBuf[:totalLen])
			if !ook {
				return epollActionCloseAfterFlush, false
			}
			if len(pt) > srv.effectiveReadCap()-len(c.appBuf) {
				return epollActionCloseAfterFlush, false
			}
			c.appBuf = append(c.appBuf, pt...)
			c.compactCipher(totalLen)
			return epollTLSContinue, true
		case 0x15, 0x16:
			c.compactCipher(totalLen)
			return epollActionCloseAfterFlush, false
		default:
			c.compactCipher(totalLen)
			continue
		}
	}
}
