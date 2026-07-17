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
	if certEntry == nil {
		return epollActionCloseAfterFlush
	}
	if !c.clientHello.SupportsTLS13() || certEntry.PrivKey == nil || c.clientHello.X25519PubKey == nil {
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
