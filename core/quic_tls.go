package core

import (
	"crypto/rand"
	"crypto/subtle"
	"hash"
	"log"
)

type quicTLSState struct {
	hashFn         func() hash.Hash
	hashLen        int
	suite          *CipherSuiteConfig
	transcript     hash.Hash
	ch             ParsedClientHello
	clientHSSecret []byte
	stage          int
}

const (
	quicTLSStageWaitClientHello = 0
	quicTLSStageWaitFinished    = 1
	quicTLSStageDone            = 2
)

func newQuicTLSState() *quicTLSState {
	return &quicTLSState{
		stage: quicTLSStageWaitClientHello,
	}
}

func (ts *quicTLSState) handleCryptoData(qc *QUICConn, space int, data []byte) {
	switch ts.stage {
	case quicTLSStageWaitClientHello:
		if space != quicSpaceInitial {
			return
		}
		ts.handleClientHello(qc, data)
	case quicTLSStageWaitFinished:
		if space == quicSpaceInitial && qc.firstFlight.sent {
			if debugFlag.Load() {
				log.Printf("[QUIC-DBG] retransmitting handshake flight (browser retried Initial)")
			}
			qc.sendFirstFlight(qc.firstFlight.serverHello, qc.firstFlight.ee, qc.firstFlight.cert, qc.firstFlight.cv, qc.firstFlight.fin)
			return
		}
		if space != quicSpaceHandshake {
			return
		}
		ts.handleClientFinished(qc, data)
	}
}

func (ts *quicTLSState) handleClientHello(qc *QUICConn, data []byte) {
	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handleClientHello: dataLen=%d", len(data))
	}
	if len(data) < 4 {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleClientHello: too short (%d < 4)", len(data))
		}
		return
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handleClientHello: msgType=0x%02x msgLen=%d totalAvail=%d", data[0], msgLen, len(data))
	}
	if len(data) < 4+msgLen {
		if debugFlag.Load() {
			log.Printf("[QUIC-DBG] handleClientHello: truncated (%d < %d)", len(data), 4+msgLen)
		}
		return
	}

	ch := &ts.ch
	ch.Reset()
	if err := ParseClientHello(data, ch); err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] bad ClientHello: %v", err)
		}
		return
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] ClientHello: SNI=%q TLS13=%v suites=%v x25519=%v sessionID_len=%d",
			ch.ServerName, ch.SupportsTLS13(), ch.CipherSuites, ch.X25519PubKey != nil, len(ch.SessionID))
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] ClientHello first 20 bytes: %x", data[:min(20, len(data))])
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] ClientHello raw bytes 4-10: %x", data[4:min(10, len(data))])
	}

	if !ch.SupportsTLS13() {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] client doesn't support TLS 1.3")
		}
		return
	}

	suite := NegotiateSuite(ch.CipherSuites)
	if suite == nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] no shared cipher suite")
		}
		return
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] negotiated suite: 0x%04x (hash=%d)", suite.ID, suite.HashLen)
	}
	ts.suite = suite
	ts.hashFn = suite.HashFn
	ts.hashLen = suite.HashLen
	ts.transcript = ts.hashFn()

	if ch.X25519PubKey == nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] no x25519 key share")
		}
		return
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] client x25519 pub: %x", ch.X25519PubKey)
	}

	entry := qc.server.certStore.Lookup(ch.ServerName)
	if entry == nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] no cert for SNI %q", ch.ServerName)
		}
		return
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] cert found for %q, privKey type=%T, chainDER=%d certs", ch.ServerName, entry.PrivKey, len(entry.ChainDER))
	}
	if entry.PrivKey == nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] cert for %q has no private key", ch.ServerName)
		}
		return
	}

	kp, kpErr := qc.server.x25519Pool.Get()
	if kpErr != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] x25519 key generation failed: %v", kpErr)
		}
		return
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] server x25519 pub: %x", kp.pub[:])
	}

	var peerPub [32]byte
	copy(peerPub[:], ch.X25519PubKey)
	sharedSecret, ok := deriveX25519SharedSecret(&kp.priv, &peerPub)
	if !ok {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] x25519 key exchange failed")
		}
		return
	}
	if debugFlag.Load() {
		log.Printf("[H3-TLS] sharedSecret: %x", sharedSecret[:])
	}

	ts.transcript.Write(data[:4+msgLen])
	chHash := make([]byte, 0, ts.hashLen)
	chHash = ts.transcript.Sum(chHash)
	if debugFlag.Load() {
		log.Printf("[H3-TLS] transcript after CH: %x", chHash)
	}

	var serverRandom [32]byte
	rand.Read(serverRandom[:])
	serverHello := BuildServerHello(serverRandom[:], ch.SessionID, suite.ID, kp.pub[:])
	if debugFlag.Load() {
		log.Printf("[H3-TLS] ServerHello: %d bytes, full hex: %x", len(serverHello), serverHello)
	}
	ts.transcript.Write(serverHello)

	chHash = chHash[:0]
	chHash = ts.transcript.Sum(chHash)
	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] CH+SH transcript hash: %x", chHash)
	}

	h := ts.hashFn
	derivedFromEarly := suite.derivedFromEarly
	handshakeSecret := TLSExtract(h, derivedFromEarly, sharedSecret[:])

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] handshakeSecret: %x", handshakeSecret[:min(16, len(handshakeSecret))])
	}
	var clientHSBuf, serverHSBuf [64]byte
	clientHSSecret := suite.DeriveSecretTo(&suite.labelClientHSTraffic, handshakeSecret, chHash, clientHSBuf[:0])
	serverHSSecret := suite.DeriveSecretTo(&suite.labelServerHSTraffic, handshakeSecret, chHash, serverHSBuf[:0])
	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] serverHSSecret: %x", serverHSSecret[:min(16, len(serverHSSecret))])
	}

	clientHSKeys, err := quicDeriveKeys(h, clientHSSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] derive client HS keys: %v", err)
		}
		return
	}
	serverHSKeys, err := quicDeriveKeys(h, serverHSSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] derive server HS keys: %v", err)
		}
		return
	}

	qc.keys[quicSpaceHandshake] = clientHSKeys
	qc.sendKeys[quicSpaceHandshake] = serverHSKeys
	if debugFlag.Load() {
		log.Printf("[H3-TLS] HS keys derived, serverHSKeys IV=%x", serverHSKeys.iv[:])
	}

	tp := quicBuildTransportParams(qc)
	if debugFlag.Load() {
		log.Printf("[H3-TLS] transport params: %d bytes, hex=%x", len(tp), tp[:min(40, len(tp))])
	}
	ee := quicBuildEncryptedExtensions("h3", tp)
	if debugFlag.Load() {
		log.Printf("[H3-TLS] EncryptedExtensions: %d bytes, first20=%x", len(ee), ee[:min(20, len(ee))])
	}
	cert := BuildCertificate(entry.ChainDER)
	if debugFlag.Load() {
		log.Printf("[H3-TLS] Certificate msg: %d bytes, first20=%x", len(cert), cert[:min(20, len(cert))])
	}

	ts.transcript.Write(ee)
	ts.transcript.Write(cert)

	cvHash := make([]byte, 0, ts.hashLen)
	cvHash = ts.transcript.Sum(cvHash)
	if debugFlag.Load() {
		log.Printf("[H3-TLS] transcript after EE+Cert: %x", cvHash)
	}
	cvScheme, sig, sigErr := SignCertificateVerify(entry.PrivKey, cvHash)
	if sigErr != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] sign CertificateVerify: %v", sigErr)
		}
		return
	}
	cv := BuildCertificateVerify(cvScheme, sig)
	if debugFlag.Load() {
		log.Printf("[H3-TLS] CertificateVerify: %d bytes, sigAlg bytes=%x", len(cv), cv[4:min(8, len(cv))])
	}
	ts.transcript.Write(cv)

	finHash := make([]byte, 0, ts.hashLen)
	finHash = ts.transcript.Sum(finHash)
	finData := suite.ComputeFinishedTo(serverHSSecret, finHash, nil)
	fin := BuildFinished(finData)
	ts.transcript.Write(fin)

	if debugFlag.Load() {
		log.Printf("[QUIC-DBG] HS message sizes: serverHello=%d ee=%d cert=%d cv=%d fin=%d chainDER=%d certs",
			len(serverHello), len(ee), len(cert), len(cv), len(fin), len(entry.ChainDER))
	}
	qc.sendFirstFlight(serverHello, ee, cert, cv, fin)

	ts.clientHSSecret = make([]byte, len(clientHSSecret))
	copy(ts.clientHSSecret, clientHSSecret)

	var derivedFromHS [64]byte
	derivedHS := suite.DeriveSecretTo(&suite.labelDerived, handshakeSecret, suite.emptyTranscriptHash, derivedFromHS[:0])
	masterSecret := TLSExtract(h, derivedHS, suite.zeroHashInput)

	sfHash := make([]byte, 0, ts.hashLen)
	sfHash = ts.transcript.Sum(sfHash)
	var clientAppBuf, serverAppBuf [64]byte
	clientAppSecret := suite.DeriveSecretTo(&suite.labelClientAppTraffic, masterSecret, sfHash, clientAppBuf[:0])
	serverAppSecret := suite.DeriveSecretTo(&suite.labelServerAppTraffic, masterSecret, sfHash, serverAppBuf[:0])

	clientAppKeys, err := quicDeriveKeys(h, clientAppSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] derive client app keys: %v", err)
		}
		return
	}
	serverAppKeys, err := quicDeriveKeys(h, serverAppSecret, suite)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] derive server app keys: %v", err)
		}
		return
	}

	qc.keys[quicSpaceAppData] = clientAppKeys
	qc.sendKeys[quicSpaceAppData] = serverAppKeys

	qc.recvSecret = make([]byte, len(clientAppSecret))
	copy(qc.recvSecret, clientAppSecret)
	qc.sendSecret = make([]byte, len(serverAppSecret))
	copy(qc.sendSecret, serverAppSecret)
	qc.appSuite = suite
	qc.origHP = clientAppKeys.hp

	nextRecvSecret := quicDeriveNextTrafficSecret(suite.HashFn, clientAppSecret, suite.HashLen)
	nextRecvKeys, _ := quicDeriveKeys(suite.HashFn, nextRecvSecret, suite)
	if nextRecvKeys != nil {
		nextRecvKeys.hp = clientAppKeys.hp
		qc.nextRecvKeys = nextRecvKeys
	}

	ts.stage = quicTLSStageWaitFinished

	if debugFlag.Load() {
		log.Printf("[QUIC-TLS] server handshake flight sent, waiting for client Finished")
	}
}

const (
	quicTPOrigDstCID            = 0x00
	quicTPMaxIdleTimeout        = 0x01
	quicTPInitialMaxData        = 0x04
	quicTPInitialMaxStreamBidiL = 0x05
	quicTPInitialMaxStreamBidiR = 0x06
	quicTPInitialMaxStreamUni   = 0x07
	quicTPInitialMaxStreamsBidi = 0x08
	quicTPInitialMaxStreamsUni  = 0x09
	quicTPInitialSrcCID         = 0x0f
	quicTPActiveConnIDLimit     = 0x0e
)

func quicBuildTransportParams(qc *QUICConn) []byte {
	var tp []byte
	appendTP := func(id uint64, val []byte) {
		tp = quicAppendVarint(tp, id)
		tp = quicAppendVarint(tp, uint64(len(val)))
		tp = append(tp, val...)
	}
	appendTPVarint := func(id, val uint64) {
		var buf [8]byte
		n := quicPutVarint(buf[:], val)
		appendTP(id, buf[:n])
	}

	idleMs := uint64(qc.idleTimeout.Milliseconds())
	if idleMs == 0 {
		idleMs = 30000
	}
	streamData := uint64(1 << 18)
	if qc.server.config.QUICMaxStreamData > 0 {
		streamData = uint64(qc.server.config.QUICMaxStreamData)
	}

	appendTP(quicTPOrigDstCID, qc.getOrigDstCID())
	appendTP(quicTPInitialSrcCID, qc.srcCID())
	appendTPVarint(quicTPMaxIdleTimeout, idleMs)
	appendTPVarint(quicTPInitialMaxData, qc.maxDataLocal)
	appendTPVarint(quicTPInitialMaxStreamBidiL, streamData)
	appendTPVarint(quicTPInitialMaxStreamBidiR, streamData)
	appendTPVarint(quicTPInitialMaxStreamUni, streamData)
	appendTPVarint(quicTPInitialMaxStreamsBidi, quicMaxBidiStreams)
	appendTPVarint(quicTPInitialMaxStreamsUni, quicMaxUniStreams)
	appendTPVarint(quicTPActiveConnIDLimit, 2)
	return tp
}

func quicBuildEncryptedExtensions(alpn string, transportParams []byte) []byte {
	var exts []byte

	if alpn != "" {
		alpnExt := BuildALPNExtension(alpn)
		exts = append(exts, alpnExt...)
	}

	tpExtType := uint16(0x0039)
	exts = append(exts, byte(tpExtType>>8), byte(tpExtType))
	exts = append(exts, byte(len(transportParams)>>8), byte(len(transportParams)))
	exts = append(exts, transportParams...)

	body := make([]byte, 2+len(exts))
	body[0] = byte(len(exts) >> 8)
	body[1] = byte(len(exts))
	copy(body[2:], exts)
	return HSWrap(0x08, body)
}

func (ts *quicTLSState) handleClientFinished(qc *QUICConn, data []byte) {
	if len(data) < 4 {
		return
	}
	if data[0] != 0x14 {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] expected Finished (0x14), got 0x%02x", data[0])
		}
		return
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return
	}

	clientFinData := data[4 : 4+msgLen]

	finHash := make([]byte, 0, ts.hashLen)
	finHash = ts.transcript.Sum(finHash)
	expectedFin := ts.suite.ComputeFinishedTo(ts.clientHSSecret, finHash, nil)
	if len(clientFinData) != len(expectedFin) {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] client Finished length mismatch")
		}
		return
	}
	if subtle.ConstantTimeCompare(clientFinData, expectedFin) != 1 {
		if debugFlag.Load() {
			log.Printf("[QUIC-TLS] client Finished verify failed")
		}
		return
	}

	ts.transcript.Write(data[:4+msgLen])
	ts.stage = quicTLSStageDone
	qc.handshakeDone.Store(true)
	qc.addressValidated.Store(true)
	qc.keys[quicSpaceHandshake] = nil

	var frames []byte
	frames = quicAppendHandshakeDoneFrame(frames)
	frames = quicAppendMaxDataFrame(frames, quicInitialMaxData)
	frames = quicAppendMaxStreamsFrame(frames, quicMaxBidiStreams, true)
	frames = quicAppendMaxStreamsFrame(frames, quicMaxUniStreams, false)
	qc.sendFrames(quicSpaceAppData, frames, true)

	if debugFlag.Load() {
		log.Printf("[QUIC] handshake complete for %s", qc.remoteAddr.String())
	}

	h3 := newH3Conn(qc)
	h3.start()
}
