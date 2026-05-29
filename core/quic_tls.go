package core

import (
	"crypto/rand"
	"hash"
	"log"
)

type quicTLSState struct {
	hashFn          func() hash.Hash
	hashLen         int
	suite           *CipherSuiteConfig
	transcript      hash.Hash
	ch              ParsedClientHello
	clientHSSecret  []byte
	stage           int
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
		if space != quicSpaceHandshake {
			return
		}
		ts.handleClientFinished(qc, data)
	}
}

func (ts *quicTLSState) handleClientHello(qc *QUICConn, data []byte) {
	if len(data) < 4 {
		return
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return
	}

	ch := &ts.ch
	ch.Reset()
	if err := ParseClientHello(data, ch); err != nil {
		log.Printf("[QUIC-TLS] bad ClientHello: %v", err)
		return
	}

	if !ch.SupportsTLS13() {
		log.Printf("[QUIC-TLS] client doesn't support TLS 1.3")
		return
	}

	suite := NegotiateSuite(ch.CipherSuites)
	if suite == nil {
		log.Printf("[QUIC-TLS] no shared cipher suite")
		return
	}
	ts.suite = suite
	ts.hashFn = suite.HashFn
	ts.hashLen = suite.HashLen
	ts.transcript = ts.hashFn()

	if ch.X25519PubKey == nil {
		log.Printf("[QUIC-TLS] no x25519 key share")
		return
	}

	entry := qc.server.certStore.Lookup(ch.ServerName)
	if entry == nil {
		log.Printf("[QUIC-TLS] no cert for SNI %q", ch.ServerName)
		return
	}
	if entry.PrivKey == nil {
		log.Printf("[QUIC-TLS] cert for %q has no ECDSA private key", ch.ServerName)
		return
	}

	kp, kpErr := qc.server.x25519Pool.Get()
	if kpErr != nil {
		log.Printf("[QUIC-TLS] x25519 key generation failed: %v", kpErr)
		return
	}

	var peerPub [32]byte
	copy(peerPub[:], ch.X25519PubKey)
	sharedSecret, ok := deriveX25519SharedSecret(&kp.priv, &peerPub)
	if !ok {
		log.Printf("[QUIC-TLS] x25519 key exchange failed")
		return
	}

	ts.transcript.Write(data[:4+msgLen])

	var serverRandom [32]byte
	rand.Read(serverRandom[:])
	serverHello := BuildServerHello(serverRandom[:], ch.SessionID, suite.ID, kp.pub[:])
	ts.transcript.Write(serverHello)

	chHash := make([]byte, 0, ts.hashLen)
	chHash = ts.transcript.Sum(chHash)

	h := ts.hashFn
	derivedFromEarly := suite.derivedFromEarly
	handshakeSecret := TLSExtract(h, derivedFromEarly, sharedSecret[:])

	var clientHSBuf, serverHSBuf [64]byte
	clientHSSecret := suite.DeriveSecretTo(&suite.labelClientHSTraffic, handshakeSecret, chHash, clientHSBuf[:0])
	serverHSSecret := suite.DeriveSecretTo(&suite.labelServerHSTraffic, handshakeSecret, chHash, serverHSBuf[:0])

	clientHSKeys, err := quicDeriveKeys(h, clientHSSecret, suite)
	if err != nil {
		log.Printf("[QUIC-TLS] derive client HS keys: %v", err)
		return
	}
	serverHSKeys, err := quicDeriveKeys(h, serverHSSecret, suite)
	if err != nil {
		log.Printf("[QUIC-TLS] derive server HS keys: %v", err)
		return
	}

	qc.keys[quicSpaceHandshake] = clientHSKeys
	qc.sendKeys[quicSpaceHandshake] = serverHSKeys

	tp := quicBuildTransportParams(qc)
	ee := quicBuildEncryptedExtensions("h3", tp)
	cert := BuildCertificate(entry.ChainDER)

	ts.transcript.Write(ee)
	ts.transcript.Write(cert)

	cvHash := make([]byte, 0, ts.hashLen)
	cvHash = ts.transcript.Sum(cvHash)
	sig, sigErr := SignCertificateVerify(entry.PrivKey, cvHash)
	if sigErr != nil {
		log.Printf("[QUIC-TLS] sign CertificateVerify: %v", sigErr)
		return
	}
	cv := BuildCertificateVerify(sig)
	ts.transcript.Write(cv)

	finHash := make([]byte, 0, ts.hashLen)
	finHash = ts.transcript.Sum(finHash)
	finData := suite.ComputeFinishedTo(serverHSSecret, finHash, nil)
	fin := BuildFinished(finData)
	ts.transcript.Write(fin)

	qc.sendCrypto(quicSpaceInitial, serverHello)

	var hsMessages []byte
	hsMessages = append(hsMessages, ee...)
	hsMessages = append(hsMessages, cert...)
	hsMessages = append(hsMessages, cv...)
	hsMessages = append(hsMessages, fin...)
	qc.sendCrypto(quicSpaceHandshake, hsMessages)

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
		log.Printf("[QUIC-TLS] derive client app keys: %v", err)
		return
	}
	serverAppKeys, err := quicDeriveKeys(h, serverAppSecret, suite)
	if err != nil {
		log.Printf("[QUIC-TLS] derive server app keys: %v", err)
		return
	}

	qc.keys[quicSpaceAppData] = clientAppKeys
	qc.sendKeys[quicSpaceAppData] = serverAppKeys

	ts.stage = quicTLSStageWaitFinished

	log.Printf("[QUIC-TLS] server handshake flight sent, waiting for client Finished")
}

const (
	quicTPOrigDstCID              = 0x00
	quicTPMaxIdleTimeout          = 0x01
	quicTPInitialMaxData          = 0x04
	quicTPInitialMaxStreamBidiL   = 0x05
	quicTPInitialMaxStreamBidiR   = 0x06
	quicTPInitialMaxStreamUni     = 0x07
	quicTPInitialMaxStreamsBidi   = 0x08
	quicTPInitialMaxStreamsUni    = 0x09
	quicTPInitialSrcCID           = 0x0f
	quicTPActiveConnIDLimit       = 0x0e
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

	appendTP(quicTPOrigDstCID, qc.getOrigDstCID())
	appendTP(quicTPInitialSrcCID, qc.srcCID())
	appendTPVarint(quicTPMaxIdleTimeout, 30000)
	appendTPVarint(quicTPInitialMaxData, quicInitialMaxData)
	appendTPVarint(quicTPInitialMaxStreamBidiL, 1<<18)
	appendTPVarint(quicTPInitialMaxStreamBidiR, 1<<18)
	appendTPVarint(quicTPInitialMaxStreamUni, 1<<18)
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
		log.Printf("[QUIC-TLS] expected Finished (0x14), got 0x%02x", data[0])
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
		log.Printf("[QUIC-TLS] client Finished length mismatch")
		return
	}
	match := true
	for i := range expectedFin {
		if clientFinData[i] != expectedFin[i] {
			match = false
			break
		}
	}
	if !match {
		log.Printf("[QUIC-TLS] client Finished verify failed")
		return
	}

	ts.transcript.Write(data[:4+msgLen])
	ts.stage = quicTLSStageDone
	qc.handshakeDone.Store(true)
	qc.keys[quicSpaceHandshake] = nil

	var frames []byte
	frames = quicAppendHandshakeDoneFrame(frames)
	frames = quicAppendMaxDataFrame(frames, quicInitialMaxData)
	frames = quicAppendMaxStreamsFrame(frames, quicMaxBidiStreams, true)
	frames = quicAppendMaxStreamsFrame(frames, quicMaxUniStreams, false)
	qc.sendFrames(quicSpaceAppData, frames, true)

	log.Printf("[QUIC] handshake complete for %s", qc.remoteAddr.String())

	h3 := newH3Conn(qc)
	h3.start()
}
