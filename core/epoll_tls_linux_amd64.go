//go:build linux && amd64

package core

import "crypto/rand"

func (c *epollConn) consumeCipher(n int) {
	c.cipherOff += n
}

func (c *epollConn) cipherInput() []byte {
	return c.readBuf[c.cipherOff:c.readN]
}

func (c *epollConn) settleCipher() {
	if c.cipherOff == 0 {
		return
	}
	remaining := c.readN - c.cipherOff
	if remaining > 0 {
		copy(c.readBuf, c.readBuf[c.cipherOff:c.readN])
	} else {
		remaining = 0
	}
	c.readN = remaining
	c.cipherOff = 0
}

func (c *epollConn) skipUselessRecord(n int) bool {
	c.consumeCipher(n)
	c.tlsUselessRecords++
	return c.tlsUselessRecords <= tlsMaxUselessRecords
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
	action := c.runTLSPhases(srv)
	c.settleCipher()
	return action
}

func (c *epollConn) runTLSPhases(srv *Server) int {
	if c.plainBuf == nil {
		c.plainBuf = c.worker.acquireWriteBuf()
	}
	if c.appBuf == nil {
		c.appBuf = c.worker.acquireWriteBuf()
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
	payload, totalLen, act, ok := c.nextClientHelloRecord()
	if !ok {
		return act
	}
	if c.clientHello == nil {
		c.clientHello = clientHelloPool.Get().(*ParsedClientHello)
	}
	if err := ParseClientHello(payload, c.clientHello); err != nil {
		return c.failTLS(clientHelloParseAlert(err))
	}
	if c.clientHello.rejectsProtocolVersion() {
		return c.failTLS(alertProtocolVersion)
	}
	selectedALPN := srv.negotiateALPN(c.clientHello.ALPNProtos)
	if len(c.clientHello.ALPNProtos) > 0 && selectedALPN == "" {
		return c.failTLS(alertNoApplicationProtocol)
	}
	certEntry := srv.certStore.Lookup(c.clientHello.ServerName)
	if certEntry == nil || certEntry.PrivKey == nil {
		return c.failTLS(certMissAlert(c.clientHello.ServerName))
	}
	c.tlsCertEntry = certEntry
	if !c.clientHello.SupportsTLS13() {
		if c.tlsRetry != nil {
			return c.failTLS(alertIllegalParameter)
		}
		if c.clientHello.inappropriateFallback() {
			return c.failTLS(alertInappropriateFallback)
		}
		if c.clientHello.renegotiatedConn {
			return c.failTLS(alertHandshakeFailure)
		}
		c.tlsVersion = TLSVersion12
		return c.epollTLS12ClientHello(srv, payload, totalLen, selectedALPN, certEntry)
	}
	policy := srv.clientAuthFor(certEntry)
	c.tlsVersion = TLSVersion13
	cs, choice, act, ok := c.negotiateTLS13(srv, payload, totalLen)
	if !ok {
		return act
	}
	var retryPrefix []byte
	if c.tlsRetry != nil {
		retryPrefix = c.tlsRetry.transcriptPrefix
	}
	transcript := cs.HashFn()
	transcript.Write(retryPrefix)
	transcript.Write(payload)

	sc := acquireTLS13HelloScratch()
	defer releaseTLS13HelloScratch(sc)
	session, alert, ok := srv.acceptResumption(resumeRequest{
		ch:               c.clientHello,
		cs:               cs,
		policy:           policy,
		transcriptPrefix: retryPrefix,
		hello:            payload,
	}, sc.early[:0])
	if !ok {
		return c.failTLS(alert)
	}
	resumed := session.early != nil
	hsSalt := cs.derivedFromEarly
	if resumed {
		hsSalt = cs.DeriveSecretTo(&cs.labelDerived, session.early, cs.emptyTranscriptHash, sc.salt[:0])
		clear(sc.early[:])
	}
	requestCert := policy.requests() && !resumed
	var staple *ocspStaple
	if !resumed {
		staple = certEntry.stapleFor(c.clientHello)
	}

	var kx serverKeyShare
	if alert, ok := srv.completeKeyShare(&kx, choice.group, choice.share); !ok {
		return c.failTLS(alert)
	}
	defer kx.wipe()

	var srvRandom [32]byte
	if _, err := rand.Read(srvRandom[:]); err != nil {
		return c.failTLS(alertInternalError)
	}
	shMsg := buildServerHelloMessage(serverHelloSpec{
		random:    srvRandom[:],
		sessionID: c.clientHello.SessionID,
		suite:     cs.ID,
		group:     uint16(choice.group),
		share:     kx.share(),
		psk:       resumed,
	})
	transcript.Write(shMsg)

	var handshakeSecretBuf [64]byte
	handshakeSecret := kx.extractHandshakeSecret(cs, hsSalt, handshakeSecretBuf[:0])
	clear(sc.salt[:])
	hsHash := transcript.Sum(sc.hsHash[:0])
	var clientHSSecretBuf [64]byte
	clientHSSecret := cs.DeriveSecretTo(&cs.labelClientHSTraffic, handshakeSecret, hsHash, clientHSSecretBuf[:0])
	var serverHSSecretBuf [64]byte
	serverHSSecret := cs.DeriveSecretTo(&cs.labelServerHSTraffic, handshakeSecret, hsHash, serverHSSecretBuf[:0])

	serverHSWriter, err := NewTrafficAEAD(cs.HashFn, serverHSSecret, cs)
	if err != nil {
		return c.failTLS(alertInternalError)
	}
	clientHSReader, err := NewTrafficAEAD(cs.HashFn, clientHSSecret, cs)
	if err != nil {
		return c.failTLS(alertInternalError)
	}

	inner := c.plainBuf[:0]
	if resumed {
		ee := certEntry.CachedEE(selectedALPN)
		transcript.Write(ee)
		inner = append(inner, ee...)
	} else if requestCert || staple != nil {
		inner = append(inner, certEntry.CachedEE(selectedALPN)...)
		if requestCert {
			inner = append(inner, certificateRequest13...)
		}
		inner = append(inner, certEntry.certificate13(staple)...)
		transcript.Write(inner)
	} else {
		eeCert := certEntry.CachedEECert(selectedALPN)
		transcript.Write(eeCert)
		inner = append(inner, eeCert...)
	}
	if !resumed {
		cvScheme, sig, err := SignCertificateVerify(certEntry.PrivKey, transcript.Sum(sc.cvHash[:0]), c.clientHello.SignatureSchemes)
		if err != nil {
			return c.failTLS(signFailureAlert(err))
		}
		cvStart := len(inner)
		inner = appendCertificateVerify(inner, cvScheme, sig)
		transcript.Write(inner[cvStart:])
	}
	var srvVerifyBuf [64]byte
	srvVerifyData := cs.ComputeFinishedTo(serverHSSecret, transcript.Sum(sc.finHash[:0]), srvVerifyBuf[:0])
	finStart := len(inner)
	inner = appendFinished(inner, srvVerifyData)
	fin := inner[finStart:]
	transcript.Write(fin)
	inner = append(inner, 0x16)
	c.plainBuf = inner

	flight := c.writeBuf
	flight = AppendRecord(flight, 0x16, shMsg)
	if c.tlsRetry == nil {
		flight = AppendRecord(flight, 0x14, tlsCompatCCS[:])
	}
	flight = appendTLSInnerRecords(flight, serverHSWriter, inner)

	var derivedFromHSBuf [64]byte
	derivedFromHS := cs.DeriveSecretTo(&cs.labelDerived, handshakeSecret, cs.emptyTranscriptHash, derivedFromHSBuf[:0])
	var masterSecretBuf [64]byte
	masterSecret := TLSExtractTo(cs.HashFn, derivedFromHS, cs.zeroHashInput, masterSecretBuf[:0])
	appHash := transcript.Sum(sc.appHash[:0])
	var clientAppSecretBuf [64]byte
	clientAppSecret := cs.DeriveSecretTo(&cs.labelClientAppTraffic, masterSecret, appHash, clientAppSecretBuf[:0])
	var serverAppSecretBuf [64]byte
	serverAppSecret := cs.DeriveSecretTo(&cs.labelServerAppTraffic, masterSecret, appHash, serverAppSecretBuf[:0])
	clientAppReader, err := NewTrafficAEAD(cs.HashFn, clientAppSecret, cs)
	if err != nil {
		return c.failTLS(alertInternalError)
	}
	serverAppWriter, err := NewTrafficAEAD(cs.HashFn, serverAppSecret, cs)
	if err != nil {
		return c.failTLS(alertInternalError)
	}
	c.writeBuf = flight
	if len(flight) == c.writeSent {
		return epollActionCloseAfterFlush
	}
	if requestCert {
		c.clientAuth = newTLS13ClientAuth(policy, cs, transcript, clientHSSecret)
		if srv.issuesTickets(c.clientHello) {
			c.clientAuth.holdTicketMaster(masterSecret, c.clientHello.ServerName)
		}
	}
	verify := cs.ComputeFinishedTo(clientHSSecret, appHash, c.expectedFin[:0])
	c.expectedFinN = len(verify)
	c.peerCerts = session.peerCerts
	if !requestCert && srv.issuesTickets(c.clientHello) {
		transcript.Write(appendFinished(sc.clientFin[:0], verify))
		c.ticket = newPendingTicket(cs, masterSecret, transcript.Sum(sc.resHash[:0]), c.clientHello.ServerName, selectedALPN, session.peerChain)
	}
	c.hsReader = clientHSReader
	c.appReader = clientAppReader
	c.appWriter = serverAppWriter
	c.sendSessionTicket(srv)
	c.selectedALPN = selectedALPN
	c.phase = tlsConnPhaseClientFinished
	c.tlsRetry = nil
	c.consumeCipher(totalLen)
	c.releaseClientHello()
	return epollActionNeedRead
}

func (c *epollConn) epollTLSClientFinished(srv *Server) int {
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(c.cipherInput())
		if err != nil {
			return c.failTLS(alertRecordOverflow)
		}
		if !ok {
			return epollActionNeedRead
		}
		if ct == 0x14 {
			if !c.skipUselessRecord(totalLen) {
				return c.failTLS(alertUnexpectedMessage)
			}
			continue
		}
		if ct != 0x17 {
			return c.failUnexpectedRecord(ct)
		}
		finPt, err := c.hsReader.Decrypt(payload)
		if err != nil {
			return c.failTLS(alertBadRecordMAC)
		}
		finContent, finCT, err := StripInnerPlaintext(finPt)
		if err != nil || finCT != 0x16 {
			return c.failUnexpectedRecord(finCT)
		}
		if c.clientAuth != nil {
			done, alert, ok := c.clientAuth.feed(finContent)
			if !ok {
				return c.failTLS(alert)
			}
			c.consumeCipher(totalLen)
			if !done {
				continue
			}
			c.peerCerts = c.clientAuth.peerCerts
			c.ticket = c.clientAuth.pendingTicket(c.selectedALPN)
			c.clientAuth = nil
			return c.completeTLS13Handshake(srv)
		}
		if act, ok := c.checkFinishedMessage(finContent, c.expectedFin[:c.expectedFinN]); !ok {
			return act
		}
		c.consumeCipher(totalLen)
		return c.completeTLS13Handshake(srv)
	}
}

func (c *epollConn) completeTLS13Handshake(srv *Server) int {
	c.hsReader = nil
	c.sendSessionTicket(srv)
	if c.selectedALPN == "h2" {
		c.phase = tlsConnPhaseH2Native
		c.h2.init(srv.h2HeaderTableSize(), srv.h2HeaderListLimit())
		c.deadline = deadlineFrom(c.worker.readTO)
		plain := appendH2ServerSettingsFlight(nil, srv)
		c.writeBuf = buildTLSAppDataRecords(c.writeBuf, c.appWriter, plain)
		Stats.H2Conns.Add(1)
		return epollTLSContinue
	}
	c.phase = tlsConnPhaseApplication
	c.deadline = deadlineFrom(c.worker.headerTO)
	Stats.H1Conns.Add(1)
	return epollTLSContinue
}

type tlsAppRecord uint8

const (
	tlsAppRecordData tlsAppRecord = iota
	tlsAppRecordControl
	tlsAppRecordPeerClosed
	tlsAppRecordFatal
)

func (c *epollConn) epollTLSDecryptToApp(srv *Server) (int, bool) {
	if c.tlsPeerClosed {
		return epollActionCloseAfterFlush, false
	}
	gotData := false
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(c.cipherInput())
		if err != nil {
			return c.failTLS(alertRecordOverflow), false
		}
		if !ok {
			break
		}
		if gotData && (ct != tlsRecAppData || len(payload) > srv.effectiveReadCap()-len(c.appBuf)) {
			break
		}
		var kind tlsAppRecord
		var content []byte
		var alert tlsAlert
		if c.tls12 != nil {
			kind, content, alert = c.openTLS12AppRecord(ct, c.cipherInput()[:totalLen])
		} else {
			kind, content, alert = c.openTLS13AppRecord(ct, payload)
		}
		switch kind {
		case tlsAppRecordFatal:
			return c.failTLS(alert), false
		case tlsAppRecordPeerClosed:
			c.consumeCipher(totalLen)
			c.tlsPeerClosed = true
			if gotData {
				c.settleCipher()
				return epollTLSContinue, true
			}
			return epollActionCloseAfterFlush, false
		case tlsAppRecordData:
			if len(content) == 0 {
				break
			}
			if len(content) > srv.effectiveReadCap()-len(c.appBuf) {
				return epollActionCloseAfterFlush, false
			}
			if c.tls12 == nil {
				c.appBuf = c.appBuf[:len(c.appBuf)+len(content)]
			} else {
				c.appBuf = append(c.appBuf, content...)
			}
			c.consumeCipher(totalLen)
			c.tlsUselessRecords = 0
			gotData = true
			continue
		}
		if !c.skipUselessRecord(totalLen) {
			return c.failTLS(alertUnexpectedMessage), false
		}
	}
	if gotData {
		c.settleCipher()
		return epollTLSContinue, true
	}
	return epollActionNeedRead, false
}

func (c *epollConn) openTLS13AppRecord(ct byte, payload []byte) (tlsAppRecord, []byte, tlsAlert) {
	switch ct {
	case tlsRecAppData:
	case tlsRecAlert:
		return tlsAppRecordPeerClosed, nil, 0
	default:
		return tlsAppRecordFatal, nil, alertUnexpectedMessage
	}
	c.appBuf = ensureTailCap(c.appBuf, len(payload))
	base := len(c.appBuf)
	pt, err := c.appReader.decryptAppend(c.appBuf, payload)
	if err != nil {
		return tlsAppRecordFatal, nil, alertBadRecordMAC
	}
	pt = pt[base:]
	if len(pt) > MaxRecordPayload+1 {
		return tlsAppRecordFatal, nil, alertRecordOverflow
	}
	content, innerType, err := StripInnerPlaintext(pt)
	if err != nil {
		return tlsAppRecordFatal, nil, alertUnexpectedMessage
	}
	switch innerType {
	case tlsRecAppData:
		return tlsAppRecordData, content, 0
	case tlsRecAlert:
		return tlsAppRecordPeerClosed, nil, 0
	case tlsRecHandshake:
		if alert, ok := c.acceptKeyUpdate(content); !ok {
			return tlsAppRecordFatal, nil, alert
		}
		return tlsAppRecordControl, nil, 0
	}
	return tlsAppRecordFatal, nil, alertUnexpectedMessage
}

func (c *epollConn) acceptKeyUpdate(msg []byte) (tlsAlert, bool) {
	requested, alert, ok := parseKeyUpdate(msg)
	if !ok {
		return alert, false
	}
	if !c.appReader.advanceGeneration() {
		return alertInternalError, false
	}
	if requested {
		if c.writeBuf, ok = appendKeyUpdateRecord(c.writeBuf, c.appWriter); !ok {
			return alertInternalError, false
		}
	}
	return 0, true
}

func (c *epollConn) openTLS12AppRecord(ct byte, record []byte) (tlsAppRecord, []byte, tlsAlert) {
	switch ct {
	case tlsRecAppData:
		_, pt, ok := c.tls12.reader.open(record)
		if !ok {
			return tlsAppRecordFatal, nil, alertBadRecordMAC
		}
		if len(pt) > MaxRecordPayload {
			return tlsAppRecordFatal, nil, alertRecordOverflow
		}
		return tlsAppRecordData, pt, 0
	case tlsRecAlert:
		return tlsAppRecordPeerClosed, nil, 0
	case tlsRecHandshake:
		return tlsAppRecordFatal, nil, alertHandshakeFailure
	}
	return tlsAppRecordFatal, nil, alertUnexpectedMessage
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
		return c.failTLS(alertInternalError)
	}
	policy := srv.clientAuthFor(certEntry)
	resumption, alert, ok := srv.acceptTLS12Ticket(c.clientHello, kt, policy)
	if !ok {
		return c.failTLS(alert)
	}
	if resumption.suite != nil {
		return c.epollTLS12Resume(srv, payload, totalLen, selectedALPN, &resumption)
	}
	suite := negotiateTLS12Suite(c.clientHello.CipherSuites, kt)
	if suite == nil {
		return c.failTLS(alertHandshakeFailure)
	}
	curve, ok := selectTLS12Curve(c.clientHello.SupportedGroups)
	if !ok {
		return c.failTLS(alertHandshakeFailure)
	}
	st := &tls12State{
		suite:       suite,
		curve:       curve,
		transcript:  suite.newHash(),
		ems:         c.clientHello.extendedMasterSecret,
		issueTicket: srv.tickets != nil && c.clientHello.sessionTicketOffered,
		sni:         c.clientHello.ServerName,
	}
	ecdhePub, err := st.generateECDHE(srv.x25519Pool)
	if err != nil {
		return c.failTLS(alertInternalError)
	}
	st.clientRandom = c.clientHello.Random
	if !st.newServerRandom() {
		return c.failTLS(alertInternalError)
	}

	staple := certEntry.stapleFor(c.clientHello)
	shMsg := buildTLS12ServerHello(st.serverRandom[:], suite.id, tls12HelloOptions{
		alpn:                 selectedALPN,
		extendedMasterSecret: st.ems,
		secureRenegotiation:  c.clientHello.secureRenegotiation,
		sessionTicket:        st.issueTicket,
		ocspStaple:           staple != nil,
	})
	certMsg := certEntry.tls12CertificateMsg()
	skeMsg, err := buildTLS12ServerKeyExchange(certEntry.PrivKey, st.clientRandom[:], st.serverRandom[:], curve, ecdhePub, c.clientHello.SignatureSchemes)
	if err != nil {
		return c.failTLS(signFailureAlert(err))
	}
	shdMsg := tls12ServerHelloDoneMsg[:]
	if policy.requests() {
		st.requestClientCert(policy)
	}

	st.record(payload)
	st.record(shMsg)
	st.record(certMsg)
	flight := c.writeBuf
	flight = AppendRecord(flight, 0x16, shMsg)
	flight = AppendRecord(flight, 0x16, certMsg)
	if staple != nil {
		st.record(staple.status12)
		flight = AppendRecord(flight, 0x16, staple.status12)
	}
	st.record(skeMsg)
	flight = AppendRecord(flight, 0x16, skeMsg)
	if st.expectCert {
		st.record(certificateRequest12)
		flight = AppendRecord(flight, 0x16, certificateRequest12)
	}
	st.record(shdMsg)
	flight = AppendRecord(flight, 0x16, shdMsg)
	c.writeBuf = flight

	c.tls12 = st
	c.selectedALPN = selectedALPN
	c.phase = tlsConnPhase12ClientFinish
	c.consumeCipher(totalLen)
	c.releaseClientHello()
	return epollActionNeedRead
}

func (c *epollConn) epollTLS12ClientFinish(srv *Server) int {
	st := c.tls12
	for {
		ct, payload, totalLen, ok, err := nextTLSRecord(c.cipherInput())
		if err != nil {
			return c.failTLS(alertRecordOverflow)
		}
		if !ok {
			return epollActionNeedRead
		}
		switch {
		case ct == 0x16 && !st.gotCCS:
			if alert, ok := st.handleClientFlight(payload); !ok {
				return c.failTLS(alert)
			}
			c.consumeCipher(totalLen)
		case ct == 0x14 && !st.gotCCS:
			if !st.clientFlightComplete() {
				return c.failTLS(alertUnexpectedMessage)
			}
			st.gotCCS = true
			c.consumeCipher(totalLen)
		case ct == 0x16 && st.gotCCS:
			if st.reader == nil {
				return c.failTLS(alertUnexpectedMessage)
			}
			typ, pt, ook := st.reader.open(c.cipherInput()[:totalLen])
			if !ook {
				return c.failTLS(alertBadRecordMAC)
			}
			if typ != 0x16 {
				return c.failUnexpectedRecord(typ)
			}
			var thBuf [64]byte
			expected := tls12Finished(st.suite.newHash, st.master, "client finished", st.transcript.Sum(thBuf[:0]))
			if act, ok := c.checkFinishedMessage(pt, expected); !ok {
				return act
			}
			st.transcript.Write(pt)
			if !st.resumed {
				c.writeBuf = c.appendTLS12ServerFinish(srv, c.writeBuf)
			}
			c.peerCerts = st.peerCerts
			st.pending = nil
			c.consumeCipher(totalLen)
			if c.selectedALPN == "h2" {
				c.phase = tlsConnPhaseH2Native
				c.h2.init(srv.h2HeaderTableSize(), srv.h2HeaderListLimit())
				c.deadline = deadlineFrom(c.worker.readTO)
				plain := appendH2ServerSettingsFlight(nil, srv)
				c.writeBuf = buildTLS12AppDataRecords(c.writeBuf, st.writer, plain)
				Stats.H2Conns.Add(1)
				return epollTLSContinue
			}
			c.phase = tlsConnPhaseApplication
			c.deadline = deadlineFrom(c.worker.headerTO)
			Stats.H1Conns.Add(1)
			return epollTLSContinue
		default:
			return c.failUnexpectedRecord(ct)
		}
	}
}
