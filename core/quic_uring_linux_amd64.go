//go:build linux && amd64

package core

import (
	"encoding/binary"
	"log"
	"net"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/guno1928/alosmap"
)

const (
	quicRecvBufRingEntries = 2048
	quicRecvBufSize        = 2048
	quicRecvmsgOutSize     = 16
	quicRecvNameLen        = 16
)

// ListenAndServeQUIC serves HTTP/3 over QUIC on the server's configured address (Addr, default ":443") using the loaded TLS certificates, blocking until the server stops. It is the QUIC counterpart to ListenAndServe.
func (s *Server) ListenAndServeQUIC() error {
	if err := s.loadCerts(); err != nil {
		return err
	}
	s.rebuildFallbackTLSConfig()
	s.Router.Build()
	s.computeFastDispatch()
	s.ensureTLSRuntime()

	addr := s.config.Addr
	if addr == "" {
		addr = ":443"
	}

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}

	listeners, err := createQUICListenersIOUring(addr, numListeners)
	if err != nil {
		return err
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	log.Printf("=== ALOS QUIC Server (HTTP/3 io_uring) ===")
	log.Printf("Listening on %s (UDP io_uring, %d listener(s))", addr, len(listeners))

	connMap := alosmap.NewTyped[[20]byte, *QUICConn]().Prealloc(256)

	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(uc *ioUringUDPConn) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			s.serveQUICIOUring(uc, connMap)
		}(ln)
	}

	select {
	case <-s.done:
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}
	wg.Wait()
	return nil
}

func (s *Server) serveQUICIOUring(uc *ioUringUDPConn, connMap *quicConnMap) {
	startReqStreamWorkers()
	uc.startSendLoop()
	if !s.serveQUICMultishot(uc, connMap) {
		s.serveQUICIOUringSingleShot(uc, connMap)
	}
}

// serveQUICMultishot receives QUIC datagrams via io_uring multishot recvmsg with
// a provided buffer ring (the same class of fast path used by HTTP/1.1 and
// HTTP/2). It returns false if multishot setup or arming fails, so the caller can
// fall back to the single-shot path.
func (s *Server) serveQUICMultishot(uc *ioUringUDPConn, connMap *quicConnMap) bool {
	bufRing, err := newIOUringBufferRing(quicRecvBufRingEntries, quicRecvBufSize, 1)
	if err != nil {
		return false
	}
	if err := bufRing.register(uc.recvRing); err != nil {
		bufRing.close()
		return false
	}
	defer bufRing.close()
	defer func() { _ = bufRing.unregister(uc.recvRing) }()

	nameBuf := new([quicRecvNameLen]byte)
	msg := new(msghdr)
	msg.Name = &nameBuf[0]
	msg.Namelen = quicRecvNameLen

	arm := func() bool {
		return uc.recvRing.prepRecvmsgMultishotUser(uc.fd, bufRing.bgid, msg, 1, false) == nil
	}
	if !arm() {
		return false
	}
	if _, err := uc.recvRing.submitIfNeeded(); err != nil {
		return false
	}

	completions := make([]ioUringCqe, 256)
	firstCompletion := true
	for {
		if uc.closed.Load() || s.shuttingDown.Load() {
			return true
		}
		count := uc.recvRing.peekBatch(completions)
		if count == 0 {
			cqe, err := uc.recvRing.waitCqe()
			if err != nil {
				if uc.closed.Load() || s.shuttingDown.Load() {
					return true
				}
				if isIOUringTransient(err) {
					continue
				}
				return true
			}
			completions[0] = cqe
			count = 1
		}
		rearm := false
		for i := 0; i < count; i++ {
			cqe := completions[i]
			if firstCompletion {
				firstCompletion = false
				if cqe.Res < 0 {
					e := syscall.Errno(-cqe.Res)
					if e == syscall.EINVAL || e == syscall.ENOSYS || e == syscall.EOPNOTSUPP {
						return false
					}
				}
			}
			flags := cqe.Flags
			if flags&ioUringCqeBuffer != 0 {
				bid := cqeBufferID(flags)
				if cqe.Res > 0 {
					s.dispatchQUICMultishot(uc, bufRing.buffer(bid), int(cqe.Res), connMap)
				}
				bufRing.recycle(bid)
			}
			if flags&ioUringCqeMore == 0 {
				rearm = true
			}
		}
		if rearm && !uc.closed.Load() && !s.shuttingDown.Load() {
			if !arm() {
				return true
			}
		}
		if _, err := uc.recvRing.submitIfNeeded(); err != nil {
			if uc.closed.Load() || s.shuttingDown.Load() {
				return true
			}
		}
	}
}

func (s *Server) dispatchQUICMultishot(uc *ioUringUDPConn, buf []byte, res int, connMap *quicConnMap) {
	payloadOff := quicRecvmsgOutSize + quicRecvNameLen
	if buf == nil || res <= payloadOff || len(buf) < payloadOff {
		return
	}
	namelen := binary.LittleEndian.Uint32(buf[0:4])
	payloadlen := binary.LittleEndian.Uint32(buf[8:12])
	if namelen == 0 {
		return
	}
	pl := int(payloadlen)
	if pl <= 0 || payloadOff+pl > res {
		pl = res - payloadOff
	}
	if pl < 5 || payloadOff+pl > len(buf) {
		return
	}
	sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&buf[quicRecvmsgOutSize]))
	pbuf := quicRecvBufPool.Get().(*[]byte)
	*pbuf = append((*pbuf)[:0], buf[payloadOff:payloadOff+pl]...)
	var addr *net.UDPAddr
	if quicIsLongHeader(*pbuf) {
		addr = sockaddrToUDPAddr(sa)
	}
	s.handleQUICPacketIOUring(uc, addr, *pbuf, pbuf, connMap)
}

func (s *Server) serveQUICIOUringSingleShot(uc *ioUringUDPConn, connMap *quicConnMap) {
	buf := make([]byte, 65536)
	for {
		n, remoteAddr, err := uc.recvmsgURing(buf)
		if err != nil {
			if s.shuttingDown.Load() || uc.closed.Load() {
				return
			}
			continue
		}
		if n < 5 {
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handleQUICPacketIOUring(uc, remoteAddr, pkt, nil, connMap)
	}
}

func (s *Server) handleQUICPacketIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
	if len(data) < 5 {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}

	isLong := quicIsLongHeader(data)
	if debugFlag.Load() {
		log.Printf("[H3-DBG] handleQUICPacket: %d bytes from %s longHeader=%v", len(data), remoteAddr, isLong)
	}

	if isLong {
		s.handleQUICLongPacketIOUring(uc, remoteAddr, data, pbuf, connMap)
	} else {
		s.handleQUICShortPacketIOUring(uc, remoteAddr, data, pbuf, connMap)
	}
}

func (s *Server) handleQUICLongPacketIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
	hdr, _, err := quicParseLongHeader(data)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: parse error: %v (dataLen=%d)", err, len(data))
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}

	if debugFlag.Load() {
		log.Printf("[H3-DBG] handleLongPacket: type=%d ver=0x%08x dcid=%x scid=%x from %s",
			hdr.pktType, hdr.version, hdr.dcid, hdr.scid, remoteAddr)
	}

	if hdr.version != quicVersion1 {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: unsupported version 0x%08x", hdr.version)
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}

	dcidKey := quicCIDKey(hdr.dcid)

	if hdr.pktType == quicPktInitial {
		var qc *QUICConn
		if v, exists := connMap.Load(dcidKey); exists {
			qc = v
			if debugFlag.Load() {
				log.Printf("[H3-DBG] handleLongPacket: existing conn for dcid=%x", hdr.dcid)
			}
		}
		if qc == nil {
			if debugFlag.Load() {
				log.Printf("[H3-DBG] handleLongPacket: NEW Initial from %s, creating conn", remoteAddr)
			}
			qc = s.createQUICConnIOUring(uc, remoteAddr, hdr.dcid, hdr.scid, connMap)
			if qc == nil {
				if debugFlag.Load() {
					log.Printf("[H3-DBG] handleLongPacket: createQUICConnIOUring returned nil!")
				}
				if pbuf != nil {
					quicRecvBufPool.Put(pbuf)
				}
				return
			}
		}
		qc.handlePacketPooled(data, pbuf)
		return
	}

	if qc, exists := connMap.Load(dcidKey); exists {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: forwarding type=%d to existing conn", hdr.pktType)
		}
		qc.handlePacketPooled(data, pbuf)
	} else {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: no conn found for dcid=%x type=%d", hdr.dcid, hdr.pktType)
		}
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
	}
}

func (s *Server) handleQUICShortPacketIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
	if len(data) < 1+quicConnIDLen {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}
	dcid := data[1 : 1+quicConnIDLen]
	dcidKey := quicCIDKey(dcid)

	qc, exists := connMap.Load(dcidKey)
	if !exists {
		if pbuf != nil {
			quicRecvBufPool.Put(pbuf)
		}
		return
	}
	qc.handlePacketPooled(data, pbuf)
}

func newQUICConnIOUring(server *Server, uc *ioUringUDPConn, remoteAddr *net.UDPAddr, dcid, scid []byte) *QUICConn {
	qc := newQUICConn(server, nil, remoteAddr, dcid, scid)
	qc.udpAddr = remoteAddr
	qc.uringUDP = uc
	return qc
}

func (s *Server) createQUICConnIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, dcid, scid []byte, connMap *quicConnMap) *QUICConn {
	if quicActiveConns.Load() >= quicMaxConns {
		return nil
	}
	clientKeys, serverKeys, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC] derive initial keys: %v", err)
		}
		return nil
	}

	qc := newQUICConnIOUring(s, uc, remoteAddr, dcid, scid)
	qc.keys[quicSpaceInitial] = clientKeys
	qc.sendKeys[quicSpaceInitial] = serverKeys

	qc.tlsState = newQuicTLSState()

	dcidKey := quicCIDKey(dcid)
	connMap.Store(dcidKey, qc)
	srcCIDKey := quicCIDKey(qc.srcCID())
	connMap.Store(srcCIDKey, qc)

	go qc.recvLoop()
	go qc.runIdleTimer()
	go qc.runLossTimer()

	quicActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	if debugFlag.Load() {
		log.Printf("[QUIC] new io_uring connection from %s dcid=%x scid=%x tlsState=%v keys=%v",
			remoteAddr, dcid, qc.srcCID(), qc.tlsState != nil, qc.keys[quicSpaceInitial] != nil)
	}

	origKey := quicCIDKey(qc.getOrigDstCID())
	go func() {
		<-qc.done
		quicActiveConns.Add(-1)
		connMap.Delete(dcidKey)
		connMap.Delete(srcCIDKey)
		if origKey != dcidKey {
			connMap.Delete(origKey)
		}
	}()

	return qc
}
