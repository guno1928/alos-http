//go:build linux && amd64

package core

import (
	"log"
	"net"
	"runtime"
	"sync"

	"github.com/guno1928/alosmap"
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
	if debugFlag.Load() {
		log.Printf("[H3-DBG] serveQUICIOUring: recv loop starting, fd=%d", uc.fd)
	}
	buf := make([]byte, 65536)
	pktCount := 0
	for {
		n, remoteAddr, err := uc.recvFromSyscall(buf)
		if err != nil {
			if s.shuttingDown.Load() || uc.closed.Load() {
				if debugFlag.Load() {
					log.Printf("[H3-DBG] serveQUICIOUring: shutting down")
				}
				return
			}
			if debugFlag.Load() {
				log.Printf("[H3-DBG] serveQUICIOUring: recv error: %v", err)
			}
			continue
		}
		pktCount++
		if debugFlag.Load() {
			log.Printf("[H3-DBG] serveQUICIOUring: UDP packet #%d: %d bytes from %s first=0x%02x", pktCount, n, remoteAddr, buf[0])
		}
		if n < 5 {
			if debugFlag.Load() {
				log.Printf("[H3-DBG] serveQUICIOUring: packet too small (%d bytes), skipping", n)
			}
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handleQUICPacketIOUring(uc, remoteAddr, pkt, connMap)
	}
}

func (s *Server) handleQUICPacketIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, data []byte, connMap *quicConnMap) {
	if len(data) < 5 {
		return
	}

	isLong := quicIsLongHeader(data)
	if debugFlag.Load() {
		log.Printf("[H3-DBG] handleQUICPacket: %d bytes from %s longHeader=%v", len(data), remoteAddr, isLong)
	}

	if isLong {
		s.handleQUICLongPacketIOUring(uc, remoteAddr, data, connMap)
	} else {
		s.handleQUICShortPacketIOUring(uc, remoteAddr, data, connMap)
	}
}

func (s *Server) handleQUICLongPacketIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, data []byte, connMap *quicConnMap) {
	hdr, _, err := quicParseLongHeader(data)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: parse error: %v (dataLen=%d)", err, len(data))
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
				return
			}
		}
		qc.handlePacket(data)
		return
	}

	if qc, exists := connMap.Load(dcidKey); exists {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: forwarding type=%d to existing conn", hdr.pktType)
		}
		qc.handlePacket(data)
	} else {
		if debugFlag.Load() {
			log.Printf("[H3-DBG] handleLongPacket: no conn found for dcid=%x type=%d", hdr.dcid, hdr.pktType)
		}
	}
}

func (s *Server) handleQUICShortPacketIOUring(uc *ioUringUDPConn, remoteAddr *net.UDPAddr, data []byte, connMap *quicConnMap) {
	if len(data) < 1+quicConnIDLen {
		return
	}
	dcid := data[1 : 1+quicConnIDLen]
	dcidKey := quicCIDKey(dcid)

	qc, exists := connMap.Load(dcidKey)
	if !exists {
		return
	}
	qc.handlePacket(data)
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
