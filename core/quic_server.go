//go:build !(linux && amd64)

package core

import (
	"log"
	"net"
	"sync"

	"github.com/guno1928/alosmap"
)

// ListenAndServeQUIC starts the QUIC (HTTP/3) UDP listener(s) on the
// server's configured address and blocks until the server is shut down.
func (s *Server) ListenAndServeQUIC() error {
	if err := s.ensureStartInit(); err != nil {
		return err
	}
	s.ensureTLSRuntime()

	addr := s.config.Addr
	if addr == "" {
		addr = ":443"
	}

	numListeners := s.config.Listeners
	if numListeners <= 0 {
		numListeners = 1
	}

	listeners, err := createQUICListeners(addr, numListeners)
	if err != nil {
		return err
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	log.Printf("=== ALOS QUIC Server (HTTP/3) ===")
	log.Printf("Listening on %s (UDP, %d listener(s))", addr, len(listeners))

	connMap := alosmap.NewTyped[[20]byte, *QUICConn]().Prealloc(256)

	var wg sync.WaitGroup
	for _, ln := range listeners {
		wg.Add(1)
		go func(pc net.PacketConn) {
			defer wg.Done()
			s.serveQUICListener(pc, connMap)
		}(ln)
	}

	select {
	case <-s.done:
		for _, ln := range listeners {
			ln.Close()
		}
	}
	wg.Wait()
	return nil
}

func (s *Server) serveQUICListener(pc net.PacketConn, connMap *quicConnMap) {
	startReqStreamWorkers()
	if udpConn, ok := pc.(*net.UDPConn); ok {
		udpConn.SetReadBuffer(4 << 20)
		udpConn.SetWriteBuffer(4 << 20)
	}

	buf := make([]byte, 65536)
	for {
		n, remoteAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.shuttingDown.Load() {
				return
			}
			continue
		}
		if n < 5 {
			continue
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.handleQUICPacket(pc, remoteAddr, pkt, connMap)
	}
}

func (s *Server) handleQUICPacket(pc net.PacketConn, remoteAddr net.Addr, data []byte, connMap *quicConnMap) {
	if len(data) < 5 {
		return
	}

	if quicIsLongHeader(data) {
		s.handleQUICLongPacket(pc, remoteAddr, data, connMap)
	} else {
		s.handleQUICShortPacket(pc, remoteAddr, data, connMap)
	}
}

func (s *Server) handleQUICLongPacket(pc net.PacketConn, remoteAddr net.Addr, data []byte, connMap *quicConnMap) {
	hdr, _, err := quicParseLongHeader(data)
	if err != nil {
		return
	}

	if hdr.version != quicVersion1 {
		return
	}

	dcidKey := quicCIDKey(hdr.dcid)

	if hdr.pktType == quicPktInitial {
		var qc *QUICConn
		if v, exists := connMap.Load(dcidKey); exists {
			qc = v
		}
		if len(data) < quicMinInitialDatagram && (qc == nil || !qc.addressValidated.Load()) {
			return
		}
		if qc == nil {
			qc = s.createQUICConn(pc, remoteAddr, hdr.dcid, hdr.scid, connMap)
			if qc == nil {
				return
			}
		}
		qc.handlePacket(data)
		return
	}

	if qc, exists := connMap.Load(dcidKey); exists {
		qc.handlePacket(data)
	}
}

func (s *Server) handleQUICShortPacket(pc net.PacketConn, remoteAddr net.Addr, data []byte, connMap *quicConnMap) {
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

func (s *Server) createQUICConn(pc net.PacketConn, remoteAddr net.Addr, dcid, scid []byte, connMap *quicConnMap) *QUICConn {
	if quicActiveConns.Load() >= quicMaxConns {
		return nil
	}
	if quicHandshakingConns.Load() >= quicMaxHandshaking {
		return nil
	}
	clientKeys, serverKeys, err := quicDeriveInitialKeys(dcid)
	if err != nil {
		if debugFlag.Load() {
			log.Printf("[QUIC] derive initial keys: %v", err)
		}
		return nil
	}

	qc := newQUICConn(s, pc, remoteAddr, dcid, scid)
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
	quicHandshakingConns.Add(1)
	qc.handshakeCounted.Store(true)
	Stats.TotalConns.Add(1)
	if debugFlag.Load() {
		log.Printf("[QUIC] new connection from %s dcid=%x scid=%x", remoteAddr, dcid, qc.srcCID())
	}

	origKey := quicCIDKey(qc.getOrigDstCID())
	go func() {
		<-qc.done
		quicActiveConns.Add(-1)
		qc.clearHandshaking()
		connMap.Delete(dcidKey)
		connMap.Delete(srcCIDKey)
		if origKey != dcidKey {
			connMap.Delete(origKey)
		}
	}()

	return qc
}
