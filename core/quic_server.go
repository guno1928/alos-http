//go:build !(linux && amd64)

package core

import (
	"encoding/hex"
	"log"
	"net"
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

	connMap := alosmap.New(alosmap.WithoutCleanup())

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

func (s *Server) serveQUICListener(pc net.PacketConn, connMap *alosmap.Map) {
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

func (s *Server) handleQUICPacket(pc net.PacketConn, remoteAddr net.Addr, data []byte, connMap *alosmap.Map) {
	if len(data) < 5 {
		return
	}

	if quicIsLongHeader(data) {
		s.handleQUICLongPacket(pc, remoteAddr, data, connMap)
	} else {
		s.handleQUICShortPacket(pc, remoteAddr, data, connMap)
	}
}

func (s *Server) handleQUICLongPacket(pc net.PacketConn, remoteAddr net.Addr, data []byte, connMap *alosmap.Map) {
	hdr, _, err := quicParseLongHeader(data)
	if err != nil {
		return
	}

	if hdr.version != quicVersion1 {
		return
	}

	dcidKey := hex.EncodeToString(hdr.dcid)

	if hdr.pktType == quicPktInitial {
		var qc *QUICConn
		if v, exists := connMap.Load(alosmap.S(dcidKey)); exists {
			qc, _ = v.(*QUICConn)
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

	if v, exists := connMap.Load(alosmap.S(dcidKey)); exists {
		if qc, ok := v.(*QUICConn); ok {
			qc.handlePacket(data)
		}
	}
}

func (s *Server) handleQUICShortPacket(pc net.PacketConn, remoteAddr net.Addr, data []byte, connMap *alosmap.Map) {
	if len(data) < 1+quicConnIDLen {
		return
	}
	dcid := data[1 : 1+quicConnIDLen]
	dcidKey := hex.EncodeToString(dcid)

	v, exists := connMap.Load(alosmap.S(dcidKey))
	if !exists {
		return
	}
	qc, ok := v.(*QUICConn)
	if !ok {
		return
	}
	qc.handlePacket(data)
}

func (s *Server) createQUICConn(pc net.PacketConn, remoteAddr net.Addr, dcid, scid []byte, connMap *alosmap.Map) *QUICConn {
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

	qc := newQUICConn(s, pc, remoteAddr, dcid, scid)
	qc.keys[quicSpaceInitial] = clientKeys
	qc.sendKeys[quicSpaceInitial] = serverKeys

	qc.tlsState = newQuicTLSState()

	dcidKey := hex.EncodeToString(dcid)
	connMap.Store(alosmap.S(dcidKey), qc)
	srcCIDKey := hex.EncodeToString(qc.srcCID())
	connMap.Store(alosmap.S(srcCIDKey), qc)

	go qc.recvLoop()
	go qc.runIdleTimer()

	quicActiveConns.Add(1)
	Stats.TotalConns.Add(1)
	if debugFlag.Load() {
		log.Printf("[QUIC] new connection from %s dcid=%s scid=%s", remoteAddr, dcidKey, srcCIDKey)
	}

	go func() {
		<-qc.done
		quicActiveConns.Add(-1)
		connMap.Delete(alosmap.S(dcidKey))
		connMap.Delete(alosmap.S(srcCIDKey))
	}()

	return qc
}
