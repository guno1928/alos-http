//go:build linux && amd64

package core

import (
	"log"
	"net"

	"github.com/guno1928/alosmap"
)

// ListenAndServeQUIC starts the HTTP/3 server over QUIC, listening for UDP
// packets on the configured address (default ":443") using the epoll-based
// receive path. It blocks until the server is shut down.
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

	log.Printf("=== ALOS QUIC Server (HTTP/3 epoll) ===")
	log.Printf("Listening on %s (UDP recvfrom/sendto, %d listener(s))", addr, numListeners)

	connMap := alosmap.NewTyped[[20]byte, *QUICConn]().Prealloc(256)
	return s.listenAndServeQUICEpoll(addr, connMap)
}

func (s *Server) handleQUICPacketIOUring(uc uringUDPSender, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
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

func (s *Server) handleQUICLongPacketIOUring(uc uringUDPSender, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
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
		if len(data) < quicMinInitialDatagram && (qc == nil || !qc.addressValidated.Load()) {
			if pbuf != nil {
				quicRecvBufPool.Put(pbuf)
			}
			return
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

func (s *Server) handleQUICShortPacketIOUring(uc uringUDPSender, remoteAddr *net.UDPAddr, data []byte, pbuf *[]byte, connMap *quicConnMap) {
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

func newQUICConnIOUring(server *Server, uc uringUDPSender, remoteAddr *net.UDPAddr, dcid, scid []byte) *QUICConn {
	qc := newQUICConn(server, nil, remoteAddr, dcid, scid)
	qc.udpAddr = remoteAddr
	qc.uringUDP = uc
	return qc
}

func (s *Server) createQUICConnIOUring(uc uringUDPSender, remoteAddr *net.UDPAddr, dcid, scid []byte, connMap *quicConnMap) *QUICConn {
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
	quicHandshakingConns.Add(1)
	qc.handshakeCounted.Store(true)
	Stats.TotalConns.Add(1)
	if debugFlag.Load() {
		log.Printf("[QUIC] new io_uring connection from %s dcid=%x scid=%x tlsState=%v keys=%v",
			remoteAddr, dcid, qc.srcCID(), qc.tlsState != nil, qc.keys[quicSpaceInitial] != nil)
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
