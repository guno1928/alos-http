//go:build linux && amd64

package core

import (
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guno1928/turbo"
)

type tlsBridgeWriteReq struct {
	data        []byte
	resp        chan error
	releaseBuf  *[]byte
	releasePool uint8
}

type tlsWorkerSharedBridge struct {
	worker        *tlsUringWorker
	conn          *tlsWorkerConn
	localAddr     net.Addr
	remoteAddr    net.Addr
	readDLN       atomic.Int64
	writeDLN      atomic.Int64
	notifyPending atomic.Bool
	closed        atomic.Bool
	done          chan struct{}
	readReady     chan struct{}

	mu             sync.Mutex
	inbound        []byte
	inboundBuf     []byte
	writeQueue     []*tlsBridgeWriteReq
	writeActive    *tlsBridgeWriteReq
	closeWait      []chan error
	closeRequested bool
	readTimer      *time.Timer
	writeTimer     *time.Timer
}

type tlsWorkerSharedConn struct {
	bridge *tlsWorkerSharedBridge
}

func newTLSWorkerSharedConn(worker *tlsUringWorker, conn *tlsWorkerConn, prefix []byte) *tlsWorkerSharedConn {
	localAddr, remoteAddr := socketAddrs(conn.fd)
	base := make([]byte, 0, len(prefix)+4096)
	bridge := &tlsWorkerSharedBridge{
		worker:     worker,
		conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		done:       make(chan struct{}),
		readReady:  make(chan struct{}, 1),
		inbound:    append(base, prefix...),
		inboundBuf: base,
		writeQueue: make([]*tlsBridgeWriteReq, 0, 8),
		closeWait:  make([]chan error, 0, 1),
	}
	conn.bridge = bridge
	worker.activeBridgeCount++
	return &tlsWorkerSharedConn{bridge: bridge}
}

var tlsBridgeReqPool = sync.Pool{
	New: func() any { return &tlsBridgeWriteReq{resp: make(chan error, 1)} },
}

func releaseTLSBridgeReq(req *tlsBridgeWriteReq) {
	req.data = nil
	req.releaseBuf = nil
	req.releasePool = writeOwnedReleaseNone
	tlsBridgeReqPool.Put(req)
}

func releaseTLSBridgeWriteReq(req *tlsBridgeWriteReq) {
	if req == nil || req.releaseBuf == nil {
		return
	}
	switch req.releasePool {
	case writeOwnedReleaseSmallBuf:
		*req.releaseBuf = req.data[:0]
		SmallBufPool.Put(req.releaseBuf)
	case writeOwnedReleaseMediumBuf:
		*req.releaseBuf = req.data[:0]
		MediumBufPool.Put(req.releaseBuf)
	case writeOwnedReleaseLargeBuf:
		*req.releaseBuf = req.data[:0]
		LargeBufPool.Put(req.releaseBuf)
	}
	req.releaseBuf = nil
	req.releasePool = writeOwnedReleaseNone
}

func (c *tlsWorkerSharedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	bridge := c.bridge
	for {
		bridge.mu.Lock()
		if len(bridge.inbound) > 0 {
			n := copy(p, bridge.inbound)
			bridge.inbound = bridge.inbound[n:]
			if len(bridge.inbound) == 0 {
				bridge.inbound = bridge.inboundBuf
			}
			bridge.mu.Unlock()
			return n, nil
		}
		closed := bridge.closed.Load()
		bridge.mu.Unlock()
		if closed {
			return 0, io.EOF
		}
		timerCh := armCachedTimer(&bridge.readTimer, bridge.readDLN.Load())
		select {
		case <-bridge.readReady:
			if timerCh != nil {
				stopDeadlineTimer(bridge.readTimer)
			}
		case <-bridge.done:
			if timerCh != nil {
				stopDeadlineTimer(bridge.readTimer)
			}
			return 0, io.EOF
		case <-timerCh:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *tlsWorkerSharedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return c.WriteOwned(append([]byte(nil), p...), nil, writeOwnedReleaseNone)
}

func (c *tlsWorkerSharedConn) WriteOwned(p []byte, releaseBuf *[]byte, releasePool uint8) (int, error) {
	if len(p) == 0 {
		releaseTLSBridgeWriteReq(&tlsBridgeWriteReq{data: p, releaseBuf: releaseBuf, releasePool: releasePool})
		return 0, nil
	}
	bridge := c.bridge
	if bridge.closed.Load() {
		releaseTLSBridgeWriteReq(&tlsBridgeWriteReq{data: p, releaseBuf: releaseBuf, releasePool: releasePool})
		return 0, net.ErrClosed
	}
	req := tlsBridgeReqPool.Get().(*tlsBridgeWriteReq)
	req.data = p
	req.releaseBuf = releaseBuf
	req.releasePool = releasePool
	bridge.mu.Lock()
	if bridge.closed.Load() {
		bridge.mu.Unlock()
		releaseTLSBridgeWriteReq(req)
		return 0, net.ErrClosed
	}
	bridge.writeQueue = append(bridge.writeQueue, req)
	bridge.mu.Unlock()
	bridge.notify()

	timerCh := armCachedTimer(&bridge.writeTimer, bridge.writeDLN.Load())
	select {
	case err := <-req.resp:
		if timerCh != nil {
			stopDeadlineTimer(bridge.writeTimer)
		}
		releaseTLSBridgeReq(req)
		if err != nil {
			return 0, err
		}
		return len(p), nil
	case <-bridge.done:
		if timerCh != nil {
			stopDeadlineTimer(bridge.writeTimer)
		}
		return 0, net.ErrClosed
	case <-timerCh:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *tlsWorkerSharedConn) Close() error {
	bridge := c.bridge
	if bridge.closed.Load() {
		return nil
	}
	wait := make(chan error, 1)
	bridge.mu.Lock()
	if bridge.closed.Load() {
		bridge.mu.Unlock()
		return nil
	}
	bridge.closeRequested = true
	bridge.closeWait = append(bridge.closeWait, wait)
	bridge.mu.Unlock()
	bridge.notify()
	select {
	case err := <-wait:
		return err
	case <-bridge.done:
		return nil
	}
}

func (c *tlsWorkerSharedConn) LocalAddr() net.Addr {
	return c.bridge.localAddr
}

func (c *tlsWorkerSharedConn) RemoteAddr() net.Addr {
	return c.bridge.remoteAddr
}

func (c *tlsWorkerSharedConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *tlsWorkerSharedConn) SetReadDeadline(t time.Time) error {
	c.bridge.readDLN.Store(deadlineUnixNano(t))
	c.bridge.signalReadReady()
	return nil
}

func (c *tlsWorkerSharedConn) SetWriteDeadline(t time.Time) error {
	c.bridge.writeDLN.Store(deadlineUnixNano(t))
	c.bridge.notify()
	return nil
}

func (bridge *tlsWorkerSharedBridge) notify() {
	if bridge == nil || bridge.closed.Load() {
		return
	}
	if !bridge.notifyPending.CompareAndSwap(false, true) {
		bridge.worker.signalWake()
		return
	}
	select {
	case bridge.worker.bridgeRequests <- bridge.conn.index:
	default:
		bridge.worker.pendingMissed.Add(1)
	}
	bridge.worker.signalWake()
}

func (bridge *tlsWorkerSharedBridge) signalReadReady() {
	select {
	case bridge.readReady <- struct{}{}:
	default:
	}
}

func (bridge *tlsWorkerSharedBridge) shutdown() {
	if bridge == nil || !bridge.closed.CompareAndSwap(false, true) {
		return
	}
	bridge.mu.Lock()
	active := bridge.writeActive
	queued := bridge.writeQueue
	waiters := bridge.closeWait
	bridge.writeActive = nil
	bridge.writeQueue = nil
	bridge.closeWait = nil
	bridge.inbound = nil
	bridge.mu.Unlock()
	releaseTLSBridgeWriteReq(active)
	if active != nil && active.resp != nil {
		active.resp <- net.ErrClosed
	}
	for i := range queued {
		releaseTLSBridgeWriteReq(queued[i])
		if queued[i].resp != nil {
			queued[i].resp <- net.ErrClosed
		}
	}
	for _, waiter := range waiters {
		waiter <- nil
	}
	close(bridge.done)
	bridge.signalReadReady()
}

func armCachedTimer(tp **time.Timer, deadlineUnix int64) <-chan time.Time {
	if deadlineUnix == 0 {
		return nil
	}
	wait := time.Duration(deadlineUnix - turbo.UnixNano())
	if wait < 0 {
		wait = 0
	}
	if *tp == nil {
		*tp = time.NewTimer(wait)
	} else {
		(*tp).Reset(wait)
	}
	return (*tp).C
}

func deadlineTimer(deadlineUnix int64) (*time.Timer, <-chan time.Time) {
	if deadlineUnix == 0 {
		return nil, nil
	}
	deadline := deadlineFromUnixNano(deadlineUnix)
	wait := time.Until(deadline)
	if wait <= 0 {
		timer := time.NewTimer(0)
		return timer, timer.C
	}
	timer := time.NewTimer(wait)
	return timer, timer.C
}

func stopDeadlineTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
