package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type pooledConn struct {
	conn         net.Conn
	br           *bufio.Reader
	created      time.Time
	idleDeadline time.Time
}

type connPool struct {
	addr          string
	useTLS        bool
	tlsSkipVerify bool
	maxIdle       int
	idleTimeout   time.Duration
	dialTimeout   time.Duration
	ch            chan *pooledConn
	closed        atomic.Bool
	closeOnce     sync.Once
	stopCh        chan struct{}
}

var brPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, 4096) },
}

type pooledConnDrainReader struct{}

func (pooledConnDrainReader) Read(_ []byte) (int, error) { return 0, io.EOF }

var pooledConnReaderSink pooledConnDrainReader

func newConnPool(addr string, useTLS, tlsSkipVerify bool, maxIdle int, idleTimeout, dialTimeout time.Duration) *connPool {
	if maxIdle <= 0 {
		maxIdle = 32
	}
	cp := &connPool{
		addr:          addr,
		useTLS:        useTLS,
		tlsSkipVerify: tlsSkipVerify,
		maxIdle:       maxIdle,
		idleTimeout:   idleTimeout,
		dialTimeout:   dialTimeout,
		ch:            make(chan *pooledConn, maxIdle),
		stopCh:        make(chan struct{}),
	}
	go cp.evictLoop()
	return cp
}

func (cp *connPool) get() (*pooledConn, error) {
	for {
		select {
		case pc := <-cp.ch:
			now := time.Now()
			if now.After(pc.idleDeadline) {
				cp.discard(pc)
				continue
			}
			if cp.useTLS && now.Sub(pc.created) > cp.idleTimeout*2 {
				cp.discard(pc)
				continue
			}
			return pc, nil
		default:
			return cp.dial()
		}
	}
}

func (cp *connPool) put(pc *pooledConn) {
	if cp.closed.Load() {
		cp.discard(pc)
		return
	}
	_ = pc.conn.SetDeadline(time.Time{})
	pc.idleDeadline = time.Now().Add(cp.idleTimeout)
	select {
	case cp.ch <- pc:
	case <-cp.stopCh:
		cp.discard(pc)
	default:
		cp.discard(pc)
	}
}

func (cp *connPool) dial() (*pooledConn, error) {
	conn, err := dialBackendConn(cp.addr, cp.useTLS, cp.tlsSkipVerify, cp.dialTimeout)
	if err != nil {
		return nil, err
	}
	enableProxyFuse(conn)
	br := brPool.Get().(*bufio.Reader)
	br.Reset(conn)
	now := time.Now()
	return &pooledConn{conn: conn, br: br, created: now, idleDeadline: now.Add(cp.idleTimeout)}, nil
}

func (cp *connPool) discard(pc *pooledConn) {
	if pc == nil {
		return
	}
	if pc.conn != nil {
		pc.conn.Close()
		pc.conn = nil
	}
	if pc.br != nil {
		pc.br.Reset(pooledConnReaderSink)
		brPool.Put(pc.br)
		pc.br = nil
	}
}

func (cp *connPool) close() {
	cp.closeOnce.Do(func() {
		cp.closed.Store(true)
		close(cp.stopCh)
		for {
			select {
			case pc := <-cp.ch:
				cp.discard(pc)
			default:
				return
			}
		}
	})
}

func (cp *connPool) evictLoop() {
	evictInterval := cp.idleTimeout / 2
	if evictInterval <= 0 {
		evictInterval = 30 * time.Second
	}
	ticker := time.NewTicker(evictInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cp.evictStale()
		case <-cp.stopCh:
			return
		}
	}
}

func (cp *connPool) evictStale() {
	defer func() {
		if r := recover(); r != nil {
			Dbg("[proxy-pool evict] recovered panic: %v", r)
		}
	}()
	n := len(cp.ch)
	now := time.Now()
	for i := 0; i < n; i++ {
		select {
		case pc := <-cp.ch:
			if now.After(pc.idleDeadline) {
				cp.discard(pc)
			} else {
				select {
				case cp.ch <- pc:
				default:
					cp.discard(pc)
				}
			}
		default:
			return
		}
	}
}

func dialBackendConn(addr string, useTLS, tlsSkipVerify bool, timeout time.Duration) (net.Conn, error) {
	conn, err := DialTCP4(addr, timeout)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return conn, nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: tlsSkipVerify,
	}
	conn.SetDeadline(time.Now().Add(timeout))
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return tlsConn, nil
}
