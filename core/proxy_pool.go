package core

import (
	"bufio"
	"crypto/tls"
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
				pc.conn.Close()
				continue
			}
			if cp.useTLS && now.Sub(pc.created) > cp.idleTimeout*2 {
				pc.conn.Close()
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
		pc.conn.Close()
		return
	}
	pc.idleDeadline = time.Now().Add(cp.idleTimeout)
	select {
	case cp.ch <- pc:
	default:
		pc.conn.Close()
	}
}

func (cp *connPool) dial() (*pooledConn, error) {
	conn, err := DialTCP4(cp.addr, cp.dialTimeout)
	if err != nil {
		return nil, err
	}
	if cp.useTLS {
		host, _, _ := net.SplitHostPort(cp.addr)
		tlsCfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: cp.tlsSkipVerify,
		}
		conn.SetDeadline(time.Now().Add(cp.dialTimeout))
		tlsConn := tls.Client(conn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, err
		}
		conn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	br := brPool.Get().(*bufio.Reader)
	br.Reset(conn)
	now := time.Now()
	return &pooledConn{conn: conn, br: br, created: now, idleDeadline: now.Add(cp.idleTimeout)}, nil
}

func (cp *connPool) close() {
	cp.closeOnce.Do(func() {
		cp.closed.Store(true)
		close(cp.stopCh)
		close(cp.ch)
		for pc := range cp.ch {
			pc.conn.Close()
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
	n := len(cp.ch)
	now := time.Now()
	for i := 0; i < n; i++ {
		select {
		case pc := <-cp.ch:
			if now.After(pc.idleDeadline) {
				pc.conn.Close()
			} else {
				select {
				case cp.ch <- pc:
				default:
					pc.conn.Close()
				}
			}
		default:
			return
		}
	}
}
