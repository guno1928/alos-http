package core

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

type healthChecker struct {
	backends []*backend
	config   HealthCheckConfig
	stopCh   chan struct{}
	parentCh <-chan struct{}
	stopped  atomic.Bool
	wg       sync.WaitGroup
}

func newHealthChecker(backends []*backend, cfg HealthCheckConfig, parentStop <-chan struct{}) *healthChecker {
	return &healthChecker{
		backends: backends,
		config:   cfg,
		stopCh:   make(chan struct{}),
		parentCh: parentStop,
	}
}

func (hc *healthChecker) start() {
	hc.wg.Add(1)
	go hc.loop()
}

func (hc *healthChecker) stop() {
	if hc.stopped.CompareAndSwap(false, true) {
		close(hc.stopCh)
	}
	hc.wg.Wait()
}

func (hc *healthChecker) loop() {
	defer hc.wg.Done()

	interval := hc.config.Interval
	if interval < 1*time.Second {
		interval = 1 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	type state struct {
		failCount    int
		successCount int
	}
	states := make([]state, len(hc.backends))

	for {
		select {
		case <-ticker.C:
			for i, b := range hc.backends {
				ok := hc.check(b)
				if ok {
					states[i].failCount = 0
					states[i].successCount++
					if !b.Healthy.Load() && states[i].successCount >= hc.config.SuccessThreshold {
						b.Healthy.Store(true)
						log.Printf("[HEALTH] %s is now HEALTHY", b.Addr)
					}
				} else {
					states[i].successCount = 0
					states[i].failCount++
					if b.Healthy.Load() && states[i].failCount >= hc.config.FailThreshold {
						b.Healthy.Store(false)
						log.Printf("[HEALTH] %s is now UNHEALTHY", b.Addr)
					}
				}
			}
		case <-hc.stopCh:
			return
		case <-hc.parentCh:
			return
		}
	}
}

func (hc *healthChecker) check(b *backend) bool {
	if hc.config.Path == "" {
		return hc.checkTCP(b)
	}
	return hc.checkHTTP(b)
}

func (hc *healthChecker) checkTCP(b *backend) bool {
	conn, err := DialTCP4(b.Addr, hc.config.Timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (hc *healthChecker) checkHTTP(b *backend) bool {
	conn, err := DialTCP4(b.Addr, hc.config.Timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(hc.config.Timeout))

	bp := SmallBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	buf = append(buf, "GET "...)
	buf = append(buf, hc.config.Path...)
	buf = append(buf, " HTTP/1.1\r\nHost: "...)
	buf = append(buf, b.Addr...)
	buf = append(buf, "\r\nConnection: close\r\n\r\n"...)

	err = writeFull(conn, buf)
	*bp = buf[:0]
	SmallBufPool.Put(bp)
	if err != nil {
		return false
	}

	var resp [128]byte
	n, err := conn.Read(resp[:])
	if err != nil || n < 12 {
		return false
	}

	code := 0
	for i := 9; i < 12 && i < n; i++ {
		d := resp[i]
		if d < '0' || d > '9' {
			return false
		}
		code = code*10 + int(d-'0')
	}

	return code >= 200 && code < 500
}
