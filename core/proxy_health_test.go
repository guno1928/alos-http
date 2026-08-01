package core

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// The health-transition tests below each take a second or more, which is
// deliberate and cannot be shortened from here: healthChecker.loop clamps any
// configured Interval below one second up to one second, so a probe cycle is a
// second at minimum. That floor is a guard against hammering backends and was
// kept on purpose. Everything else in this file polls on a short interval.

// freeAddr returns an address nothing is listening on, so connections to it are
// refused rather than hanging.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// statusOrigin answers every request with the given status line.
func statusOrigin(t *testing.T, status string) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				io.WriteString(c, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestProbeBackendTCPDetectsReachability(t *testing.T) {
	up := statusOrigin(t, "200 OK")
	cfg := HealthCheckConfig{Timeout: 2 * time.Second}

	if !probeBackendHealth(up, false, false, cfg) {
		t.Error("a listening backend was reported unhealthy")
	}
	if probeBackendHealth(freeAddr(t), false, false, cfg) {
		t.Error("a backend refusing connections was reported healthy")
	}
}

// With a Path set the probe issues a real request and judges the status code.
func TestProbeBackendHTTPJudgesStatusCode(t *testing.T) {
	cfg := HealthCheckConfig{Path: "/healthz", Timeout: 2 * time.Second}

	cases := []struct {
		status string
		want   bool
		why    string
	}{
		{"200 OK", true, "2xx is healthy"},
		{"301 Moved Permanently", true, "3xx is healthy"},
		// 4xx counts as healthy on purpose: it proves the backend is serving,
		// even if the health path itself is not routed.
		{"404 Not Found", true, "4xx means the backend answered"},
		{"499 Client Closed", true, "the upper bound is exclusive at 500"},
		{"500 Internal Server Error", false, "5xx is unhealthy"},
		{"503 Service Unavailable", false, "5xx is unhealthy"},
	}
	for _, tc := range cases {
		addr := statusOrigin(t, tc.status)
		got := probeBackendHealth(addr, false, false, cfg)
		if got != tc.want {
			t.Errorf("status %q reported healthy=%v, want %v (%s)", tc.status, got, tc.want, tc.why)
		}
	}
}

func TestProbeBackendHTTPUnreachableIsUnhealthy(t *testing.T) {
	cfg := HealthCheckConfig{Path: "/healthz", Timeout: 2 * time.Second}
	if probeBackendHealth(freeAddr(t), false, false, cfg) {
		t.Error("an unreachable backend was reported healthy by the HTTP probe")
	}
}

// The checker must eject a backend that stops answering.
func TestHealthCheckerEjectsDeadBackend(t *testing.T) {
	dead := &backend{Addr: freeAddr(t)}
	dead.Healthy.Store(true)
	live := &backend{Addr: statusOrigin(t, "200 OK")}
	live.Healthy.Store(true)

	hc := newHealthChecker([]*backend{dead, live}, HealthCheckConfig{
		Interval:         time.Second,
		Timeout:          500 * time.Millisecond,
		FailThreshold:    1,
		SuccessThreshold: 1,
	}, nil)
	hc.start()
	defer hc.stop()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if !dead.Healthy.Load() {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if dead.Healthy.Load() {
		t.Fatal("a backend refusing connections was never marked unhealthy")
	}
	if !live.Healthy.Load() {
		t.Fatal("a responsive backend was wrongly marked unhealthy")
	}
}

// A backend must not be ejected until FailThreshold consecutive probes fail.
func TestHealthCheckerHonoursFailThreshold(t *testing.T) {
	dead := &backend{Addr: freeAddr(t)}
	dead.Healthy.Store(true)

	hc := newHealthChecker([]*backend{dead}, HealthCheckConfig{
		Interval:         time.Second,
		Timeout:          300 * time.Millisecond,
		FailThreshold:    3,
		SuccessThreshold: 1,
	}, nil)
	hc.start()
	defer hc.stop()

	// One tick in it must still be considered healthy.
	time.Sleep(1500 * time.Millisecond)
	if !dead.Healthy.Load() {
		t.Fatal("backend ejected after a single failure despite FailThreshold=3")
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if !dead.Healthy.Load() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("backend was never ejected after repeated failures")
}

// A backend that comes back must be returned to service.
func TestHealthCheckerRestoresRecoveredBackend(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // start out refusing connections

	b := &backend{Addr: addr}
	b.Healthy.Store(true)

	hc := newHealthChecker([]*backend{b}, HealthCheckConfig{
		Interval:         time.Second,
		Timeout:          300 * time.Millisecond,
		FailThreshold:    1,
		SuccessThreshold: 1,
	}, nil)
	hc.start()
	defer hc.stop()

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) && b.Healthy.Load() {
		time.Sleep(15 * time.Millisecond)
	}
	if b.Healthy.Load() {
		t.Fatal("backend was never ejected, so recovery cannot be observed")
	}

	// Bring the same port back up.
	revived, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Skipf("could not rebind %s to simulate recovery: %v", addr, err)
	}
	defer revived.Close()
	go func() {
		for {
			c, aerr := revived.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if b.Healthy.Load() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatal("a recovered backend was never returned to service")
}

// stop() must terminate the checker goroutine, and be safe to call twice.
func TestHealthCheckerStopIsCleanAndIdempotent(t *testing.T) {
	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	before := runtime.NumGoroutine()

	for i := 0; i < 20; i++ {
		b := &backend{Addr: fmt.Sprintf("127.0.0.1:%d", 9000+i)}
		b.Healthy.Store(true)
		hc := newHealthChecker([]*backend{b}, HealthCheckConfig{
			Interval:         time.Second,
			Timeout:          100 * time.Millisecond,
			FailThreshold:    1,
			SuccessThreshold: 1,
		}, nil)
		hc.start()
		hc.stop()
		hc.stop() // must not panic on a double close
	}

	runtime.GC()
	time.Sleep(150 * time.Millisecond)
	if after := runtime.NumGoroutine(); after-before > 5 {
		t.Fatalf("20 start/stop cycles leaked goroutines (%d -> %d)", before, after)
	}
}

// Closing the parent channel must also shut the checker down, so a server
// shutdown does not leave probes running.
func TestHealthCheckerStopsWithParent(t *testing.T) {
	parent := make(chan struct{})
	b := &backend{Addr: freeAddr(t)}
	b.Healthy.Store(true)

	hc := newHealthChecker([]*backend{b}, HealthCheckConfig{
		Interval:         time.Second,
		Timeout:          100 * time.Millisecond,
		FailThreshold:    1,
		SuccessThreshold: 1,
	}, parent)
	hc.start()

	close(parent)
	done := make(chan struct{})
	go func() {
		hc.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("checker did not exit when its parent stop channel closed")
	}
}
