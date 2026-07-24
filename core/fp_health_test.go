//go:build linux

package core

import (
	"net"
	"testing"
	"time"
)

func TestFPHealthCheckerEjectsDeadBackend(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()

	alive := &fpBackend{authority: ln.Addr().String()}
	alive.healthy.Store(true)
	dead := &fpBackend{authority: "127.0.0.1:1"}
	dead.healthy.Store(true)

	stop := make(chan struct{})
	defer close(stop)
	cfg := HealthCheckConfig{
		Enabled:       true,
		Interval:      time.Second,
		Timeout:       500 * time.Millisecond,
		FailThreshold: 2,
	}
	startFPHealthChecker([]*fpBackend{alive, dead}, cfg, stop)

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if !dead.healthy.Load() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if dead.healthy.Load() {
		t.Fatal("dead backend was not marked unhealthy by the health checker")
	}
	if !alive.healthy.Load() {
		t.Fatal("alive backend was wrongly marked unhealthy")
	}

	g := &backendGroup{lb: LBRoundRobin, backends: []*fpBackend{alive, dead}}
	for i := 0; i < 50; i++ {
		if g.pick("") == dead {
			t.Fatal("pick returned the unhealthy backend")
		}
	}
}
