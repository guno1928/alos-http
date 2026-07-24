//go:build linux

package core

import (
	"log"
	"time"
)

func startFPHealthChecker(backends []*fpBackend, cfg HealthCheckConfig, stop <-chan struct{}) {
	if len(backends) == 0 {
		return
	}
	interval := cfg.Interval
	if interval < time.Second {
		interval = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	failN := cfg.FailThreshold
	if failN <= 0 {
		failN = 3
	}
	succN := cfg.SuccessThreshold
	if succN <= 0 {
		succN = 1
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		fails := make([]int, len(backends))
		succs := make([]int, len(backends))
		for {
			select {
			case <-ticker.C:
				for i, be := range backends {
					if probeBackendHealth(be.authority, be.tls, be.skipVerify, cfg) {
						fails[i] = 0
						succs[i]++
						if !be.healthy.Load() && succs[i] >= succN {
							be.healthy.Store(true)
							log.Printf("[HEALTH] %s is now HEALTHY", be.authority)
						}
					} else {
						succs[i] = 0
						fails[i]++
						if be.healthy.Load() && fails[i] >= failN {
							be.healthy.Store(false)
							log.Printf("[HEALTH] %s is now UNHEALTHY", be.authority)
						}
					}
				}
			case <-stop:
				return
			}
		}
	}()
}
