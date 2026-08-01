//go:build linux

package core

const sweepIntervalNano = int64(250 * 1e6)

func (l *eventLoop) maybeSweep(now int64) {
	if l.liveConns == 0 {
		return
	}
	if now-l.lastSweep < sweepIntervalNano {
		return
	}
	l.lastSweep = now
	l.sweepBackends(now)
}

func (l *eventLoop) nextTimeoutMs() int {
	if l.liveConns == 0 {
		return maxEpollWaitMs
	}
	return int(sweepIntervalNano / 1e6)
}
