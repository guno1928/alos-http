//go:build linux

package core

const sweepIntervalNano = int64(250 * 1e6)

func (l *eventLoop) maybeSweep(now int64) {
	if l.liveConns == 0 && l.liveInconns == 0 {
		return
	}
	if now-l.lastSweep < sweepIntervalNano {
		return
	}
	l.lastSweep = now
	l.sweep(now)
}

func (l *eventLoop) sweep(now int64) {
	for _, ic := range l.inconns {
		if ic == nil || ic.closed {
			continue
		}
		if now > ic.deadline {
			l.closeInbound(ic)
		}
	}
	for _, c := range l.conns {
		if c == nil || c.state == connClosed {
			continue
		}
		if c.inIdle {
			if now > c.idleDeadline {
				l.closeConn(c, nil)
			}
			continue
		}
		if c.h2 != nil {
			l.sweepH2(c, now)
			continue
		}
		if c.cur != nil && now > c.cur.deadline {
			l.closeConn(c, fpErrTimeout)
		}
	}
}

func (l *eventLoop) sweepH2(c *backendConn, now int64) {
	for id, st := range c.h2.streams {
		if !st.ended && now > st.ex.deadline {
			st.ended = true
			delete(c.h2.streams, id)
			c.send(h2Frame(h2FrameRSTStream, 0, id, []byte{0, 0, 0, 8}))
			l.flushWrites(c)
			l.finish(st.ex, fpErrTimeout)
		}
	}
}

func (l *eventLoop) nextTimeoutMs() int {
	if l.liveConns == 0 {
		return maxEpollWaitMs
	}
	return int(sweepIntervalNano / 1e6)
}
