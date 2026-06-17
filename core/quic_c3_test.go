package core

import (
	"testing"
)

// TestQUICConnCapDropsAtLimit verifies the connection cardinality cap: once the
// server is tracking quicMaxLiveConns live QUIC connections, a new reservation
// (the gate the Initial-handling path checks before allocating a conn or
// spawning goroutines) is denied, and the live-conn gauge does not drift.
func TestQUICConnCapDropsAtLimit(t *testing.T) {
	s := &Server{}

	if got := s.quicConnCap(); got != quicMaxLiveConns {
		t.Fatalf("quicConnCap() = %d, want %d", got, quicMaxLiveConns)
	}

	// Fill to one below the cap; every reservation must succeed.
	for i := int64(0); i < s.quicConnCap()-1; i++ {
		if !s.reserveQUICConn() {
			t.Fatalf("reserveQUICConn denied at i=%d below cap", i)
		}
	}

	// The reservation that brings us to exactly the cap must still succeed.
	if !s.reserveQUICConn() {
		t.Fatal("reserveQUICConn denied at the cap boundary")
	}
	if got := s.quicLiveConns.Load(); got != s.quicConnCap() {
		t.Fatalf("quicLiveConns = %d, want %d", got, s.quicConnCap())
	}

	// At the cap, the next Initial is dropped: reservation fails closed and the
	// gauge stays pinned at the cap (no drift from the rejected increment).
	if s.reserveQUICConn() {
		t.Fatal("reserveQUICConn succeeded past the cap")
	}
	if got := s.quicLiveConns.Load(); got != s.quicConnCap() {
		t.Fatalf("after denied reservation quicLiveConns = %d, want %d (gauge drifted)", got, s.quicConnCap())
	}

	// Releasing one slot must let exactly one more reservation through.
	s.releaseQUICConn()
	if got := s.quicLiveConns.Load(); got != s.quicConnCap()-1 {
		t.Fatalf("after release quicLiveConns = %d, want %d", got, s.quicConnCap()-1)
	}
	if !s.reserveQUICConn() {
		t.Fatal("reserveQUICConn denied after a slot was released")
	}
}

// TestQUICPathValidatedFlips verifies pathValidated starts false and flips to
// true once (idempotently), and that the effective idle timeout transitions
// from the short unvalidated timeout to the full timeout on validation.
func TestQUICPathValidatedFlips(t *testing.T) {
	qc := &QUICConn{idleTimeout: quicDefaultIdleTimeout}

	if qc.pathValidated.Load() {
		t.Fatal("pathValidated should start false")
	}
	if got := qc.effectiveIdleTimeout(); got != quicUnvalidatedIdleTimeout {
		t.Fatalf("unvalidated effectiveIdleTimeout = %v, want %v", got, quicUnvalidatedIdleTimeout)
	}

	qc.markPathValidated()

	if !qc.pathValidated.Load() {
		t.Fatal("pathValidated should be true after markPathValidated")
	}
	if got := qc.effectiveIdleTimeout(); got != quicDefaultIdleTimeout {
		t.Fatalf("validated effectiveIdleTimeout = %v, want %v", got, quicDefaultIdleTimeout)
	}

	// Idempotent: a second call must not regress state.
	qc.markPathValidated()
	if !qc.pathValidated.Load() {
		t.Fatal("pathValidated regressed after second markPathValidated")
	}
}

// TestQUICEffectiveIdleTimeoutClampsToConfigured ensures a configured idle
// timeout shorter than the unvalidated timeout is not lengthened (we never
// reap slower than the configured value).
func TestQUICEffectiveIdleTimeoutClampsToConfigured(t *testing.T) {
	short := quicUnvalidatedIdleTimeout / 2
	qc := &QUICConn{idleTimeout: short}

	if got := qc.effectiveIdleTimeout(); got != short {
		t.Fatalf("effectiveIdleTimeout = %v, want configured %v", got, short)
	}
}

// TestQUICAmplificationBudgetExceeded verifies the RFC 9000 §8 3x check: on an
// unvalidated path, sending more than 3x received bytes is over budget; once
// the path is validated the budget no longer applies.
func TestQUICAmplificationBudgetExceeded(t *testing.T) {
	qc := &QUICConn{}
	qc.bytesReceived.Store(1200)

	// 3x1200 = 3600 budget. Already sent 3500, +100 = 3600 is exactly at the
	// budget (not over); +101 exceeds it.
	qc.bytesSent.Store(3500)

	if qc.amplificationBudgetExceeded(100) {
		t.Fatal("sending up to exactly 3x received must not exceed budget")
	}
	if !qc.amplificationBudgetExceeded(101) {
		t.Fatal("sending past 3x received on an unvalidated path must exceed budget")
	}

	// With nothing received yet, any non-trivial send exceeds the (zero) budget.
	fresh := &QUICConn{}
	if !fresh.amplificationBudgetExceeded(1) {
		t.Fatal("sending with zero bytes received on an unvalidated path must exceed budget")
	}

	// Once the path is validated, the budget no longer constrains sends.
	qc.markPathValidated()
	if qc.amplificationBudgetExceeded(1 << 20) {
		t.Fatal("validated path must never report budget exceeded")
	}
}

// TestQUICUnvalidatedIdleTimeoutOrdering documents the invariant the reaping
// logic relies on: the unvalidated timeout is strictly shorter than the full
// idle timeout, so a spoofed-Initial flood is reaped sooner.
func TestQUICUnvalidatedIdleTimeoutOrdering(t *testing.T) {
	if !(quicUnvalidatedIdleTimeout < quicDefaultIdleTimeout) {
		t.Fatalf("quicUnvalidatedIdleTimeout (%v) must be < quicDefaultIdleTimeout (%v)",
			quicUnvalidatedIdleTimeout, quicDefaultIdleTimeout)
	}
	if quicUnvalidatedIdleTimeout <= 0 {
		t.Fatalf("quicUnvalidatedIdleTimeout must be positive, got %v", quicUnvalidatedIdleTimeout)
	}
}
