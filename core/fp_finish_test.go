//go:build linux

package core

import "testing"

// An exchange with no waiting caller must complete through the sink rather than
// closing a nil channel. The proxy builds exactly such exchanges, so getting
// this wrong panics inside the event loop and takes every connection with it.
func TestFinishWithoutWaiterDoesNotPanic(t *testing.T) {
	l := newLoopForTest()
	ex := l.exGet()
	if ex.done != nil {
		t.Fatal("a pooled exchange should not carry a done channel")
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("finish panicked for an exchange with no waiter: %v", r)
		}
	}()
	l.finish(ex, nil)
}

// A completed exchange must return to the freelist instead of being dropped.
func TestFinishRecyclesExchange(t *testing.T) {
	l := newLoopForTest()
	ex := l.exGet()
	l.finish(ex, nil)

	if l.exFree == nil {
		t.Fatal("the exchange should be back on the freelist")
	}
	if reused := l.exGet(); reused != ex {
		t.Fatal("exGet should hand back the recycled exchange")
	}
}

// finish must be idempotent: a connection error arriving after completion must
// not deliver the same exchange twice.
func TestFinishIsIdempotent(t *testing.T) {
	l := newLoopForTest()
	ex := l.exGet()
	l.finish(ex, nil)
	free := l.exFree

	l.finish(ex, fpErrConnClosed)
	if l.exFree != free {
		t.Fatal("a second finish re-queued the exchange, so it would be delivered twice")
	}
}
