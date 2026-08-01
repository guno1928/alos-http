//go:build linux && amd64

package core

import "testing"

func TestH1ConnectionsShareBodyBudget(t *testing.T) {
	srv := New(Config{MaxInFlightBodyBytes: 1024, MaxConnsPerIP: -1})
	w := &epollWorker{server: srv}
	a := &epollConn{worker: w}
	b := &epollConn{worker: w}
	if !a.reserveH1BodyBudget(srv, 768) {
		t.Fatal("first H1 body should reserve capacity")
	}
	if b.reserveH1BodyBudget(srv, 257) {
		t.Fatal("second H1 body exceeded the aggregate capacity")
	}
	a.releaseH1BodyBudget()
	if !b.reserveH1BodyBudget(srv, 1024) {
		t.Fatal("released H1 body capacity was not reusable")
	}
	b.releaseH1BodyBudget()
}

func TestChunkedReservationUsesSmallerReadCap(t *testing.T) {
	srv := New(Config{MaxBodySize: 100 << 20, MaxReadSize: 2 << 20, MaxConnsPerIP: -1})
	if got, want := h1ChunkedBodyReservation(srv), 2<<20; got != want {
		t.Fatalf("chunked reservation = %d, want read cap %d", got, want)
	}
}
