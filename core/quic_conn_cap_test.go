package core

import "testing"

// TestAdmitQUICConnCap verifies the per-server QUIC connection cardinality cap:
// admits succeed up to maxQUICConns, the next is refused, and release frees a
// slot so admission resumes.
func TestAdmitQUICConnCap(t *testing.T) {
	s := &Server{}
	s.quicConns.Store(maxQUICConns - 1)

	if !s.admitQUICConn() {
		t.Fatal("admit at cap-1 should succeed")
	}
	if s.quicConns.Load() != maxQUICConns {
		t.Fatalf("count = %d, want %d", s.quicConns.Load(), maxQUICConns)
	}
	if s.admitQUICConn() {
		t.Fatal("admit over cap should be refused")
	}
	// A refused admit must not leak a slot.
	if s.quicConns.Load() != maxQUICConns {
		t.Fatalf("refused admit changed count to %d", s.quicConns.Load())
	}
	s.releaseQUICConn()
	if !s.admitQUICConn() {
		t.Fatal("admit after release should succeed")
	}
}

func BenchmarkAdmitReleaseQUICConn(b *testing.B) {
	s := &Server{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if s.admitQUICConn() {
			s.releaseQUICConn()
		}
	}
}
