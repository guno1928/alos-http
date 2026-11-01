//go:build linux && amd64

package core

import "testing"

func BenchmarkQUICServeRequestStream(b *testing.B) {
	qc := newQUICFixBenchConn(b)
	request := h3AppendHeadersFrame(nil, quicFixGET("/ok", [2]string{"user-agent", "bench"}, [2]string{"accept", "*/*"}))
	var id uint64
	serve := func() {
		s := getPooledStream(id, qc)
		s.refCount.Store(2)
		s.recvBuf = request
		s.recvFin = true
		s.maxSend = quicFixUnlimitedCredit
		s.dispatched.Store(true)
		qc.streamsMu.Lock()
		qc.streams[id] = s
		qc.streamsMu.Unlock()
		qc.activeReqStreams.Add(1)
		qc.serveRequestStream(s)
		id += 4
	}
	serve()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serve()
	}
}
