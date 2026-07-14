//go:build linux && amd64

package core

import (
	"runtime"
	"testing"
)

func retainedHeap() uint64 {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func setupMidSend(n int, release bool) float64 {
	shared := make([]byte, 130<<10)
	base := retainedHeap()
	w := &plainUringWorker{connections: make([]plainWorkerConn, n), recvBufs: &ioUringBufferRing{}}
	w.initConnections()
	for i := range w.connections {
		c := &w.connections[i]
		c.readBuf = acquirePooledBuf(&connReadBufPool)
		c.readBuf = append(c.readBuf, make([]byte, 8192)...)
		c.readN = 0
		c.writeBuf = acquirePooledBuf(&connWriteBufPool)
		c.writeBuf = append(c.writeBuf, make([]byte, 124)...)
		c.writeN = len(c.writeBuf)
		c.writeSent = c.writeN
		c.bodyBuf = shared
		c.writingBody = true
		c.bodySent = 4096
		if release {
			w.releaseIdleWriteBuf(c)
			w.releaseIdleReadBuf(c)
		}
	}
	after := retainedHeap()
	runtime.KeepAlive(w)
	return float64(after-base) / float64(n)
}

func TestMidSendRetention(t *testing.T) {
	const N = 50000
	held := setupMidSend(N, false)
	released := setupMidSend(N, true)
	t.Logf("mid-send WITHOUT release = %.0f B/conn  (=> %.2f GB @138k conns)", held, held*138000/1e9)
	t.Logf("mid-send WITH release    = %.0f B/conn  (=> %.2f GB @138k conns)", released, released*138000/1e9)
	if held < 20000 {
		t.Fatalf("expected ~24KB/conn held before release, got %.0f", held)
	}
	if released > held/3 {
		t.Fatalf("release did not cut mid-send memory enough: held=%.0f released=%.0f", held, released)
	}
}
