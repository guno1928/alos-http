//go:build linux && amd64

package core

import (
	"runtime"
	"testing"
	"unsafe"
)

func retainedHeapInuse() uint64 {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func TestStructSizes(t *testing.T) {
	t.Logf("sizeof(plainWorkerConn) = %d bytes", unsafe.Sizeof(plainWorkerConn{}))
	t.Logf("sizeof(Request)         = %d bytes", unsafe.Sizeof(Request{}))
	t.Logf("sizeof(Response)        = %d bytes", unsafe.Sizeof(Response{}))
	t.Logf("sizeof(tlsWorkerH2State) = %d bytes", unsafe.Sizeof(tlsWorkerH2State{}))
}

// TestSlotRetentionAfterRecycle simulates a connection flood: N slots each serve
// one request (read 8KB, write a ~40KB serialized response, grow resp.body),
// then every connection is recycled (closed). It measures how much heap remains
// pinned by the FREE slots afterwards — i.e. the memory a slowloris flood leaves
// stuck at the high-water mark.
func TestSlotRetentionAfterRecycle(t *testing.T) {
	const (
		N          = 50000
		readSize   = 8 << 10
		writeSize  = 40 << 10
		bodySize   = 8 << 10
	)

	base := retainedHeapInuse()

	worker := &plainUringWorker{
		connections: make([]plainWorkerConn, N),
		freeHead:    0,
	}
	worker.initConnections()

	afterAlloc := retainedHeapInuse()

	for i := range worker.connections {
		conn := &worker.connections[i]
		conn.readBuf = make([]byte, 0, readSize)
		conn.readBuf = append(conn.readBuf, make([]byte, readSize)...)
		conn.writeBuf = make([]byte, 0, 16384)
		conn.writeBuf = append(conn.writeBuf, make([]byte, writeSize)...)
		conn.resp.body = append(conn.resp.body[:0], make([]byte, bodySize)...)
		conn.req.Body = append(conn.req.Body[:0], make([]byte, 512)...)
		worker.recycleConnection(conn)
	}

	afterRecycle := retainedHeapInuse()
	runtime.KeepAlive(worker)

	slabBytes := afterAlloc - base
	retainedBytes := afterRecycle - base
	perSlotSlab := float64(slabBytes) / N
	perSlotRetained := float64(retainedBytes) / N

	t.Logf("N slots                     = %d", N)
	t.Logf("slab alloc (empty slots)    = %.1f MB  (%.0f B/slot)", float64(slabBytes)/1e6, perSlotSlab)
	t.Logf("retained after recycle-all  = %.1f MB  (%.0f B/slot)", float64(retainedBytes)/1e6, perSlotRetained)
	t.Logf("=> at 1,000,000 conns this floor projects to %.2f GB", perSlotRetained*1e6/1e9)
}
