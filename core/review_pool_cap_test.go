package core

import (
	"sync"
	"testing"
)

const poolCapRetries = 16

func TestPutBoxedBufCappedDropsOversizedBuffers(t *testing.T) {
	pool := sync.Pool{New: func() any { b := make([]byte, 0, 16); return &b }}
	for i := 0; i < poolCapRetries; i++ {
		big := make([]byte, 0, 4096)
		putBoxedBufCapped(&pool, &big, 1024)
		if got := pool.Get().(*[]byte); cap(*got) > 1024 {
			t.Fatalf("oversized buffer (cap %d) was retained by the pool", cap(*got))
		}
	}
	small := make([]byte, 100, 512)
	putBoxedBufCapped(&pool, &small, 1024)
	if len(small) != 0 {
		t.Fatalf("in-range buffer not reset before pooling: len=%d", len(small))
	}
	for i := 0; i < poolCapRetries; i++ {
		if got := pool.Get().(*[]byte); cap(*got) == 512 {
			return
		}
		putBoxedBufCapped(&pool, &small, 1024)
	}
	t.Fatal("in-range buffer never came back from the pool")
}
