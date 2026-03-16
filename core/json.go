package core

import (
	"sync"

	"github.com/bytedance/sonic"
)

type JSON struct {
	Buf []byte
}

var jsonPool = sync.Pool{
	New: func() any {
		return &JSON{}
	},
}

func AcquireJSON() *JSON {
	return jsonPool.Get().(*JSON)
}

func (j *JSON) Marshal(v any) []byte {
	j.Buf, _ = sonic.Marshal(v)
	return j.Buf
}

func (j *JSON) Release() {
	j.Buf = j.Buf[:0]
	jsonPool.Put(j)
}
