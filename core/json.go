package core

import (
	"log"
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
	data, err := sonic.Marshal(v)
	if err != nil {
		log.Printf("[JSON] marshal failed: %v", err)
		j.Buf = append(j.Buf[:0], "null"...)
		return j.Buf
	}
	j.Buf = append(j.Buf[:0], data...)
	return j.Buf
}

func (j *JSON) Release() {
	j.Buf = j.Buf[:0]
	jsonPool.Put(j)
}
