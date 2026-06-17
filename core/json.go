package core

import (
	"log"
	"sync"

	"github.com/bytedance/sonic"
)

// JSON is a pooled JSON encoder backed by sonic. Acquire one with AcquireJSON,
// call Marshal to encode a value, then Release to return it to the pool.
//
//	j := core.AcquireJSON()
//	defer j.Release()
//	resp.Status(200).JSON(j.Marshal(myStruct))
type JSON struct {
	Buf []byte
}

var jsonPool = sync.Pool{
	New: func() any {
		return &JSON{}
	},
}

// AcquireJSON returns a pooled JSON encoder. Call Release when done to return
// it to the pool and avoid allocations.
//
//	j := core.AcquireJSON()
//	defer j.Release()
//	data := j.Marshal(payload)
func AcquireJSON() *JSON {
	return jsonPool.Get().(*JSON)
}

func (j *JSON) Marshal(v any) []byte {
	data, err := sonic.Marshal(v)
	if err != nil {
		log.Printf("[JSON] marshal failed: %v", err)
		return []byte("null")
	}
	return data
}

func (j *JSON) Release() {
	j.Buf = j.Buf[:0]
	jsonPool.Put(j)
}
