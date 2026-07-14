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

// Marshal encodes v to JSON and returns the bytes; on failure it logs the error and returns the literal null.
//
// Example: data := j.Marshal(User{Name: "ada"})
// Example: resp.Status(200).JSON(j.Marshal(map[string]int{"count": 3}))
func (j *JSON) Marshal(v any) []byte {
	data, err := sonic.Marshal(v)
	if err != nil {
		log.Printf("[JSON] marshal failed: %v", err)
		return []byte("null")
	}
	return data
}

// Release returns the encoder to the pool for reuse; do not use it after calling Release.
//
// Example: defer j.Release()
func (j *JSON) Release() {
	j.Buf = j.Buf[:0]
	jsonPool.Put(j)
}
