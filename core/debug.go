package core

import (
	"encoding/hex"
	"log"
	"sync/atomic"
)

var debugFlag atomic.Bool

func SetDebugFlag(on bool) { debugFlag.Store(on) }

func Dbg(format string, v ...interface{}) {
	if debugFlag.Load() {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func DbgHex(label string, data []byte) {
	if !debugFlag.Load() {
		return
	}
	if len(data) <= 48 {
		log.Printf("[DEBUG] %s: (%d bytes)\n%s", label, len(data), hex.Dump(data))
	} else {
		log.Printf("[DEBUG] %s: %d bytes", label, len(data))
	}
}
