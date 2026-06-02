//go:build !linux

package core

import "runtime"

type Capabilities struct {
	OS              string
	Arch            string
	NumCPU          int
	GOMAXPROCS      int
	CPUHasAES       bool
	CPUHasPCLMULQDQ bool
	KTLSAvailable   bool
	NICIface        string
	NICOffloadTX    bool
	NICOffloadRX    bool
}

func DetectCapabilities() Capabilities {
	return Capabilities{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
}

func (c Capabilities) UseKTLS() bool { return false }
