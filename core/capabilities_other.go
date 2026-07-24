//go:build !linux

package core

import "runtime"

// Capabilities describes the runtime environment and hardware features detected on the host.
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

// DetectCapabilities returns the detected OS, architecture, CPU count, and GOMAXPROCS for the current host. On non-Linux builds it always reports no kTLS, NIC offload, or CPU crypto extensions.
func DetectCapabilities() Capabilities {
	return Capabilities{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
}

// UseKTLS reports whether kernel TLS offload should be used; always false on non-Linux builds.
func (c Capabilities) UseKTLS() bool { return false }
