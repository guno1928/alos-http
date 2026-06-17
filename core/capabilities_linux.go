//go:build linux

package core

import (
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/cpu"
	"golang.org/x/sys/unix"
)

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
	c := Capabilities{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
	switch runtime.GOARCH {
	case "amd64", "386":
		c.CPUHasAES = cpu.X86.HasAES
		c.CPUHasPCLMULQDQ = cpu.X86.HasPCLMULQDQ
	case "arm64":
		c.CPUHasAES = cpu.ARM64.HasAES
		c.CPUHasPCLMULQDQ = cpu.ARM64.HasPMULL
	}
	c.KTLSAvailable = kernelKTLSAvailable()
	c.NICIface = defaultRouteIface()
	if c.NICIface != "" {
		c.NICOffloadTX, c.NICOffloadRX = nicTLSOffload(c.NICIface)
	}
	return c
}

func (c Capabilities) UseKTLS() bool {
	return c.KTLSAvailable && c.NICOffloadTX
}

func kernelKTLSAvailable() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_ulp")
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(data)) {
		if f == "tls" {
			return true
		}
	}
	return false
}

func defaultRouteIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "00000000" {
				return fields[0]
			}
		}
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err == nil {
		for _, e := range entries {
			if e.Name() != "lo" {
				return e.Name()
			}
		}
	}
	return ""
}

const (
	ethtoolGSSetInfo = 0x37
	ethtoolGStrings  = 0x1b
	ethtoolGFeatures = 0x3a
	ethSSFeatures    = 4
	ethGStringLen    = 32
	siocEthtool      = 0x8946
)

func ethtoolCall(fd int, iface string, data unsafe.Pointer) bool {
	var ifr [40]byte
	copy(ifr[:15], iface)
	*(*uintptr)(unsafe.Pointer(&ifr[16])) = uintptr(data)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(siocEthtool), uintptr(unsafe.Pointer(&ifr[0])))
	runtime.KeepAlive(data)
	return errno == 0
}

func nicTLSOffload(iface string) (tx bool, rx bool) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return false, false
	}
	defer unix.Close(fd)

	var si struct {
		cmd      uint32
		reserved uint32
		ssetMask uint64
		data     [1]uint32
	}
	si.cmd = ethtoolGSSetInfo
	si.ssetMask = 1 << ethSSFeatures
	if !ethtoolCall(fd, iface, unsafe.Pointer(&si)) || si.ssetMask == 0 {
		return false, false
	}
	count := int(si.data[0])
	if count <= 0 || count > 4096 {
		return false, false
	}

	strBuf := make([]byte, 12+count*ethGStringLen)
	*(*uint32)(unsafe.Pointer(&strBuf[0])) = ethtoolGStrings
	*(*uint32)(unsafe.Pointer(&strBuf[4])) = ethSSFeatures
	*(*uint32)(unsafe.Pointer(&strBuf[8])) = uint32(count)
	if !ethtoolCall(fd, iface, unsafe.Pointer(&strBuf[0])) {
		return false, false
	}
	txIdx, rxIdx := -1, -1
	for i := 0; i < count; i++ {
		off := 12 + i*ethGStringLen
		name := cString(strBuf[off : off+ethGStringLen])
		switch name {
		case "tls-hw-tx-offload":
			txIdx = i
		case "tls-hw-rx-offload":
			rxIdx = i
		}
	}
	if txIdx < 0 && rxIdx < 0 {
		return false, false
	}

	blocks := (count + 31) / 32
	featBuf := make([]byte, 8+blocks*16)
	*(*uint32)(unsafe.Pointer(&featBuf[0])) = ethtoolGFeatures
	*(*uint32)(unsafe.Pointer(&featBuf[4])) = uint32(blocks)
	if !ethtoolCall(fd, iface, unsafe.Pointer(&featBuf[0])) {
		return false, false
	}
	activeBit := func(idx int) bool {
		if idx < 0 {
			return false
		}
		blk := idx / 32
		bit := uint32(1) << (uint(idx) % 32)
		off := 8 + blk*16 + 8
		return *(*uint32)(unsafe.Pointer(&featBuf[off]))&bit != 0
	}
	return activeBit(txIdx), activeBit(rxIdx)
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
