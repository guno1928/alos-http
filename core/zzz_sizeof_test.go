//go:build linux && amd64

package core

import (
	"testing"
	"unsafe"
)

func TestZZZSizeof(t *testing.T) {
	t.Logf("epollConn=%d", unsafe.Sizeof(epollConn{}))
	t.Logf("Request=%d", unsafe.Sizeof(Request{}))
	t.Logf("Response=%d", unsafe.Sizeof(Response{}))
	t.Logf("tlsWorkerH2State=%d", unsafe.Sizeof(tlsWorkerH2State{}))
	t.Logf("epollSlab(header only, conns field)=%d", unsafe.Sizeof(epollSlab{}))
	t.Logf("H2Stream=%d", unsafe.Sizeof(H2Stream{}))
	t.Logf("TrafficAEAD=%d", unsafe.Sizeof(TrafficAEAD{}))
	t.Logf("tls12State=%d", unsafe.Sizeof(tls12State{}))
	t.Logf("ParsedClientHello=%d", unsafe.Sizeof(ParsedClientHello{}))
}
