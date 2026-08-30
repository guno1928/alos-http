package core

import (
	"strings"
	"testing"
	"unsafe"
)

func benchAliasSource(nHeaders, nameLen, valLen int) ([]byte, []string, []string) {
	stride := nameLen + valLen
	buf := []byte(strings.Repeat("z", nHeaders*stride))
	names := make([]string, nHeaders)
	vals := make([]string, nHeaders)
	for i := 0; i < nHeaders; i++ {
		names[i] = unsafe.String(&buf[i*stride], nameLen)
		vals[i] = unsafe.String(&buf[i*stride+nameLen], valLen)
	}
	return buf, names, vals
}

func reAlias(req *Request, names, vals []string, path, host string) {
	req.Headers = req.Headers[:0]
	for j := range names {
		req.Headers = append(req.Headers, [2]string{names[j], vals[j]})
	}
	req.Method = "GET"
	req.Path = path
	req.Host = host
	req.aliasesReadBuf = true
}

func BenchmarkPromoteArena(b *testing.B) {
	buf, names, vals := benchAliasSource(14, 18, 42)
	path := unsafe.String(&buf[0], 24)
	host := unsafe.String(&buf[0], 11)
	req := &Request{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reAlias(req, names, vals, path, host)
		promoteRequestStrings(req)
	}
}

func BenchmarkPromotePerRequestAlloc(b *testing.B) {
	buf, names, vals := benchAliasSource(14, 18, 42)
	path := unsafe.String(&buf[0], 24)
	host := unsafe.String(&buf[0], 11)
	req := &Request{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.promoteBuf = nil
		req.promoteOff = 0
		reAlias(req, names, vals, path, host)
		promoteRequestStrings(req)
	}
}

func BenchmarkPromoteNoop(b *testing.B) {
	req := &Request{}
	req.aliasesReadBuf = false
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		promoteRequestStrings(req)
	}
}

func TestPromoteCorrectnessAndArena(t *testing.T) {
	buf, names, vals := benchAliasSource(6, 12, 20)
	path := unsafe.String(&buf[0], 10)
	host := unsafe.String(&buf[0], 6)
	req := &Request{}
	reAlias(req, names, vals, path, host)
	wantNames := make([]string, len(names))
	wantVals := make([]string, len(vals))
	for i := range names {
		wantNames[i] = string([]byte(names[i]))
		wantVals[i] = string([]byte(vals[i]))
	}
	promoteRequestStrings(req)
	for i := range buf {
		buf[i] = '!'
	}
	for i := range req.Headers {
		if req.Headers[i][0] != wantNames[i] || req.Headers[i][1] != wantVals[i] {
			t.Fatalf("header %d mutated after source overwrite: got (%q,%q)", i, req.Headers[i][0], req.Headers[i][1])
		}
	}
	if req.aliasesReadBuf {
		t.Fatalf("aliasesReadBuf should be false after promotion")
	}
}

func TestPromoteNoopWhenNotAliased(t *testing.T) {
	req := &Request{}
	req.aliasesReadBuf = false
	allocs := testing.AllocsPerRun(200, func() {
		promoteRequestStrings(req)
	})
	if allocs != 0 {
		t.Fatalf("no-op promotion allocated %v times, want 0", allocs)
	}
}

func TestPromoteArenaAmortizesAllocations(t *testing.T) {
	buf, names, vals := benchAliasSource(14, 18, 42)
	path := unsafe.String(&buf[0], 24)
	host := unsafe.String(&buf[0], 11)
	req := &Request{}
	reAlias(req, names, vals, path, host)
	promoteRequestStrings(req)
	allocs := testing.AllocsPerRun(2000, func() {
		reAlias(req, names, vals, path, host)
		promoteRequestStrings(req)
	})
	if allocs > 1 {
		t.Fatalf("arena promotion averaged %v allocs/op, want <=1 (amortized)", allocs)
	}
}
