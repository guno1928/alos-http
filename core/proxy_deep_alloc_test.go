//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var dpCRLFCRLF = []byte("\r\n\r\n")

// allocsPerProxiedRequest reports heap objects allocated per request by the
// server. The client side must not be measured, so it never uses
// http.ReadResponse, which allocates a Response, a header map and a body reader
// on every call. Instead the exact reply length is learned once and every
// subsequent reply is drained into a single reused buffer.
func allocsPerProxiedRequest(t *testing.T, addr string, path string, n int) float64 {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := []byte("GET " + path + " HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	buf := make([]byte, 2<<20)

	// Learn the exact reply size once.
	if _, werr := conn.Write(req); werr != nil {
		t.Fatalf("probe write: %v", werr)
	}
	total := 0
	replyLen := 0
	for replyLen == 0 {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		nr, rerr := conn.Read(buf[total:])
		if nr > 0 {
			total += nr
		}
		if rerr != nil {
			t.Fatalf("probe read: %v", rerr)
		}
		if idx := bytes.Index(buf[:total], dpCRLFCRLF); idx >= 0 {
			want := idx + 4 + dpDeclaredBodyLen(buf[:idx])
			if total >= want {
				replyLen = want
			}
		}
	}

	drive := func(count int) {
		for i := 0; i < count; i++ {
			if _, werr := conn.Write(req); werr != nil {
				t.Fatalf("write %d: %v", i, werr)
			}
			got := 0
			for got < replyLen {
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				nr, rerr := conn.Read(buf[got:replyLen])
				if nr > 0 {
					got += nr
				}
				if rerr != nil {
					t.Fatalf("read %d after %d/%d bytes: %v", i, got, replyLen, rerr)
				}
			}
		}
	}

	drive(200) // warm pools, buffers and the exchange freelist

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	drive(n)
	runtime.GC()
	runtime.ReadMemStats(&after)

	return float64(after.Mallocs-before.Mallocs) / float64(n)
}

func dpDeclaredBodyLen(head []byte) int {
	for _, line := range strings.Split(string(head), "\r\n") {
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(line[:i]), "content-length") {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(line[i+1:])); err == nil {
			return v
		}
	}
	return 0
}

// Whole-process allocation ceiling. This figure includes the in-process test
// origin, which uses http.ReadRequest and allocates far more than the proxy
// does; TestDeepProxyAllocationsAreNearZero measures the proxy itself against a
// zero-allocation origin. This test exists to catch gross regressions anywhere
// in the request path.
func TestDeepAllocationsPerRequestAreBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	addr := dpProxy(t, dpFixed("alloc-check"))
	got := allocsPerProxiedRequest(t, addr, "/alloc", 3000)
	t.Logf("allocations per proxied request: %.2f", got)
	const budget = 14.0
	if got > budget {
		t.Fatalf("%.2f allocations per request exceeds the budget of %.0f", got, budget)
	}
}

func TestDeepAllocationsStableAcrossBodySizes(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	for _, size := range []int{64, 1024, 8192, 60000} {
		addr := dpProxy(t, dpFixed(strings.Repeat("b", size)))
		got := allocsPerProxiedRequest(t, addr, "/alloc", 1500)
		t.Logf("body %6d bytes -> %.2f allocations per request", size, got)
		if got > 14.0 {
			t.Errorf("body %d: %.2f allocations per request is too high", size, got)
		}
	}
}

func TestDeepAllocationsWithCacheHitsAreLow(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	o := newInloopOrigin(t, dpFixed("cached"))
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: time.Minute}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: time.Minute,
	}, nil)
	got := allocsPerProxiedRequest(t, addr, "/hit", 3000)
	t.Logf("allocations per cache hit: %.2f", got)
	if got > 12.0 {
		t.Fatalf("%.2f allocations per cache hit is too high", got)
	}
}

func TestDeepAllocationsWithHooksStayBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	o := newInloopOrigin(t, dpFixed("hooked"))
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: o.addr()}},
	}, func(pe *ProxyEngine) {
		pe.OnRequest = func(pr *ProxyRequest) bool { return true }
		pe.OnResponse = func(pr *ProxyResponse) {}
	})
	got := allocsPerProxiedRequest(t, addr, "/hooked", 2000)
	t.Logf("allocations per request with both hooks active: %.2f", got)
	// Hooks are documented to build a ProxyRequest/ProxyResponse per request, so
	// they cost more; the point is that the cost is small and bounded.
	if got > 14.0 {
		t.Fatalf("%.2f allocations per hooked request is too high", got)
	}
}

// The exchange freelist must be doing its job: sustained traffic must not grow
// the live heap.
func TestDeepHeapDoesNotGrowUnderSustainedLoad(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	addr := dpProxy(t, dpFixed("steady"))
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	drive := func(n int) {
		for i := 0; i < n; i++ {
			io.WriteString(conn, "GET /s HTTP/1.1\r\nHost: origin.test\r\n\r\n")
			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			resp, rerr := http.ReadResponse(br, nil)
			if rerr != nil {
				t.Fatalf("response %d: %v", i, rerr)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	drive(500)
	runtime.GC()
	var a runtime.MemStats
	runtime.ReadMemStats(&a)

	drive(3000)
	runtime.GC()
	var b runtime.MemStats
	runtime.ReadMemStats(&b)

	growth := int64(b.HeapAlloc) - int64(a.HeapAlloc)
	t.Logf("heap after 500 requests: %d KiB, after 3500: %d KiB (growth %d KiB)",
		a.HeapAlloc>>10, b.HeapAlloc>>10, growth>>10)
	if growth > 8<<20 {
		t.Fatalf("heap grew %d KiB over 3000 further requests; something is retained per request", growth>>10)
	}
}

// ---------- benchmarks ----------

// End-to-end throughput is measured with wrk via scripts/ab-compare.sh rather
// than with go test -bench: standing a server up per benchmark invocation
// confuses the iteration estimator and produces meaningless per-op figures.
// Allocation cost is covered exactly by the MemStats tests above.

func BenchmarkProxyRequestSerialize(b *testing.B) {
	req := &Request{
		Method: "GET", Path: "/some/path", RawPath: "/some/path", Query: "a=1&b=2",
		Headers: [][2]string{
			{"User-Agent", "bench/1.0"},
			{"Accept", "*/*"},
			{"X-Trace", "abcdef0123456789"},
			{"Cookie", "session=abc123; theme=dark"},
		},
	}
	buf := make([]byte, 0, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = appendProxyRequest(buf[:0], req, "origin.test", "203.0.113.7")
	}
	if len(buf) == 0 {
		b.Fatal("serializer produced nothing")
	}
}

func BenchmarkProxyResponseHead(b *testing.B) {
	headers := [][2]string{
		{"content-type", "text/plain"},
		{"date", "Mon, 01 Jan 2026 00:00:00 GMT"},
		{"server", "origin"},
		{"etag", `"abc123"`},
	}
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = appendProxyResponseHead(buf[:0], 200, respHeaders{str: headers}, 1024, true, "")
	}
	if len(buf) == 0 {
		b.Fatal("serializer produced nothing")
	}
}

func BenchmarkBalancerPick(b *testing.B) {
	backends := backendsForBalance(1, 1, 1, 1)
	for _, typ := range []struct {
		name string
		t    LoadBalancerType
	}{
		{"RoundRobin", LBRoundRobin},
		{"WeightedRR", LBWeightedRR},
		{"LeastConn", LBLeastConn},
		{"IPHash", LBIPHash},
		{"Random", LBRandom},
	} {
		lb := newBalancer(typ.t, backends)
		b.Run(typ.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lb.pick(backends, "198.51.100.7")
			}
		})
	}
}
