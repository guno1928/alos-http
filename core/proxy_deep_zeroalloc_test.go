//go:build linux && amd64

package core

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"
)

// zeroAllocOrigin is an upstream that allocates nothing per request. The usual
// test origin uses http.ReadRequest, which allocates a Request, a header map and
// a parsed URL every time; because it runs in this process those allocations are
// indistinguishable from the proxy's own in MemStats. This one reads into a
// fixed buffer, counts request terminators and writes a canned reply, so a
// MemStats delta around it reflects the proxy alone.
func zeroAllocOrigin(t *testing.T, bodySize int) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	body := bytes.Repeat([]byte("z"), bodySize)
	reply := append([]byte("HTTP/1.1 200 OK\r\nContent-Length: "+
		strconv.Itoa(bodySize)+"\r\nContent-Type: text/plain\r\n\r\n"), body...)

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64<<10)
				carry := 0
				for {
					n, rerr := c.Read(buf[carry:])
					if n > 0 {
						total := carry + n
						// Count complete request heads, carrying a split
						// terminator across reads.
						scanned := 0
						for {
							idx := bytes.Index(buf[scanned:total], dpCRLFCRLF)
							if idx < 0 {
								break
							}
							scanned += idx + 4
							if _, werr := c.Write(reply); werr != nil {
								return
							}
						}
						keep := total - scanned
						if keep > 3 {
							keep = 3
						}
						copy(buf, buf[total-keep:total])
						carry = keep
					}
					if rerr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

// zaAllocsPerRequest measures allocations per request against a
// zero-allocation origin, using a client that allocates nothing per iteration.
func zaAllocsPerRequest(t *testing.T, addr string, n int) float64 {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req := []byte("GET /za HTTP/1.1\r\nHost: origin.test\r\n\r\n")
	buf := make([]byte, 2<<20)

	conn.Write(req)
	total, replyLen := 0, 0
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
			if want := idx + 4 + dpDeclaredBodyLen(buf[:idx]); total >= want {
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
					t.Fatalf("read %d: %v", i, rerr)
				}
			}
		}
	}

	drive(300)
	var before, after MemStatsAlias
	readMem(&before)
	drive(n)
	readMem(&after)
	return float64(after.Mallocs-before.Mallocs) / float64(n)
}

// The real budget: with neither the origin nor the client allocating, whatever
// MemStats records is the proxy's own cost.
func TestDeepProxyAllocationsAreNearZero(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: zeroAllocOrigin(t, 1024)}},
	}, nil)
	got := zaAllocsPerRequest(t, addr, 5000)
	t.Logf("proxy allocations per request: %.3f", got)
	// The parser hands the serializer byte slices of its own reused copy of the
	// header block, so a buffered proxied request allocates nothing at all. The
	// budget is a hair above zero only to tolerate a stray runtime allocation
	// landing inside the measured window.
	if got > 0.05 {
		t.Fatalf("%.3f allocations per request; the proxy hot path must not allocate", got)
	}
}

func TestDeepProxyAllocationsFlatAcrossSizes(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	for _, size := range []int{64, 1024, 16384, 60000} {
		addr := startInloopProxy(t, DomainConfig{
			Domain:   "origin.test",
			Backends: []BackendConfig{{Addr: zeroAllocOrigin(t, size)}},
		}, nil)
		got := zaAllocsPerRequest(t, addr, 3000)
		t.Logf("body %6d bytes -> %.3f proxy allocations per request", size, got)
		if got > 0.05 {
			t.Errorf("body %d: %.3f allocations per request is too high", size, got)
		}
	}
}

func TestDeepProxyCacheHitAllocationsAreNearZero(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	addr := startCachingProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: zeroAllocOrigin(t, 4096)}},
	}, ProxyCacheConfig{
		Rules:         []CacheRule{{PathPrefix: "/", MaxAge: time.Minute}},
		MaxEntrySize:  1 << 20,
		DefaultMaxAge: time.Minute,
	}, nil)
	got := zaAllocsPerRequest(t, addr, 5000)
	t.Logf("proxy allocations per cache hit: %.3f", got)
	if got > 3.5 {
		t.Fatalf("%.3f allocations per cache hit is too high", got)
	}
}

func TestDeepProxyAllocationsFlatUnderPipelining(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every allocation, so budgets do not apply")
	}
	addr := startInloopProxy(t, DomainConfig{
		Domain:   "origin.test",
		Backends: []BackendConfig{{Addr: zeroAllocOrigin(t, 512)}},
	}, nil)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	one := "GET /p HTTP/1.1\r\nHost: origin.test\r\n\r\n"
	batch := []byte(one + one + one + one)
	buf := make([]byte, 1<<20)

	drain := func(reps int) {
		for i := 0; i < reps; i++ {
			conn.Write(batch)
			seen := 0
			for seen < 4 {
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, rerr := conn.Read(buf)
				if n > 0 {
					seen += bytes.Count(buf[:n], []byte("HTTP/1.1 200"))
				}
				if rerr != nil {
					t.Fatalf("read: %v", rerr)
				}
			}
		}
	}

	drain(100)
	var before, after MemStatsAlias
	readMem(&before)
	drain(500)
	readMem(&after)
	per := float64(after.Mallocs-before.Mallocs) / float64(500*4)
	t.Logf("proxy allocations per pipelined request: %.3f", per)
	if per > 0.05 {
		t.Fatalf("%.3f allocations per pipelined request is too high", per)
	}
}
