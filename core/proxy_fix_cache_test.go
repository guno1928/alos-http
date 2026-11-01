//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/andybalholm/brotli"

	"github.com/guno1928/turbo"
)

func proxyFixEncode(t testing.TB, encoding string, raw []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	var w io.WriteCloser
	switch encoding {
	case "gzip":
		w = gzip.NewWriter(&out)
	case "deflate":
		fw, err := flate.NewWriter(&out, flate.BestCompression)
		if err != nil {
			t.Fatalf("deflate writer: %v", err)
		}
		w = fw
	case "br":
		w = brotli.NewWriter(&out)
	default:
		t.Fatalf("unknown encoding %q", encoding)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("%s write: %v", encoding, err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("%s close: %v", encoding, err)
	}
	return out.Bytes()
}

const (
	proxyFixCacheEntryCap = 1 << 20
	proxyFixInflatedBomb  = 8 << 20
)

func proxyFixRuledCache(maxEntry int64) *ProxyCache {
	return NewProxyCache(ProxyCacheConfig{
		MaxEntrySize: maxEntry,
		Rules:        []CacheRule{{PathPrefix: "/", MaxAge: time.Minute}},
	})
}

func TestProxyFixCacheInflationBoundedByMaxEntrySize(t *testing.T) {
	for _, enc := range []string{"gzip", "deflate", "br"} {
		t.Run(enc, func(t *testing.T) {
			pc := proxyFixRuledCache(proxyFixCacheEntryCap)
			defer pc.Stop()
			bomb := proxyFixEncode(t, enc, make([]byte, proxyFixInflatedBomb))
			if int64(len(bomb)) > proxyFixCacheEntryCap {
				t.Fatalf("encoded bomb is %d bytes, the test needs it under MaxEntrySize", len(bomb))
			}
			pc.Put("GET", "h", "/bomb", 200, [][2]string{{"Content-Encoding", enc}}, "application/octet-stream", bomb)
			if _, stored, _, _ := pc.Stats(); stored > proxyFixCacheEntryCap {
				t.Fatalf("%d encoded bytes inflated into a %d byte entry with MaxEntrySize=%d", len(bomb), stored, proxyFixCacheEntryCap)
			}
		})
	}
}

func TestProxyFixCacheStillInflatesEntriesWithinLimit(t *testing.T) {
	raw := proxyFixPattern(proxyFixCacheEntryCap / 2)
	for _, enc := range []string{"gzip", "deflate", "br"} {
		t.Run(enc, func(t *testing.T) {
			pc := proxyFixRuledCache(proxyFixCacheEntryCap)
			defer pc.Stop()
			pc.Put("GET", "h", "/ok", 200, [][2]string{{"Content-Encoding", enc}}, "application/octet-stream", proxyFixEncode(t, enc, raw))
			entry, hit := pc.GetFP("GET", "h", "/ok", true)
			if !hit || !bytes.Equal(entry.body, raw) {
				t.Fatalf("%s entry within MaxEntrySize: hit=%v, stored body matches=%v", enc, hit, hit && bytes.Equal(entry.body, raw))
			}
		})
	}
}

const (
	proxyFixHeavyBody      = 8 << 20
	proxyFixHeavyMisses    = 4
	proxyFixProbeRounds    = 20
	proxyFixProbeStallUpTo = 300 * time.Millisecond
)

const (
	proxyFixTextAlphabet = 16
	proxyFixLCGMul       = 6364136223846793005
	proxyFixLCGInc       = 1442695040888963407
	proxyFixLCGShift     = 33
)

func proxyFixNoisyText(n int) []byte {
	b := make([]byte, n)
	x := uint64(1)
	for i := range b {
		x = x*proxyFixLCGMul + proxyFixLCGInc
		b[i] = byte('a' + (x>>proxyFixLCGShift)%proxyFixTextAlphabet)
	}
	return b
}

func proxyFixHeavyOrigin(t *testing.T) *inloopOrigin {
	t.Helper()
	heavy := proxyFixEncode(t, "gzip", proxyFixNoisyText(proxyFixHeavyBody-1))
	return newInloopOrigin(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		if req.URL.Path != "/heavy" {
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCache-Control: no-store\r\n\r\nok")
			return
		}
		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(heavy))
		_, _ = conn.Write(heavy)
	})
}

func TestProxyFixCacheTransformDoesNotStallLoop(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector slows inflate and gzip by an order of magnitude, so loop latency is not meaningful")
	}
	o := proxyFixHeavyOrigin(t)
	cfg := DefaultProxyCacheConfig()
	cfg.MaxEntrySize = proxyFixHeavyBody
	cfg.CompressLevel = gzip.BestCompression
	srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) { s.SetProxyCache(cfg) })
	if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/probe")); got != http.StatusOK {
		t.Fatalf("warm-up probe: %d", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < proxyFixHeavyMisses; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, proxyFixIOTimeout)
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.SetDeadline(wallDeadline(proxyFixCeiling))
			_, _ = io.WriteString(c, proxyFixGet(proxyFixDomain, "/heavy?n="+strconv.Itoa(i)))
			_, _ = io.Copy(io.Discard, c)
		}(i)
	}
	var worst time.Duration
	for i := 0; i < proxyFixProbeRounds; i++ {
		start := turbo.Now()
		if got := proxyFixH1Status(t, addr, proxyFixGet(proxyFixDomain, "/probe")); got != http.StatusOK {
			t.Fatalf("probe %d: %d", i, got)
		}
		worst = max(worst, turbo.Since(start))
		time.Sleep(proxyFixPoll)
	}
	wg.Wait()
	t.Logf("worst probe latency while %d heavy cache stores ran: %v", proxyFixHeavyMisses, worst)
	if worst > proxyFixProbeStallUpTo {
		t.Fatalf("a probe on the same worker waited %v behind cache inflate/compress work, want under %v", worst, proxyFixProbeStallUpTo)
	}
	proxyFixEventually(t, "an offloaded heavy entry is stored", func() bool {
		entries, _, _, _ := srv.ProxyCacheStats()
		return entries > 0
	})
}

const (
	proxyFixPurgeWriters = 4
	proxyFixPurgeRun     = 150 * time.Millisecond
	proxyFixPurgeKeys    = 64
	proxyFixPurgeBody    = 100
)

func proxyFixCacheActual(pc *ProxyCache) (entries, bytes int64) {
	pc.entries.Range(func(key string, e *cacheEntry) bool {
		entries++
		bytes += cacheEntryCost(key, e)
		return true
	})
	return entries, bytes
}

func TestProxyFixCachePurgeAllKeepsCountersExact(t *testing.T) {
	pc := NewProxyCache(ProxyCacheConfig{})
	defer pc.Stop()
	body := make([]byte, proxyFixPurgeBody)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < proxyFixPurgeWriters; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				pc.PutManual("GET", "h", "/w"+strconv.Itoa(w)+"/"+strconv.Itoa(i%proxyFixPurgeKeys), 200, nil, "text/plain", body, time.Minute, 0, false, 0)
			}
		}(w)
	}
	deadline := turbo.Deadline(proxyFixPurgeRun)
	for turbo.Until(deadline) > 0 {
		pc.PurgeAll()
	}
	close(stop)
	wg.Wait()
	gotEntries, gotBytes, _, _ := pc.Stats()
	wantEntries, wantBytes := proxyFixCacheActual(pc)
	if gotEntries != wantEntries || gotBytes != wantBytes {
		t.Fatalf("after PurgeAll under concurrent Puts: counters say %d entries / %d bytes, the map holds %d / %d",
			gotEntries, gotBytes, wantEntries, wantBytes)
	}
}

func TestProxyFixCachePurgeDuringFillIsNotUndone(t *testing.T) {
	for _, purge := range []struct {
		name string
		run  func(s *Server)
	}{
		{"purge_all", func(s *Server) { s.PurgeAllProxyCache() }},
		{"purge_url", func(s *Server) { s.PurgeProxyCache("GET", proxyFixDomain, "/doc") }},
		{"purge_domain", func(s *Server) { s.PurgeDomainCache(proxyFixDomain) }},
	} {
		t.Run(purge.name, func(t *testing.T) {
			o := newProxyFixHeldOrigin(t, false)
			srv, addr := proxyFixStart(t, Config{}, proxyFixSingleBackend(o.addr()), func(s *Server) {
				s.SetProxyCache(DefaultProxyCacheConfig())
			})
			c := proxyFixDial(t, addr)
			defer c.Close()
			if _, err := io.WriteString(c, proxyFixGet(proxyFixDomain, "/doc")); err != nil {
				t.Fatalf("write: %v", err)
			}
			proxyFixEventually(t, "the cache miss reached the origin", func() bool { return o.received.Load() == 1 })
			purge.run(srv)
			o.releaseOnce()
			if resp, body := proxyFixReadResponse(t, bufio.NewReader(c)); resp.StatusCode != http.StatusOK || body != "ok" {
				t.Fatalf("in-flight response: %d %q", resp.StatusCode, body)
			}
			time.Sleep(proxyFixPoll)
			if entries, _, _, _ := srv.ProxyCacheStats(); entries != 0 {
				t.Fatalf("a fill that started before %s was stored afterwards (%d entries)", purge.name, entries)
			}
		})
	}
}
