//go:build linux && amd64

package core

import (
	"strconv"
	"strings"
	"testing"
)

func rootFastLimitsServer(t *testing.T, maxBytes, maxCount int) *Server {
	t.Helper()
	srv := New(Config{MaxHeaderSize: maxBytes, MaxHeaderCount: maxCount, MaxConnsPerIP: -1})
	srv.Router.GET("/", func(_ *Request, resp *Response) { resp.Status(200).String("root") })
	srv.Router.Build()
	srv.computeFastDispatch()
	if srv.plainRootFast.Load() == nil {
		t.Fatal("root fast path not built")
	}
	return srv
}

func rootFastLimitsRequest(fields int, valueLen int, trailing string) []byte {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\nHost: a\r\n")
	for i := 1; i < fields; i++ {
		b.WriteString("X" + strconv.Itoa(i) + ": " + strings.Repeat("v", valueLen) + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(trailing)
	return []byte(b.String())
}

func TestRootFastPathHonoursHeaderLimits(t *testing.T) {
	const pipelined = "GET / HTTP/1.1\r\n"
	cases := []struct {
		name     string
		maxBytes int
		maxCount int
		raw      []byte
		wantFast bool
	}{
		{"scalar/within", 64, 3, rootFastLimitsRequest(3, 1, ""), true},
		{"scalar/count", 64, 2, rootFastLimitsRequest(3, 1, ""), false},
		{"scalar/bytes", 30, 3, rootFastLimitsRequest(3, 1, ""), false},
		{"terminator/within", 4096, 4, rootFastLimitsRequest(4, 40, ""), true},
		{"terminator/count", 4096, 3, rootFastLimitsRequest(4, 40, ""), false},
		{"terminator/bytes", 120, 4, rootFastLimitsRequest(4, 40, ""), false},
		{"search/within", 4096, 4, rootFastLimitsRequest(4, 40, pipelined), true},
		{"search/count", 4096, 3, rootFastLimitsRequest(4, 40, pipelined), false},
		{"search/bytes", 120, 4, rootFastLimitsRequest(4, 40, pipelined), false},
		{"default-count/within", 0, 0, rootFastLimitsRequest(128, 1, ""), true},
		{"default-count/over", 0, 0, rootFastLimitsRequest(129, 1, ""), false},
		{"boundary/bytes-exact", len(rootFastLimitsRequest(4, 40, "")) - 2, 4, rootFastLimitsRequest(4, 40, ""), true},
		{"boundary/bytes-over", len(rootFastLimitsRequest(4, 40, "")) - 3, 4, rootFastLimitsRequest(4, 40, ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := rootFastLimitsServer(t, tc.maxBytes, tc.maxCount)
			_, _, _, fast := srv.matchPlainRootFastRequest(tc.raw, false)
			var req Request
			_, _, _, _, reject, _, tooLarge, ok := parseH1RequestHead(tc.raw, &req, srv.limits.Load().MaxHeaderSize, srv.config.MaxHeaderCount)
			general := ok && !tooLarge && reject == h1RejectNone
			if fast != tc.wantFast || general != tc.wantFast {
				t.Fatalf("%d-byte request: fast path accepted=%v, general parser accepted=%v (tooLarge=%v), want %v", len(tc.raw), fast, general, tooLarge, tc.wantFast)
			}
		})
	}
}

func TestRootFastPathOverLimitAnswers431(t *testing.T) {
	addr := startH2FixServer(t, func(c *Config) {
		c.MaxHeaderSize = 256
		c.MaxHeaderCount = 4
	}, func(s *Server) {
		s.Router.GET("/", func(_ *Request, resp *Response) { resp.Status(200).String("root") })
	})
	for _, tc := range []struct {
		raw  []byte
		want int
	}{
		{rootFastLimitsRequest(2, 8, ""), 200},
		{rootFastLimitsRequest(6, 8, ""), 431},
		{rootFastLimitsRequest(2, 400, ""), 431},
	} {
		conn := dialH1Budget(t, addr, string(tc.raw))
		if status, body := h1BudgetOutcome(conn); status != tc.want {
			t.Fatalf("%d-byte GET / answered %d %q, want %d", len(tc.raw), status, body, tc.want)
		}
		_ = conn.Close()
	}
}

func BenchmarkGatePlainRootFastMatch(b *testing.B) {
	srv := New(Config{MaxConnsPerIP: -1})
	srv.Router.GET("/", func(_ *Request, resp *Response) { resp.Status(200).String("root") })
	srv.Router.Build()
	srv.computeFastDispatch()
	for _, req := range gateRootFastRequests {
		b.Run(req.name, func(b *testing.B) {
			b.SetBytes(int64(len(req.raw)))
			for b.Loop() {
				if _, _, _, ok := srv.matchPlainRootFastRequest(req.raw, false); !ok {
					b.Fatal("fast path refused the request")
				}
			}
		})
	}
}

func BenchmarkPerfH1RootFast(b *testing.B) {
	ts := newTestServer(b, testServerOptions{Routes: func(r *Router) {
		r.GET("/", func(_ *Request, resp *Response) { resp.String(perfH1PlaintextBody) })
	}})
	w := perfH1Workload{"root", "GET", perfH1Get("/", ""), []byte(perfH1PlaintextBody)}
	b.Run("Depth1", func(b *testing.B) { benchPerfH1RoundTripOn(b, ts, w, 1) })
	b.Run("Pipelined16", func(b *testing.B) { benchPerfH1RoundTripOn(b, ts, w, perfH1PipelineDepth) })
}
