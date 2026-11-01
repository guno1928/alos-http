//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h1BudgetLimit      = 1 << 20
	h1BudgetPollPeriod = 5 * time.Millisecond
)

func startH1BudgetServer(t *testing.T) (string, *Server) {
	var srv *Server
	addr := startH2FixServer(t, func(c *Config) {
		c.MaxInFlightBodyBytes = h1BudgetLimit
		c.MaxBodySize = h1BudgetLimit
	}, func(s *Server) {
		srv = s
		s.Router.POST("/body", func(req *Request, resp *Response) { resp.Status(200).String(strconv.Itoa(len(req.Body))) })
	})
	return addr, srv
}

func dialH1Budget(t *testing.T, addr string, wire string) net.Conn {
	conn, err := net.DialTimeout("tcp", addr, h2FixCeiling)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(wallDeadline(2 * h2FixCeiling))
	if _, err := conn.Write([]byte(wire)); err != nil {
		t.Fatalf("write: %v", err)
	}
	return conn
}

func awaitBodyCharge(t *testing.T, srv *Server, atLeast int64) int64 {
	t.Helper()
	start := turbo.Now()
	for turbo.Since(start) < h2FixCeiling {
		if held := srv.inFlightBodyBytes.Load(); held >= atLeast {
			return held
		}
		turbo.Sleep(h1BudgetPollPeriod)
	}
	t.Fatalf("body budget charge stayed at %d, want at least %d", srv.inFlightBodyBytes.Load(), atLeast)
	return 0
}

func h1BudgetOutcome(conn net.Conn) (int, string) {
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func readH1BudgetResponse(t *testing.T, conn net.Conn) (int, string) {
	t.Helper()
	status, body := h1BudgetOutcome(conn)
	if status == 0 {
		t.Fatalf("read response: %s", body)
	}
	return status, body
}

func TestH1HeaderOnlyUploadsDoNotPinBodyBudget(t *testing.T) {
	addr, srv := startH1BudgetServer(t)
	const head = "POST /body HTTP/1.1\r\nHost: budget.test\r\n"
	const declaredLen = h1BudgetLimit - 64
	declared := dialH1Budget(t, addr, head+"Content-Length: "+strconv.Itoa(declaredLen)+"\r\n\r\nx")
	awaitBodyCharge(t, srv, 1)
	chunked := dialH1Budget(t, addr, head+"Transfer-Encoding: chunked\r\n\r\n5\r\nab")
	charged := awaitBodyCharge(t, srv, 2)
	if charged > int64(len("x")+len("5\r\nab")) {
		t.Fatalf("two stalled uploads that sent %d body bytes hold %d bytes of the shared body budget", len("x")+len("5\r\nab"), charged)
	}

	victim := dialH1Budget(t, addr, head+"Content-Length: 5\r\n\r\nhello")
	if status, body := readH1BudgetResponse(t, victim); status != 200 || body != "5" {
		t.Fatalf("upload beside stalled header-only uploads got %d %q, want 200 \"5\"", status, body)
	}

	half := declaredLen / 2
	if _, err := declared.Write([]byte(strings.Repeat("y", half))); err != nil {
		t.Fatalf("write body: %v", err)
	}
	awaitBodyCharge(t, srv, int64(1+half))
	if _, err := declared.Write([]byte(strings.Repeat("z", declaredLen-1-half))); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if status, body := readH1BudgetResponse(t, declared); status != 200 || body != strconv.Itoa(declaredLen) {
		t.Fatalf("complete declared upload got %d %q", status, body)
	}
	if _, err := chunked.Write([]byte("cde\r\n0\r\n\r\n")); err != nil {
		t.Fatalf("write chunk: %v", err)
	}
	if status, body := readH1BudgetResponse(t, chunked); status != 200 || body != "5" {
		t.Fatalf("complete chunked upload got %d %q", status, body)
	}
	start := turbo.Now()
	for srv.inFlightBodyBytes.Load() != 0 && turbo.Since(start) < h2FixCeiling {
		turbo.Sleep(h1BudgetPollPeriod)
	}
	if held := srv.inFlightBodyBytes.Load(); held != 0 {
		t.Fatalf("finished uploads still hold %d body budget bytes", held)
	}
}

func TestH1ChargedBodyStillBoundedByBudget(t *testing.T) {
	addr, srv := startH1BudgetServer(t)
	const head = "POST /body HTTP/1.1\r\nHost: budget.test\r\n"
	first := dialH1Budget(t, addr, head+"Content-Length: "+strconv.Itoa(h1BudgetLimit)+"\r\n\r\n"+strings.Repeat("a", h1BudgetLimit-1))
	awaitBodyCharge(t, srv, h1BudgetLimit-1)
	second := dialH1Budget(t, addr, head+"Content-Length: 64\r\n\r\n"+strings.Repeat("b", 64))
	if status, _ := readH1BudgetResponse(t, second); status != 503 {
		t.Fatalf("upload past an exhausted body budget got %d, want 503", status)
	}
	if _, err := first.Write([]byte("a")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if status, body := readH1BudgetResponse(t, first); status != 200 || body != strconv.Itoa(h1BudgetLimit) {
		t.Fatalf("budget holder got %d %q", status, body)
	}
}

func h1UploadWorkload(size int, chunked bool) perfH1Workload {
	head := "POST /echo HTTP/1.1\r\nHost: alos.gg\r\nContent-Type: application/octet-stream\r\n"
	body := strings.Repeat("a", size)
	wire := head + "Content-Length: " + strconv.Itoa(size) + "\r\n\r\n" + body
	if chunked {
		wire = head + "Transfer-Encoding: chunked\r\n\r\n" + strconv.FormatInt(int64(size), 16) + "\r\n" + body + "\r\n0\r\n\r\n"
	}
	return perfH1Workload{"upload", "POST", []byte(wire), []byte(strconv.Itoa(size))}
}

func BenchmarkH1BufferedUpload(b *testing.B) {
	for _, tc := range []struct {
		name    string
		size    int
		chunked bool
	}{
		{"ContentLength64K", perfH1Body64K, false},
		{"ContentLength1M", perfH1Body1M, false},
		{"Chunked64K", perfH1Body64K, true},
		{"Chunked1M", perfH1Body1M, true},
	} {
		b.Run(tc.name, func(b *testing.B) { benchPerfH1RoundTrip(b, h1UploadWorkload(tc.size, tc.chunked), 1) })
	}
}
