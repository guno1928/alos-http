//go:build linux && amd64

package core

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestProxyBackendFINCoalescedWithBodyFailsPromptly(t *testing.T) {
	addr := dpProxy(t, func(req *http.Request, conn net.Conn, br *bufio.Reader) {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\npartial")
		conn.Close()
	})
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		io.WriteString(c, "GET /x HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		elapsed := time.Since(start)
		if err != nil {
			c.Close()
			t.Fatalf("attempt %d: no response %v after a backend that died mid-body (waited %v)", i, err, elapsed)
		}
		resp.Body.Close()
		c.Close()
		if resp.StatusCode < 500 {
			t.Fatalf("attempt %d: status %d, want 5xx", i, resp.StatusCode)
		}
		if elapsed > 1500*time.Millisecond {
			t.Fatalf("attempt %d: 5xx took %v; the backend FIN was not noticed until a timeout", i, elapsed)
		}
	}
}
