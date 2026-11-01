//go:build linux && amd64

package core

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const limitsTestDeadline = 2 * time.Second

func startLimitsServer(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()
	addr := freeLoopbackAddr(t)
	cfg.Addr, cfg.LogRequests, cfg.Listeners = addr, false, 1
	srv := New(cfg)
	srv.Router.GET("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	srv.Router.POST("/ok", func(req *Request, resp *Response) { resp.Status(200).String("ok") })
	go func() { _ = srv.ListenAndServe() }()
	t.Cleanup(func() { stopServer(srv) })
	var probe net.Conn
	proxyFixEventually(t, "limits server accepts connections", func() bool {
		conn, err := net.DialTimeout("tcp4", addr, proxyFixStep)
		if err != nil {
			return false
		}
		probe = conn
		return true
	})
	defer probe.Close()
	client := &rawConn{Conn: probe, r: bufio.NewReader(probe)}
	status, err := client.roundTrip("GET /ok HTTP/1.1\r\nHost: limits.test\r\nConnection: close\r\n\r\n")
	if err != nil || status != http.StatusOK {
		t.Fatalf("readiness request: status=%d err=%v, want 200", status, err)
	}
	_ = probe.Close()
	proxyFixEventually(t, "readiness connection released", func() bool {
		limiter := srv.perIPConnLimiter.Load()
		return srv.activeConns.Load() == 0 && (limiter == nil || liveCount(limiter, "127.0.0.1") == 0)
	})
	return srv, addr
}

type rawConn struct {
	net.Conn
	r *bufio.Reader
}

func dialRaw(t *testing.T, addr string) *rawConn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", addr, limitsTestDeadline)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &rawConn{Conn: c, r: bufio.NewReader(c)}
}

func (c *rawConn) roundTrip(raw string) (int, error) {
	_ = c.SetDeadline(time.Now().Add(limitsTestDeadline))
	if _, err := c.Write([]byte(raw)); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(c.r, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = bufio.NewReader(resp.Body).WriteTo(discardWriter{})
	return resp.StatusCode, nil
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

const getOK = "GET /ok HTTP/1.1\r\nHost: limits.test\r\n\r\n"

func mustServe(t *testing.T, c *rawConn, label string) {
	t.Helper()
	status, err := c.roundTrip(getOK)
	if err != nil || status != 200 {
		t.Fatalf("%s: status=%d err=%v, want 200", label, status, err)
	}
}

func mustRefuse(t *testing.T, c *rawConn, label string) {
	t.Helper()
	if status, err := c.roundTrip(getOK); err == nil {
		t.Fatalf("%s: served with status %d, want the connection refused", label, status)
	}
}

func TestLimitsDefaultsMatchNew(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0"})
	got := srv.Limits()
	want := Limits{
		MaxConns: limitDefaultMaxConns, MaxConnsPerIP: limitDefaultMaxConnsPerIP,
		MaxBodySize: limitDefaultMaxBodySize, MaxHeaderSize: limitDefaultMaxHeaderSize,
		ReadTimeout: limitDefaultReadTimeout, WriteTimeout: limitDefaultWriteTimeout,
		IdleTimeout: limitDefaultIdleTimeout, HandshakeTimeout: limitDefaultHandshakeTimeout,
	}
	if got != want {
		t.Fatalf("Limits() = %+v, want %+v", got, want)
	}
	if err := srv.SetLimits(Limits{}); err != nil || srv.Limits() != want {
		t.Fatalf("SetLimits(zero) = %v, limits %+v, want the defaults", err, srv.Limits())
	}
	if err := srv.SetLimits(Limits{MaxHeaderSize: -1}); !errors.Is(err, ErrInvalidLimits) {
		t.Fatalf("negative MaxHeaderSize: err=%v", err)
	}
	if srv.Limits() != want {
		t.Fatal("a rejected SetLimits changed the limits")
	}
}

func TestSetLimitsLowersMaxConnsPerIPForNewConnectionsOnly(t *testing.T) {
	srv, addr := startLimitsServer(t, Config{MaxConnsPerIP: 20})
	first, second := dialRaw(t, addr), dialRaw(t, addr)
	mustServe(t, first, "first")
	mustServe(t, second, "second")

	cur := srv.Limits()
	cur.MaxConnsPerIP = 2
	if err := srv.SetLimits(cur); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, dialRaw(t, addr), "third connection over the lowered limit")
	mustServe(t, first, "first after lowering")
	mustServe(t, second, "second after lowering")

	_ = first.Close()
	deadline := time.Now().Add(limitsTestDeadline)
	for {
		c := dialRaw(t, addr)
		if status, err := c.roundTrip(getOK); err == nil && status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing a connection never freed its per-IP slot")
		}
		time.Sleep(15 * time.Millisecond)
	}
}

func TestSetLimitsRaisesMaxConnsPerIP(t *testing.T) {
	srv, addr := startLimitsServer(t, Config{MaxConnsPerIP: 1})
	mustServe(t, dialRaw(t, addr), "first")
	mustRefuse(t, dialRaw(t, addr), "second at limit 1")
	cur := srv.Limits()
	cur.MaxConnsPerIP = 2
	if err := srv.SetLimits(cur); err != nil {
		t.Fatal(err)
	}
	mustServe(t, dialRaw(t, addr), "second at limit 2")
}

func TestSetLimitsEnablesAPerIPLimitThatStartedUnlimited(t *testing.T) {
	srv, addr := startLimitsServer(t, Config{MaxConnsPerIP: -1})
	for i := range 3 {
		mustServe(t, dialRaw(t, addr), "unlimited conn "+string(rune('a'+i)))
	}
	cur := srv.Limits()
	cur.MaxConnsPerIP = 2
	if err := srv.SetLimits(cur); err != nil {
		t.Fatal(err)
	}
	mustServe(t, dialRaw(t, addr), "first counted")
	mustServe(t, dialRaw(t, addr), "second counted")
	mustRefuse(t, dialRaw(t, addr), "third counted")
}

func TestSetLimitsChangesHeaderAndBodyCapsOnTheNextRequest(t *testing.T) {
	srv, addr := startLimitsServer(t, Config{MaxConnsPerIP: -1})
	c := dialRaw(t, addr)
	bigHeader := "GET /ok HTTP/1.1\r\nHost: limits.test\r\nX-Pad: " + strings.Repeat("a", 2048) + "\r\n\r\n"
	if status, err := c.roundTrip(bigHeader); err != nil || status != 200 {
		t.Fatalf("2 KiB header under default cap: status=%d err=%v", status, err)
	}
	body := strings.Repeat("b", 4096)
	post := "POST /ok HTTP/1.1\r\nHost: limits.test\r\nContent-Length: 4096\r\n\r\n" + body
	if status, err := c.roundTrip(post); err != nil || status != 200 {
		t.Fatalf("4 KiB body under default cap: status=%d err=%v", status, err)
	}

	cur := srv.Limits()
	cur.MaxHeaderSize, cur.MaxBodySize = 1024, 1024
	if err := srv.SetLimits(cur); err != nil {
		t.Fatal(err)
	}
	if status, _ := dialRaw(t, addr).roundTrip(bigHeader); status != 431 {
		t.Fatalf("2 KiB header over a 1 KiB cap: status %d, want 431", status)
	}
	if status, _ := dialRaw(t, addr).roundTrip(post); status != 413 {
		t.Fatalf("4 KiB body over a 1 KiB cap: status %d, want 413", status)
	}
}

func TestSetLimitsIsRaceFreeUnderLoad(t *testing.T) {
	srv, addr := startLimitsServer(t, Config{MaxConnsPerIP: -1})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			c := dialRaw(t, addr)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if status, err := c.roundTrip(getOK); err != nil || status != 200 {
					t.Errorf("request during SetLimits churn: status=%d err=%v", status, err)
					return
				}
			}
		})
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	for i := 0; time.Now().Before(deadline); i++ {
		cur := srv.Limits()
		cur.MaxHeaderSize = 4096 + i%4096
		cur.IdleTimeout = time.Duration(60+i%60) * time.Second
		if err := srv.SetLimits(cur); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}
