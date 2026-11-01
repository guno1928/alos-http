//go:build linux && amd64

package core

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/guno1928/turbo"
)

const (
	h2IdleReapTimeout    = 150 * time.Millisecond
	h2IdleReapSlowHandle = 20 * time.Millisecond
	h2IdleReapCeiling    = 2*epollSweepIntervalMs*time.Millisecond + h2FixCeiling
)

func startH2IdleReapServer(t *testing.T, overTLS bool) string {
	return startH2FixServer(t, func(c *Config) {
		c.IdleTimeout = h2IdleReapTimeout
		c.ReadTimeout = h2IdleReapTimeout
		if overTLS {
			c.PlainHTTP = false
			c.Certs = []CertConfig{{Domain: h2FixAuthority, Source: CertSelfSigned}}
		}
	}, func(s *Server) {
		s.Router.GET("/", func(_ *Request, resp *Response) { resp.Status(200).String("root") })
		s.Router.GET("/fast", func(_ *Request, resp *Response) { resp.Status(200).String("fast") })
		s.Router.GET("/slow", func(_ *Request, resp *Response) {
			turbo.Sleep(h2IdleReapSlowHandle)
			resp.Status(200).String("slow")
		})
	})
}

func dialH2RawMaybeTLS(t *testing.T, addr string, overTLS bool) *h2RawConn {
	if !overTLS {
		return h2RawDial(t, addr, nil)
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: h2FixCeiling}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: h2FixAuthority, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	rc, _ := h2HandshakeCaptureSettings(t, conn)
	return rc
}

func (rc *h2RawConn) awaitStreamEnd(streamID uint32) {
	rc.t.Helper()
	for {
		f, err := rc.tryRead()
		if err != nil {
			rc.t.Fatalf("stream %d did not complete: %v", streamID, err)
		}
		if f.typ == H2FrameGoAway || f.typ == H2FrameRSTStream && f.streamID == streamID {
			rc.t.Fatalf("stream %d refused with frame type %d", streamID, f.typ)
		}
		if f.streamID == streamID && f.flags&H2FlagEndStream != 0 {
			return
		}
	}
}

func (rc *h2RawConn) closedByServerWithin(window time.Duration) (bool, error) {
	_ = rc.conn.SetReadDeadline(wallDeadline(window))
	for {
		if _, err := rc.tryRead(); err != nil {
			return h2FixConnClosed(err), err
		}
	}
}

func TestH2IdleConnectionReapedAfterServedRequest(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		partialFirst bool
		partialAfter bool
	}{
		{name: "no-request"},
		{name: "root-fast", path: "/"},
		{name: "inline", path: "/fast"},
		{name: "async", path: "/slow"},
		{name: "async-partial-frame-in-flight", path: "/slow", partialFirst: true},
		{name: "inline-partial-frame-after", path: "/fast", partialAfter: true},
	}
	for _, transport := range []string{"h2c", "tls"} {
		overTLS := transport == "tls"
		for _, tc := range cases {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				addr := startH2IdleReapServer(t, overTLS)
				rc := dialH2RawMaybeTLS(t, addr, overTLS)
				partial := []byte{0, 0, 8, H2FramePing}
				if tc.path != "" {
					h2FixGet(rc, 1, tc.path)
					if tc.partialFirst {
						rc.writeRaw(partial)
					}
					rc.awaitStreamEnd(1)
					if tc.partialAfter {
						rc.writeRaw(partial)
					}
				}
				start := turbo.Now()
				closed, err := rc.closedByServerWithin(h2IdleReapCeiling)
				if !closed {
					t.Fatalf("idle HTTP/2 connection still open %v after its last response (IdleTimeout=%v ReadTimeout=%v): %v",
						turbo.Since(start), h2IdleReapTimeout, h2IdleReapTimeout, err)
				}
			})
		}
	}
}
