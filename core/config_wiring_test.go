package core

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type closeCaptureConn struct {
	closed bool
}

func (c *closeCaptureConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *closeCaptureConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *closeCaptureConn) Close() error                     { c.closed = true; return nil }
func (c *closeCaptureConn) LocalAddr() net.Addr              { return nil }
func (c *closeCaptureConn) RemoteAddr() net.Addr             { return nil }
func (c *closeCaptureConn) SetDeadline(time.Time) error      { return nil }
func (c *closeCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeCaptureConn) SetWriteDeadline(time.Time) error { return nil }

func TestConfigDisableHTTP2AllTCPEntryPoints(t *testing.T) {
	s := New(Config{DisableHTTP2: true, MaxConnsPerIP: -1})
	if s.http2Enabled() {
		t.Fatal("HTTP/2 should be disabled")
	}
	if got := s.tlsNextProtos(); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("TLS protocols = %v", got)
	}
	if got := s.negotiateALPN([]string{"h2", "http/1.1"}); got != "http/1.1" {
		t.Fatalf("ALPN = %q", got)
	}
	conn := &closeCaptureConn{}
	s.ServeH2Plain(conn)
	if !conn.closed {
		t.Fatal("plain HTTP/2 entry point did not close the connection")
	}
}

func TestConfigH2HeaderTableSizeWired(t *testing.T) {
	def := New(Config{MaxConnsPerIP: -1})
	if got := def.h2HeaderTableSize(); got != H2HeaderTableSize {
		t.Fatalf("default table size = %d", got)
	}
	custom := New(Config{H2HeaderTableSize: 16384, MaxConnsPerIP: -1})
	if got := custom.h2HeaderTableSize(); got != 16384 {
		t.Fatalf("custom table size = %d", got)
	}
	settings := decodeH2Settings(appendH2ServerSettingsFlight(nil, custom))
	if got := settings[uint16(H2SettingHeaderTableSize)]; got != 16384 {
		t.Fatalf("advertised table size = %d", got)
	}
	decoder := newHpackDecoder(custom.h2HeaderTableSize())
	if decoder.maxTableSize != 16384 || decoder.protocolMaxSize != 16384 {
		t.Fatalf("decoder limits = %d/%d", decoder.maxTableSize, decoder.protocolMaxSize)
	}
}

func TestConfigH2ProtocolValueValidation(t *testing.T) {
	if got := New(Config{H2InitialWindowSize: 1<<31 + 100, MaxConnsPerIP: -1}).h2InitialWindow(); got != 1<<31-1 {
		t.Fatalf("initial window = %d", got)
	}
	for _, value := range []uint32{1, H2MaxFrameSize + 1} {
		if got := New(Config{H2MaxFrameSize: value, MaxConnsPerIP: -1}).h2MaxFrameSize(); got != H2DefaultMaxFrameSize {
			t.Fatalf("frame size for %d = %d", value, got)
		}
	}
	if got := New(Config{H2MaxFrameSize: 32768, MaxConnsPerIP: -1}).h2MaxFrameSize(); got != 32768 {
		t.Fatalf("valid frame size = %d", got)
	}
}

func TestConfiguredH2HeaderTableRetainsAllEntriesWithinByteLimit(t *testing.T) {
	decoder := newHpackDecoder(16384)
	for i := 0; i < 300; i++ {
		decoder.addEntry("x", "v")
	}
	if decoder.dynLen != 300 {
		t.Fatalf("dynamic entries = %d, want 300", decoder.dynLen)
	}
}

func TestConfigReadHeaderTimeoutResolution(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want time.Duration
	}{
		{"read-fallback", Config{ReadTimeout: 7 * time.Second}, 7 * time.Second},
		{"custom", Config{ReadTimeout: 7 * time.Second, ReadHeaderTimeout: 2 * time.Second}, 2 * time.Second},
		{"disabled", Config{ReadHeaderTimeout: -1}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.MaxConnsPerIP = -1
			if got := New(tc.cfg).readHeaderTimeout(); got != tc.want {
				t.Fatalf("timeout = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfigOptionalWebSocketTimeouts(t *testing.T) {
	if got := optionalDuration(0, wsDefaultReadTimeout); got != wsDefaultReadTimeout {
		t.Fatalf("default = %v", got)
	}
	if got := optionalDuration(-1, wsDefaultReadTimeout); got != 0 {
		t.Fatalf("disabled = %v", got)
	}
	if got := optionalDuration(3*time.Second, wsDefaultReadTimeout); got != 3*time.Second {
		t.Fatalf("custom = %v", got)
	}
}

func TestConfigShutdownTimeoutBoundsBackgroundContext(t *testing.T) {
	s := New(Config{ShutdownTimeout: 15 * time.Millisecond, MaxConnsPerIP: -1})
	s.activeConns.Store(1)
	started := time.Now()
	err := s.Shutdown(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown error = %v", err)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("Shutdown elapsed = %v", elapsed)
	}
}

func TestConfigMaxConnsExactAndUnlimited(t *testing.T) {
	limited := New(Config{MaxConns: 2, MaxConnsPerIP: -1})
	if !limited.tryTrackConn() || !limited.tryTrackConn() {
		t.Fatal("configured connection slots were not admitted")
	}
	if limited.tryTrackConn() {
		t.Fatal("connection above configured maximum was admitted")
	}
	limited.releaseTrackedConn()
	limited.releaseTrackedConn()

	unlimited := New(Config{MaxConns: -1, MaxConnsPerIP: -1})
	for i := 0; i < 100000; i++ {
		if !unlimited.tryTrackConn() {
			t.Fatalf("unlimited MaxConns rejected slot %d", i)
		}
	}
	if got := unlimited.activeConns.Load(); got != 100000 {
		t.Fatalf("active connections = %d", got)
	}
}

func BenchmarkConfiguredH2HeaderTable(b *testing.B) {
	for i := 0; i < b.N; i++ {
		decoder := newHpackDecoder(16384)
		for j := 0; j < 300; j++ {
			decoder.addEntry("x", "v")
		}
	}
}

func BenchmarkDefaultH2HeaderTable(b *testing.B) {
	for i := 0; i < b.N; i++ {
		decoder := newHpackDecoder(H2HeaderTableSize)
		for j := 0; j < 100; j++ {
			decoder.addEntry("x", "v")
		}
	}
}
