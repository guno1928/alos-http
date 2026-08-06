//go:build linux && amd64

package core

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAppendH2SettingsFlightUsesConfig(t *testing.T) {
	s := New(Config{H2MaxConcurrentStreams: 111, H2InitialWindowSize: 200000, H2MaxFrameSize: 20000, H2HeaderTableSize: 16384})
	m := decodeH2Settings(appendH2ServerSettingsFlight(nil, s))
	if m[uint16(H2SettingHeaderTableSize)] != 16384 {
		t.Fatalf("flight header table = %d, want 16384", m[uint16(H2SettingHeaderTableSize)])
	}
	if m[uint16(H2SettingMaxConcurrentStreams)] != 111 {
		t.Fatalf("flight streams = %d, want 111", m[uint16(H2SettingMaxConcurrentStreams)])
	}
	if m[uint16(H2SettingInitialWindowSize)] != 200000 {
		t.Fatalf("flight window = %d, want 200000", m[uint16(H2SettingInitialWindowSize)])
	}
	if m[uint16(H2SettingMaxFrameSize)] != 20000 {
		t.Fatalf("flight frame = %d, want 20000", m[uint16(H2SettingMaxFrameSize)])
	}
}

func TestAppendH2SettingsFlightDefaults(t *testing.T) {
	m := decodeH2Settings(appendH2ServerSettingsFlight(nil, New(Config{})))
	if m[uint16(H2SettingMaxConcurrentStreams)] != uint32(H2MaxConcurrentStream) {
		t.Fatalf("default flight streams = %d", m[uint16(H2SettingMaxConcurrentStreams)])
	}
	if m[uint16(H2SettingMaxFrameSize)] != uint32(H2DefaultMaxFrameSize) {
		t.Fatalf("default flight frame = %d", m[uint16(H2SettingMaxFrameSize)])
	}
}

func TestEpollWorkerTimeoutConfigWiring(t *testing.T) {
	s := New(Config{
		ReadTimeout:       11 * time.Second,
		ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout:      7 * time.Second,
		IdleTimeout:       13 * time.Second,
		HandshakeTimeout:  5 * time.Second,
		MaxConnsPerIP:     -1,
	})
	w, err := newEpollWorker(s, "127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(w.listenerFD)
	defer unix.Close(w.epfd)
	defer unix.Close(w.wakeFd)
	if w.readTO != int64(11*time.Second) || w.headerTO != int64(3*time.Second) || w.writeTO != int64(7*time.Second) || w.idleTO != int64(13*time.Second) || w.handshakeTO != int64(5*time.Second) {
		t.Fatalf("worker timeouts = read:%v header:%v write:%v idle:%v handshake:%v", time.Duration(w.readTO), time.Duration(w.headerTO), time.Duration(w.writeTO), time.Duration(w.idleTO), time.Duration(w.handshakeTO))
	}
	plain := &epollConn{protocol: plainConnProtoH1}
	if got := w.nextReadTimeout(plain); got != int64(3*time.Second) {
		t.Fatalf("plain header timeout = %v", time.Duration(got))
	}
	plain.h1BodyAccounted = 1
	if got := w.nextReadTimeout(plain); got != int64(11*time.Second) {
		t.Fatalf("plain body timeout = %v", time.Duration(got))
	}
	tlsConn := &epollConn{tls: true, phase: tlsConnPhaseClientHello}
	if got := w.nextReadTimeout(tlsConn); got != int64(5*time.Second) {
		t.Fatalf("TLS handshake timeout = %v", time.Duration(got))
	}
}
