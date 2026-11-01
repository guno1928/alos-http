//go:build linux && amd64

package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

const (
	startupProbeTimeout   = 2 * time.Second
	startupPollInterval   = 15 * time.Millisecond
	lateFailureChildEnv   = "ALOS_TLS_LATE_FAILURE_CHILD"
	lateFailureClosedMark = "LATE_FAILURE_REDIRECT_CLOSED"
)

type startupHookHandler struct {
	hooks map[string]func()
}

func (h *startupHookHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *startupHookHandler) Handle(_ context.Context, r slog.Record) error {
	if hook := h.hooks[r.Message]; hook != nil {
		hook()
	}
	return nil
}

func (h *startupHookHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *startupHookHandler) WithGroup(string) slog.Handler      { return h }

func startupTestConfig(addr, httpAddr string, hooks map[string]func()) Config {
	return Config{
		Addr:          addr,
		HTTPAddr:      httpAddr,
		Listeners:     1,
		MaxConnsPerIP: -1,
		Certs:         []CertConfig{{Domain: "localhost", Source: CertSelfSigned}},
		Logger:        slog.New(&startupHookHandler{hooks: hooks}),
	}
}

func startupHandshake(addr string) error {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: startupProbeTimeout},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupProbeTimeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

func TestHTTPSListeningLoggedOnlyWhenServing(t *testing.T) {
	addr := freeLoopbackAddr(t)
	handshakeErr := make(chan error, 1)
	srv := New(startupTestConfig(addr, "-", map[string]func(){
		"HTTPS listening": func() { handshakeErr <- startupHandshake(addr) },
	}))
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServeTLS() }()
	t.Cleanup(func() { stopServer(srv) })
	select {
	case err := <-handshakeErr:
		if err != nil {
			t.Fatalf("handshake at the moment HTTPS listening was logged failed: %v", err)
		}
	case err := <-served:
		t.Fatalf("ListenAndServeTLS returned before logging HTTPS listening: %v", err)
	case <-time.After(3 * startupProbeTimeout):
		t.Fatal("HTTPS listening was never logged")
	}
}

func TestHTTPSPortHeldThroughTLSStartup(t *testing.T) {
	addr := freeLoopbackAddr(t)
	httpAddr := freeLoopbackAddr(t)
	stealErr := make(chan error, 1)
	srv := New(startupTestConfig(addr, httpAddr, map[string]func(){
		"HTTP redirect listening": func() {
			ln, err := net.Listen("tcp4", addr)
			if err == nil {
				_ = ln.Close()
				stealErr <- errors.New("HTTPS port was free while the redirect listener started")
				return
			}
			conn, err := net.DialTimeout("tcp4", addr, startupProbeTimeout)
			if err == nil {
				_ = conn.Close()
				stealErr <- errors.New("HTTPS port accepted TCP before the TLS runtime was ready")
				return
			}
			stealErr <- nil
		},
	}))
	served := make(chan error, 1)
	go func() { served <- srv.ListenAndServeTLS() }()
	t.Cleanup(func() { stopServer(srv) })
	select {
	case err := <-stealErr:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-served:
		t.Fatalf("ListenAndServeTLS returned during startup: %v", err)
	case <-time.After(3 * startupProbeTimeout):
		t.Fatal("redirect listener never started")
	}
	waitForProxy(t, addr)
	if err := startupHandshake(addr); err != nil {
		t.Fatalf("server not serving after startup: %v", err)
	}
}

func TestTLSStartupLateFailureReleasesResources(t *testing.T) {
	if listeners, err := strconv.Atoi(os.Getenv(lateFailureChildEnv)); err == nil {
		runLateFailureChild(t, listeners)
		return
	}
	for _, listeners := range []int{1, 2} {
		t.Run("listeners="+strconv.Itoa(listeners), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTLSStartupLateFailureReleasesResources$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), lateFailureChildEnv+"="+strconv.Itoa(listeners))
			out, err := cmd.CombinedOutput()
			if err != nil || !bytes.Contains(out, []byte(lateFailureClosedMark)) {
				t.Fatalf("late startup failure left resources running (err=%v):\n%s", err, out)
			}
		})
	}
}

func runLateFailureChild(t *testing.T, listeners int) {
	addr := freeLoopbackAddr(t)
	httpAddr := freeLoopbackAddr(t)
	cfg := startupTestConfig(addr, httpAddr, nil)
	cfg.Listeners = listeners
	srv := New(cfg)
	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &original); err != nil {
		t.Fatal(err)
	}
	limit := fdLimitLeavingFreeSlots(t, 4*listeners-2)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: limit, Max: limit}); err != nil {
		t.Skipf("cannot lower RLIMIT_NOFILE: %v", err)
	}
	err := srv.ListenAndServeTLS()
	if restoreErr := unix.Setrlimit(unix.RLIMIT_NOFILE, &original); restoreErr != nil {
		t.Fatalf("restore RLIMIT_NOFILE: %v", restoreErr)
	}
	if err == nil {
		t.Fatal("ListenAndServeTLS succeeded without enough descriptors for its epoll workers")
	}
	t.Logf("startup failed as intended: %v", err)
	for name, target := range map[string]string{"redirect": httpAddr, "HTTPS": addr} {
		deadline := wallNow().Add(startupProbeTimeout)
		for {
			conn, dialErr := net.DialTimeout("tcp4", target, startupPollInterval)
			if errors.Is(dialErr, unix.ECONNREFUSED) {
				break
			}
			if conn != nil {
				_ = conn.Close()
			}
			if wallNow().After(deadline) {
				t.Fatalf("%s listener still accepting after the failed start (last dial error %v)", name, dialErr)
			}
			turbo.Sleep(startupPollInterval)
		}
	}
	if !srv.doneClosed() {
		t.Fatal("server not shut down after the failed start")
	}
	if srv.x25519Pool != nil {
		select {
		case <-srv.x25519Pool.stop:
		case <-time.After(startupProbeTimeout):
			t.Fatal("x25519 key pool still running after the failed start")
		}
	}
	t.Log(lateFailureClosedMark)
}

func fdLimitLeavingFreeSlots(t *testing.T, free int) uint64 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	dirFD := int(dir.Fd())
	names, err := dir.Readdirnames(-1)
	_ = dir.Close()
	if err != nil {
		t.Fatal(err)
	}
	open := make(map[int]bool, len(names))
	for _, name := range names {
		if fd, convErr := strconv.Atoi(name); convErr == nil && fd != dirFD {
			open[fd] = true
		}
	}
	fd := 0
	for ; free > 0; fd++ {
		if !open[fd] {
			free--
		}
	}
	return uint64(fd)
}

func TestShutdownDuringTLSStartupIsRaceFree(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Millisecond, 5 * time.Millisecond, 25 * time.Millisecond} {
		srv := New(startupTestConfig(freeLoopbackAddr(t), "-", nil))
		served := make(chan error, 1)
		go func() { served <- srv.ListenAndServeTLS() }()
		turbo.Sleep(delay)
		stopServer(srv)
		select {
		case err := <-served:
			if err != nil {
				t.Fatalf("delay %v: ListenAndServeTLS after Shutdown: %v", delay, err)
			}
		case <-time.After(3 * startupProbeTimeout):
			t.Fatalf("delay %v: ListenAndServeTLS did not return after Shutdown", delay)
		}
	}
}
