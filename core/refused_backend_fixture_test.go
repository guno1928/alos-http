//go:build linux && amd64

package core

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

type refusedFixtureFactory struct {
	name string
	addr func(*testing.T) string
}

func refusedFixtureFactories() []refusedFixtureFactory {
	return []refusedFixtureFactory{
		{"outlier", closedBackendAddr},
		{"retry", func(t *testing.T) string { return startRetryOrigin(t, "refused").addr }},
		{"health", freeAddr},
		{"lifecycle", proxyFixRefusedAddr},
	}
}

func assertRefusedFixtureReservation(t *testing.T, addr string) {
	t.Helper()
	endpoint, err := netip.ParseAddrPort(addr)
	if err != nil || !endpoint.Addr().Is4() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 {
		t.Fatalf("invalid loopback reservation %q: %v", addr, err)
	}
	assertRefusedFixtureConnect(t, addr)
	wildcard := netip.AddrPortFrom(netip.IPv4Unspecified(), endpoint.Port()).String()
	for _, target := range []string{addr, wildcard} {
		competitor, err := net.Listen("tcp4", target)
		if competitor != nil {
			if closeErr := competitor.Close(); closeErr != nil {
				t.Error(closeErr)
			}
			t.Fatalf("refused fixture released %s: competitor bound %s", addr, target)
		}
		if !errors.Is(err, unix.EADDRINUSE) {
			t.Fatalf("competitor bind %s: %v, want EADDRINUSE", target, err)
		}
	}
	assertRefusedFixtureConnect(t, addr)
}

func assertRefusedFixtureConnect(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", addr, harnessIOTimeout)
	if conn != nil {
		if closeErr := conn.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatalf("refused fixture %s accepted a TCP connection", addr)
	}
	if !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("connect to %s: %v, want ECONNREFUSED", addr, err)
	}
}

func TestRefusedBackendFixtureReservesEveryFactory(t *testing.T) {
	for _, factory := range refusedFixtureFactories() {
		t.Run(factory.name, func(t *testing.T) {
			assertRefusedFixtureReservation(t, factory.addr(t))
		})
	}
}

func TestRefusedBackendFixtureCleanupReleasesEveryFactory(t *testing.T) {
	for _, factory := range refusedFixtureFactories() {
		t.Run(factory.name, func(t *testing.T) {
			var addr string
			if !t.Run("held", func(t *testing.T) {
				addr = factory.addr(t)
				assertRefusedFixtureReservation(t, addr)
			}) {
				return
			}
			listener, err := net.Listen("tcp4", addr)
			if err != nil {
				t.Fatalf("cleanup kept %s reserved: %v", addr, err)
			}
			t.Cleanup(func() {
				if err := listener.Close(); err != nil {
					t.Error(err)
				}
			})
			conn, err := net.DialTimeout("tcp4", addr, harnessIOTimeout)
			if err != nil {
				t.Fatalf("released address %s did not accept a connection: %v", addr, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func refusedLoopbackAddr(t *testing.T) string {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("create refused backend reservation: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Close(fd); err != nil {
			t.Errorf("close refused backend reservation: %v", err)
		}
	})
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind refused backend reservation: %v", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("inspect refused backend reservation: %v", err)
	}
	address, ok := bound.(*unix.SockaddrInet4)
	if !ok {
		t.Fatalf("refused backend address has type %T", bound)
	}
	return netip.AddrPortFrom(netip.AddrFrom4(address.Addr), uint16(address.Port)).String()
}

func TestRefusedBackendFixtureReservationsHaveIndependentLifetimes(t *testing.T) {
	outer := refusedLoopbackAddr(t)
	var inner string
	if !t.Run("inner", func(t *testing.T) {
		inner = refusedLoopbackAddr(t)
		if inner == outer {
			t.Fatal("two live refused fixtures share the same address")
		}
		assertRefusedFixtureReservation(t, outer)
		assertRefusedFixtureReservation(t, inner)
	}) {
		return
	}
	assertRefusedFixtureReservation(t, outer)
	listener, err := net.Listen("tcp4", inner)
	if err != nil {
		t.Fatalf("inner cleanup kept its address reserved: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
