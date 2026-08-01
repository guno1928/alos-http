//go:build linux && amd64

package core

import (
	"testing"

	"golang.org/x/sys/unix"
)

// The unified proxy engine puts backend sockets in the same epoll set as client
// sockets and tells them apart by a class tag carried in EpollEvent.Pad. On
// linux/amd64 the kernel's epoll_event holds a 64-bit opaque data field that Go
// splits into Fd and Pad, so the kernel must echo Pad back untouched. Every
// dispatch decision depends on that, so it is asserted rather than assumed.
func TestEpollEventPadRoundTrips(t *testing.T) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create1: %v", err)
	}
	defer unix.Close(epfd)

	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	readFD, writeFD := pipeFDs[0], pipeFDs[1]
	defer unix.Close(readFD)
	defer unix.Close(writeFD)

	const addTag = 0x5A5A5A5A
	add := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(readFD), Pad: addTag}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, readFD, &add); err != nil {
		t.Fatalf("epoll_ctl add: %v", err)
	}

	if _, err := unix.Write(writeFD, []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	events := make([]unix.EpollEvent, 8)
	n, err := unix.EpollWait(epfd, events, 1000)
	if err != nil {
		t.Fatalf("epoll_wait: %v", err)
	}
	if n != 1 {
		t.Fatalf("epoll_wait returned %d events, want 1", n)
	}
	if got := int(events[0].Fd); got != readFD {
		t.Fatalf("Fd = %d, want %d", got, readFD)
	}
	if events[0].Pad != addTag {
		t.Fatalf("Pad after EPOLL_CTL_ADD = %#x, want %#x", events[0].Pad, addTag)
	}

	// The tag must also survive rearming, which the backpressure path does on
	// every pause/resume of a backend read.
	const modTag = 0x0BADF00D
	drain := make([]byte, 8)
	if _, err := unix.Read(readFD, drain); err != nil {
		t.Fatalf("drain read: %v", err)
	}
	mod := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(readFD), Pad: modTag}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_MOD, readFD, &mod); err != nil {
		t.Fatalf("epoll_ctl mod: %v", err)
	}
	if _, err := unix.Write(writeFD, []byte("y")); err != nil {
		t.Fatalf("write after mod: %v", err)
	}
	n, err = unix.EpollWait(epfd, events, 1000)
	if err != nil {
		t.Fatalf("epoll_wait after mod: %v", err)
	}
	if n != 1 {
		t.Fatalf("epoll_wait after mod returned %d events, want 1", n)
	}
	if events[0].Pad != modTag {
		t.Fatalf("Pad after EPOLL_CTL_MOD = %#x, want %#x", events[0].Pad, modTag)
	}
}

// A zero Pad is the client-connection class, so the existing EPOLL_CTL_ADD call
// sites that never set it must keep reporting zero.
func TestEpollEventPadDefaultsToZero(t *testing.T) {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatalf("epoll_create1: %v", err)
	}
	defer unix.Close(epfd)

	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("pipe2: %v", err)
	}
	defer unix.Close(pipeFDs[0])
	defer unix.Close(pipeFDs[1])

	ev := unix.EpollEvent{Events: unix.EPOLLIN | unix.EPOLLET, Fd: int32(pipeFDs[0])}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, pipeFDs[0], &ev); err != nil {
		t.Fatalf("epoll_ctl add: %v", err)
	}
	if _, err := unix.Write(pipeFDs[1], []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	events := make([]unix.EpollEvent, 8)
	n, err := unix.EpollWait(epfd, events, 1000)
	if err != nil {
		t.Fatalf("epoll_wait: %v", err)
	}
	if n != 1 {
		t.Fatalf("epoll_wait returned %d events, want 1", n)
	}
	if events[0].Pad != 0 {
		t.Fatalf("Pad = %#x for an untagged registration, want 0", events[0].Pad)
	}
}
