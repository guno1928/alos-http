//go:build linux

package core

import (
	"log"

	"golang.org/x/sys/unix"
)

func maybeRaiseProcessFileLimit() {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	target := lim.Max
	if target == 0 {
		return
	}
	if target == unix.RLIM_INFINITY || target > 1_048_576 {
		target = 1_048_576
	}
	if target <= lim.Cur {
		return
	}
	next := unix.Rlimit{Cur: target, Max: lim.Max}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &next); err != nil {
		return
	}
	log.Printf("[INFO] raised RLIMIT_NOFILE soft limit to %d (hard=%d)", target, lim.Max)
}
