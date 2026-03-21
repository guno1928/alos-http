//go:build !linux || !amd64

package core

func logIOUringStartupProbe() {}

func IOUringStartupProbeReport() string {
	return "[INFO] io_uring startup probe\n[INFO]   status                   unsupported on this build (requires linux/amd64)"
}
