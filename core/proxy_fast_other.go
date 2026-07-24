//go:build !linux

package core

import "errors"

// StartFastProxy is unavailable on non-Linux platforms and always returns an
// error; the epoll-based fast reverse proxy requires Linux.
func StartFastProxy(listenAddr string, domains []DomainConfig, loops int) error {
	return errors.New("fast proxy requires linux")
}
