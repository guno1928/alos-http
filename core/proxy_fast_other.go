//go:build !linux

package core

import "errors"

func StartFastProxy(listenAddr string, domains []DomainConfig, loops int) error {
	return errors.New("fast proxy requires linux")
}
