//go:build !linux

package core

import "os"

func trySendFileFastPath(sw StreamWriter, file *os.File, size int64, limiter *TokenBucket) (bool, error) {
	return false, nil
}