//go:build linux && amd64

package core

import "testing"

// shouldUseZeroCopySend gates the SEND_ZC path. It must only return true for
// closeAfter responses at or above the ZC threshold, because the kernel keeps a
// reference to writeBuf until the F_NOTIF notification CQE. The handleWrite
// close-on-zcPending guard relies on ZC implying closeAfter, so this contract
// is load-bearing for the use-after-submit fix (H1).
func TestShouldUseZeroCopySend(t *testing.T) {
	// sendZCState == 1 marks SEND_ZC as supported without touching a kernel,
	// so canUseSendZC short-circuits and the decision logic is exercised pure.
	worker := &tlsUringWorker{ring: &ioUring{sendZCState: 1}}

	cases := []struct {
		name       string
		closeAfter bool
		writeN     int
		want       bool
	}{
		{"close and large", true, ioUringSendZCThreshold, true},
		{"close but below threshold", true, ioUringSendZCThreshold - 1, false},
		{"keepalive large", false, ioUringSendZCThreshold, false},
		{"keepalive below threshold", false, ioUringSendZCThreshold - 1, false},
		{"empty write", true, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &tlsWorkerConn{closeAfter: tc.closeAfter, writeN: tc.writeN}
			if got := worker.shouldUseZeroCopySend(conn); got != tc.want {
				t.Fatalf("shouldUseZeroCopySend(closeAfter=%v writeN=%d) = %v, want %v",
					tc.closeAfter, tc.writeN, got, tc.want)
			}
		})
	}
}

// When SEND_ZC is unsupported the path must never be selected regardless of
// response size, so the buffer is reused only on the safe blocking-send path.
func TestShouldUseZeroCopySendUnsupported(t *testing.T) {
	worker := &tlsUringWorker{ring: &ioUring{sendZCState: 2}}
	conn := &tlsWorkerConn{closeAfter: true, writeN: ioUringSendZCThreshold}
	if worker.shouldUseZeroCopySend(conn) {
		t.Fatal("shouldUseZeroCopySend must be false when SEND_ZC is unsupported")
	}
}
