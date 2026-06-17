//go:build linux && amd64

package core

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ioUringFeatNoDrop         = 1 << 1
	ioUringFeatSubmitStable   = 1 << 2
	ioUringFeatRWCurPos       = 1 << 3
	ioUringFeatCurPersonality = 1 << 4
	ioUringFeatFastPoll       = 1 << 5
	ioUringFeatPoll32Bits     = 1 << 6
	ioUringFeatSQPollNonfixed = 1 << 7
	ioUringFeatExtArg         = 1 << 8
	ioUringFeatNativeWorkers  = 1 << 9
	ioUringFeatRsrcTags       = 1 << 10
	ioUringFeatCQESkip        = 1 << 11
	ioUringFeatLinkedFile     = 1 << 12
)

type ioUringStartupProbeResult struct {
	available              bool
	availableErr           error
	activeSetupFlags       uint32
	kernelFeatures         uint32
	preferredOwnerFlagsOK  bool
	preferredOwnerFlagsErr error
	sendZCOK               bool
	sendZCErr              error
	multishotAcceptOK      bool
	multishotAcceptErr     error
	providedBufRingOK      bool
	providedBufRingErr     error
	multishotRecvOK        bool
	multishotRecvErr       error
}

type ioUringProbeCheck struct {
	label   string
	request string
	ok      bool
	err     error
	yesText string
	noText  string
}

type ioUringCapabilityProbe struct {
	ok  bool
	err error
}

var (
	ioUringStartupProbeOnce sync.Once
	ioUringStartupProbe     ioUringStartupProbeResult
)

func logIOUringStartupProbe() {
	if !debugFlag.Load() {
		return
	}
	for _, line := range ioUringStartupProbeLines(getIOUringStartupProbe()) {
		log.Print(line)
	}
}

func IOUringStartupProbeReport() string {
	return strings.Join(ioUringStartupProbeLines(getIOUringStartupProbe()), "\n")
}

func getIOUringStartupProbe() ioUringStartupProbeResult {
	ioUringStartupProbeOnce.Do(func() {
		ioUringStartupProbe = runIOUringStartupProbe()
	})
	return ioUringStartupProbe
}

func runIOUringStartupProbe() ioUringStartupProbeResult {
	result := ioUringStartupProbeResult{}

	ring, err := newOwnedIOUring(8)
	if err != nil {
		result.availableErr = err
		return result
	}
	result.available = true
	result.activeSetupFlags = ring.flags
	result.kernelFeatures = ring.features
	ring.close()

	const preferredOwnerFlags = ioUringSetupCoopTaskrun |
		ioUringSetupTaskrunFlag |
		ioUringSetupSubmitAll |
		ioUringSetupSingleIssuer |
		ioUringSetupDeferTaskrun
	if probeRing, err := newIOUringConfigured(8, preferredOwnerFlags); err == nil {
		result.preferredOwnerFlagsOK = true
		probeRing.close()
	} else {
		result.preferredOwnerFlagsErr = err
	}

	sendZC := probeIOUringSendZCDetailed()
	result.sendZCOK = sendZC.ok
	result.sendZCErr = sendZC.err

	multishotAccept := probeIOUringMultishotAcceptDetailed()
	result.multishotAcceptOK = multishotAccept.ok
	result.multishotAcceptErr = multishotAccept.err

	providedBufRing := probeIOUringProvidedBufferRingDetailed()
	result.providedBufRingOK = providedBufRing.ok
	result.providedBufRingErr = providedBufRing.err

	multishotRecv := probeIOUringRecvMultishotDetailed()
	result.multishotRecvOK = multishotRecv.ok
	result.multishotRecvErr = multishotRecv.err

	return result
}

func logIOUringStartupProbeResult(result ioUringStartupProbeResult) {
	if !debugFlag.Load() {
		return
	}
	for _, line := range ioUringStartupProbeLines(result) {
		log.Print(line)
	}
}

func ioUringStartupProbeLines(result ioUringStartupProbeResult) []string {
	lines := []string{"[INFO] io_uring startup probe"}
	if !result.available {
		lines = append(lines,
			formatProbeLine("status", "unavailable"),
			formatProbeLine("error", formatProbeError(result.availableErr)),
		)
		return lines
	}

	lines = append(lines,
		formatProbeLine("setup", "active-flags="+formatIOUringSetupFlags(result.activeSetupFlags)),
		formatProbeLine("setup", "kernel-features="+formatIOUringFeatures(result.kernelFeatures)),
	)

	lines = append(lines, formatProbeLine("summary", fmt.Sprintf(
		"preferred-owner-flags=%s, send-zc=%s, multishot-accept=%s, provided-buf-ring=%s, multishot-recv=%s",
		formatProbeSummaryStatus(result.preferredOwnerFlagsOK, result.preferredOwnerFlagsErr, "supported", "unsupported"),
		formatProbeSummaryStatus(result.sendZCOK, result.sendZCErr, "active", "disabled"),
		formatProbeSummaryStatus(result.multishotAcceptOK, result.multishotAcceptErr, "active", "one-shot accept fallback"),
		formatProbeSummaryStatus(result.providedBufRingOK, result.providedBufRingErr, "active", "disabled"),
		formatProbeSummaryStatus(result.multishotRecvOK, result.multishotRecvErr, "active", "classic recv fallback"),
	)))

	checks := []ioUringProbeCheck{
		{
			label:   "preferred owner flags",
			request: "io_uring_setup flags=SUBMIT_ALL|COOP_TASKRUN|TASKRUN_FLAG|SINGLE_ISSUER|DEFER_TASKRUN",
			ok:      result.preferredOwnerFlagsOK,
			err:     result.preferredOwnerFlagsErr,
			yesText: "supported",
			noText:  "unsupported",
		},
		{
			label:   "send_zc",
			request: "IORING_OP_SEND_ZC on tcp4 loopback with accepted socket preparation",
			ok:      result.sendZCOK,
			err:     result.sendZCErr,
			yesText: "active",
			noText:  "disabled",
		},
		{
			label:   "multishot accept",
			request: "IORING_OP_ACCEPT + ACCEPT_MULTISHOT + SOCK_CLOEXEC|SOCK_NONBLOCK (tcp4 loopback listener)",
			ok:      result.multishotAcceptOK,
			err:     result.multishotAcceptErr,
			yesText: "active",
			noText:  "fallback -> one-shot accept",
		},
		{
			label:   "provided buffer ring",
			request: "IORING_REGISTER_PBUF_RING entries=8 buf-size=2048 bgid=1",
			ok:      result.providedBufRingOK,
			err:     result.providedBufRingErr,
			yesText: "active",
			noText:  "disabled",
		},
		{
			label:   "multishot recv",
			request: "IORING_OP_RECV + RECV_MULTISHOT + BUFFER_SELECT bgid=1 (unix socketpair)",
			ok:      result.multishotRecvOK,
			err:     result.multishotRecvErr,
			yesText: "active",
			noText:  "fallback -> classic recv",
		},
	}
	for _, check := range checks {
		lines = append(lines, formatIOUringProbeCheckLines(check)...)
	}

	return lines
}

func formatProbeStatus(ok bool, err error, yesText string, noText string) string {
	if ok {
		return yesText
	}
	if err == nil {
		return noText
	}
	return fmt.Sprintf("%s (%v)", noText, err)
}

func formatProbeSummaryStatus(ok bool, err error, yesText string, noText string) string {
	if ok {
		return yesText
	}
	if errno, ok := ioUringProbeErrno(err); ok {
		return fmt.Sprintf("%s [%s]", noText, formatIOUringErrnoName(errno))
	}
	if err == nil {
		return noText
	}
	return fmt.Sprintf("%s [%v]", noText, err)
}

func formatIOUringProbeCheckLines(check ioUringProbeCheck) []string {
	lines := []string{
		formatProbeLine(check.label, formatProbeState(check.ok, check.yesText, check.noText)),
		formatProbeDetailLine("request", check.request),
	}
	if check.err == nil {
		return lines
	}
	lines = append(lines, formatProbeDetailLine("kernel reply", formatProbeError(check.err)))
	if note := formatProbeNote(check.label, check.err); note != "" {
		lines = append(lines, formatProbeDetailLine("note", note))
	}
	return lines
}

func formatProbeState(ok bool, yesText string, noText string) string {
	if ok {
		return yesText
	}
	return noText
}

func formatProbeLine(label string, value string) string {
	return fmt.Sprintf("[INFO]   %-24s %s", label, value)
}

func formatProbeDetailLine(label string, value string) string {
	return fmt.Sprintf("[INFO]     %-22s %s", label, value)
}

func formatProbeError(err error) string {
	if err == nil {
		return "none"
	}
	if errno, ok := ioUringProbeErrno(err); ok {
		return fmt.Sprintf("%s (%s)", formatIOUringErrnoName(errno), errno.Error())
	}
	return err.Error()
}

func formatProbeNote(label string, err error) string {
	errno, ok := ioUringProbeErrno(err)
	if !ok {
		return ""
	}
	switch errno {
	case syscall.ENOSYS:
		switch label {
		case "provided buffer ring":
			return "kernel does not implement provided buffer rings on this build"
		case "multishot accept":
			return "kernel does not implement multishot accept on this build"
		case "multishot recv":
			return "kernel does not implement multishot recv on this build"
		default:
			return "kernel does not implement the requested io_uring setup/feature"
		}
	case syscall.EINVAL:
		switch label {
		case "preferred owner flags":
			return "kernel rejected one or more requested io_uring setup flags"
		case "send_zc":
			return "kernel/runtime rejected the zero-copy send request shape on this machine"
		case "provided buffer ring":
			return "kernel rejected the provided buffer ring registration request"
		case "multishot accept":
			return "kernel rejected the multishot accept request shape"
		case "multishot recv":
			return "kernel rejected multishot recv or its provided-buffer setup"
		}
	case syscall.EOPNOTSUPP:
		if label == "send_zc" {
			return "protocol or kernel configuration does not support zero-copy send here"
		}
	}
	return ""
}

func ioUringProbeErrno(err error) (syscall.Errno, bool) {
	if err == nil {
		return 0, false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno, true
	}
	return 0, false
}

func formatIOUringErrnoName(errno syscall.Errno) string {
	switch errno {
	case syscall.EINVAL:
		return "EINVAL"
	case syscall.ENOSYS:
		return "ENOSYS"
	case syscall.EPERM:
		return "EPERM"
	case syscall.EOPNOTSUPP:
		return "EOPNOTSUPP"
	case syscall.ENOBUFS:
		return "ENOBUFS"
	default:
		return fmt.Sprintf("errno=%d", int(errno))
	}
}

func isIOUringUnsupportedProbeErr(err error) bool {
	errno, ok := ioUringProbeErrno(err)
	if !ok {
		return false
	}
	return errors.Is(errno, syscall.EINVAL) || errors.Is(errno, syscall.ENOSYS)
}

func formatIOUringSetupFlags(flags uint32) string {
	parts := make([]string, 0, 8)
	appendFlag := func(bit uint32, name string) {
		if flags&bit != 0 {
			parts = append(parts, name)
		}
	}
	appendFlag(ioUringSetupRDisabled, "R_DISABLED")
	appendFlag(ioUringSetupSubmitAll, "SUBMIT_ALL")
	appendFlag(ioUringSetupCoopTaskrun, "COOP_TASKRUN")
	appendFlag(ioUringSetupTaskrunFlag, "TASKRUN_FLAG")
	appendFlag(ioUringSetupSingleIssuer, "SINGLE_ISSUER")
	appendFlag(ioUringSetupDeferTaskrun, "DEFER_TASKRUN")
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func formatIOUringFeatures(features uint32) string {
	parts := make([]string, 0, 12)
	appendFeature := func(bit uint32, name string) {
		if features&bit != 0 {
			parts = append(parts, name)
		}
	}
	appendFeature(ioUringFeatSingleMmap, "SINGLE_MMAP")
	appendFeature(ioUringFeatNoDrop, "NODROP")
	appendFeature(ioUringFeatSubmitStable, "SUBMIT_STABLE")
	appendFeature(ioUringFeatRWCurPos, "RW_CUR_POS")
	appendFeature(ioUringFeatCurPersonality, "CUR_PERSONALITY")
	appendFeature(ioUringFeatFastPoll, "FAST_POLL")
	appendFeature(ioUringFeatPoll32Bits, "POLL_32BITS")
	appendFeature(ioUringFeatSQPollNonfixed, "SQPOLL_NONFIXED")
	appendFeature(ioUringFeatExtArg, "EXT_ARG")
	appendFeature(ioUringFeatNativeWorkers, "NATIVE_WORKERS")
	appendFeature(ioUringFeatRsrcTags, "RSRC_TAGS")
	appendFeature(ioUringFeatCQESkip, "CQE_SKIP")
	appendFeature(ioUringFeatLinkedFile, "LINKED_FILE")
	appendFeature(ioUringFeatRegRegRing, "REG_REG_RING")
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func probeIOUringProvidedBufferRingDetailed() ioUringCapabilityProbe {
	ring, err := newOwnedIOUring(8)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer ring.close()
	if err := ring.enable(); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	bufs, err := newIOUringBufferRing(8, 2048, 1)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer bufs.close()
	if err := bufs.register(ring); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer bufs.unregister(ring)
	return ioUringCapabilityProbe{ok: true}
}

func probeIOUringRecvMultishot() (bool, error) {
	result := probeIOUringRecvMultishotDetailed()
	if isIOUringUnsupportedProbeErr(result.err) {
		return false, nil
	}
	return result.ok, result.err
}

func probeIOUringRecvMultishotDetailed() ioUringCapabilityProbe {
	ring, err := newOwnedIOUring(8)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer ring.close()
	if err := ring.enable(); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	bufs, err := newIOUringBufferRing(8, 2048, 1)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer bufs.close()
	if err := bufs.register(ring); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer bufs.unregister(ring)
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	if err := ring.prepRecvMultishotUser(fds[0], bufs.bgid, 1, false, false); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if _, err := ring.submitAndWait(0); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if _, err := syscall.Write(fds[1], []byte{1}); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if _, err := ring.submitAndWait(1); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	cqe, err := ring.waitCqe()
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if cqe.Res < 0 {
		errno := syscall.Errno(-cqe.Res)
		return ioUringCapabilityProbe{err: errno}
	}
	if cqe.Flags&ioUringCqeBuffer != 0 {
		bufs.recycle(cqeBufferID(cqe.Flags))
	}
	return ioUringCapabilityProbe{ok: true}
}

func probeIOUringTLSRecvPathDetailed(workers int) ioUringCapabilityProbe {
	if workers < 1 {
		workers = 1
	}
	for workerID := 0; workerID < workers; workerID++ {
		ring, err := newOwnedIOUring(tlsWorkerRingEntries)
		if err != nil {
			return ioUringCapabilityProbe{err: err}
		}
		bufs, err := newIOUringBufferRing(tlsRecvBufRingSize, tlsRecvBufSize, uint16(workerID+1))
		if err != nil {
			ring.close()
			return ioUringCapabilityProbe{err: err}
		}
		if err := ring.enable(); err != nil {
			bufs.close()
			ring.close()
			return ioUringCapabilityProbe{err: err}
		}
		if err := bufs.register(ring); err != nil {
			bufs.close()
			ring.close()
			return ioUringCapabilityProbe{err: err}
		}
		_ = bufs.unregister(ring)
		bufs.close()
		ring.close()
	}
	return ioUringCapabilityProbe{ok: true}
}

func probeIOUringSendZCDetailed() ioUringCapabilityProbe {
	ring, err := newOwnedIOUring(16)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer ring.close()
	if err := ring.enable(); err != nil {
		return ioUringCapabilityProbe{err: err}
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer listener.Close()

	payloadSize := ioUringSendZCThreshold
	if payloadSize < 64<<10 {
		payloadSize = 64 << 10
	}
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	readDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			readDone <- acceptErr
			return
		}
		defer conn.Close()
		prepareAcceptedConn(conn)
		_, copyErr := io.Copy(io.Discard, io.LimitReader(conn, int64(len(payload))))
		readDone <- copyErr
	}()

	clientConn, err := net.DialTimeout("tcp4", listener.Addr().String(), 500*time.Millisecond)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer clientConn.Close()
	prepareAcceptedConn(clientConn)

	tcpConn, ok := clientConn.(*net.TCPConn)
	if !ok {
		return ioUringCapabilityProbe{err: fmt.Errorf("unexpected client conn type %T", clientConn)}
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	fd := -1
	if err := raw.Control(func(value uintptr) {
		fd = int(value)
	}); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if fd < 0 {
		return ioUringCapabilityProbe{err: errors.New("tcp fd unavailable")}
	}

	if err := ring.prepSendZCUser(fd, payload, 1, false); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if _, err := ring.submitAndWait(1); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	cqe, err := ring.waitCqe()
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if cqe.Res < 0 {
		return ioUringCapabilityProbe{err: syscall.Errno(-cqe.Res)}
	}
	if cqe.Flags&ioUringCqeMore != 0 {
		if _, err := ring.submitAndWait(1); err != nil {
			return ioUringCapabilityProbe{err: err}
		}
		notif, err := ring.waitCqe()
		if err != nil {
			return ioUringCapabilityProbe{err: err}
		}
		if notif.Flags&ioUringCqeNotif == 0 {
			return ioUringCapabilityProbe{err: syscall.EINVAL}
		}
	}
	if err := <-readDone; err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	return ioUringCapabilityProbe{ok: true}
}

func probeIOUringMultishotAcceptDetailed() ioUringCapabilityProbe {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer listener.Close()
	fd, err := listenerFD(listener)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	ring, err := newOwnedIOUring(8)
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	defer ring.close()
	if err := ring.enable(); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if err := ring.prepAcceptMultishotUser(fd, 1, uint32(sockCloexec|sockNonblock)); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if _, err := ring.submitAndWait(0); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	errCh := make(chan error, 1)
	go func() {
		conn, err := net.DialTimeout("tcp4", listener.Addr().String(), 500*time.Millisecond)
		if err == nil && conn != nil {
			_ = conn.Close()
		}
		errCh <- err
	}()
	if _, err := ring.submitAndWait(1); err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	cqe, err := ring.waitCqe()
	if err != nil {
		return ioUringCapabilityProbe{err: err}
	}
	if dialErr := <-errCh; dialErr != nil {
		return ioUringCapabilityProbe{err: dialErr}
	}
	if cqe.Res < 0 {
		errno := syscall.Errno(-cqe.Res)
		return ioUringCapabilityProbe{err: errno}
	}
	_ = syscall.Close(int(cqe.Res))
	return ioUringCapabilityProbe{ok: true}
}
