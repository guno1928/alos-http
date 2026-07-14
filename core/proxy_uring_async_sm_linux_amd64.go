//go:build linux && amd64

package core

import (
	"bufio"
	"bytes"
	"io"
	"unsafe"

	"github.com/guno1928/turbo"
	"golang.org/x/sys/unix"
)

func newRespReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

func readFullResp(br *bufio.Reader, buf []byte) {
	_, _ = io.ReadFull(br, buf)
}

func bytesIndexSlice(b, sub []byte) int {
	return bytes.Index(b, sub)
}

func (worker *plainUringWorker) tryAsyncForward(conn *plainWorkerConn, consumed int, clientClose bool) bool {
	pe := worker.server.proxy.Load()
	if pe == nil || pe.OnRequest != nil || pe.OnResponse != nil || pe.OnError != nil || pe.Cache != nil {
		return false
	}
	if conn.req.Host == "" {
		return false
	}
	ds := pe.Lookup(stripPort(conn.req.Host))
	if ds == nil {
		return false
	}
	if isWebSocket(&conn.req) {
		return false
	}
	b := asyncPickBackend(ds)
	if b == nil || b.TLS {
		return false
	}
	ip, port, ok := asyncResolveAddr(b.Addr)
	if !ok {
		return false
	}
	if worker.asyncFwd == nil {
		worker.asyncFwd = newAsyncForwardPool()
	}
	fw := worker.asyncFwd.alloc()
	if fw == nil {
		return false
	}
	fw.clientIndex = conn.index
	fw.clientGen = conn.generation
	fw.consumed = consumed
	fw.keepAlive = !clientClose
	fw.reqNoBody = conn.req.Method == "HEAD"
	fw.backendAddr = b.Addr
	timeoutNs := ds.config.ReadTimeout.Nanoseconds()
	if timeoutNs <= 0 {
		timeoutNs = asyncDefaultTimeoutNs
	}
	fw.deadline = MonotonicNanotime() + timeoutNs
	fw.reqBuf = buildProxyRequest(worker.asyncFwd.getReqBuf(), &conn.req, b.Addr, &ds.config)
	fw.respBuf = worker.asyncFwd.getRespBuf()

	conn.state = plainConnStateForwarding
	conn.fwdIndex = fw.index
	conn.fwdGen = fw.generation

	if c := worker.asyncFwd.getIdle(b.Addr); c != nil {
		fw.backendFd = c.fd
		fw.pooled = true
		fw.state = fwdStateSending
		if !worker.submitBackendSend(fw) {
			worker.failForward(fw, 502)
		}
		return true
	}
	fd, err := asyncDialSocket()
	if err != nil {
		worker.failForward(fw, 502)
		return true
	}
	fw.backendFd = fd
	fw.sa = unix.RawSockaddrInet4{Family: unix.AF_INET, Port: htons(port)}
	copy(fw.sa.Addr[:], ip[:])
	fw.state = fwdStateConnecting
	if !worker.submitBackendConnect(fw) {
		worker.failForward(fw, 502)
	}
	return true
}

func (worker *plainUringWorker) submitBackendConnect(fw *asyncForward) bool {
	ud := plainEncodeUserData(plainUringOpBackendConnect, int(fw.index), fw.generation)
	return worker.ring.prepConnectUser(fw.backendFd, unsafe.Pointer(&fw.sa), uint64(unsafe.Sizeof(fw.sa)), ud) == nil
}

func (worker *plainUringWorker) submitBackendSend(fw *asyncForward) bool {
	ud := plainEncodeUserData(plainUringOpBackendSend, int(fw.index), fw.generation)
	return worker.ring.prepSendUser(fw.backendFd, fw.reqBuf[fw.reqSent:], ud) == nil
}

func (worker *plainUringWorker) submitBackendRecv(fw *asyncForward) bool {
	if len(fw.respBuf)-fw.respN < 4096 {
		grow := len(fw.respBuf) * 2
		if grow < asyncForwardRecvChunk {
			grow = asyncForwardRecvChunk
		}
		if grow > asyncForwardMaxRespBody+asyncForwardMaxHeaderBytes {
			return false
		}
		nb := make([]byte, grow)
		copy(nb, fw.respBuf[:fw.respN])
		fw.respBuf = nb
	}
	ud := plainEncodeUserData(plainUringOpBackendRecv, int(fw.index), fw.generation)
	return worker.ring.prepRecvUser(fw.backendFd, fw.respBuf[fw.respN:len(fw.respBuf)], ud) == nil
}

func (worker *plainUringWorker) handleBackendCompletion(op uint8, userData uint64, result int32) error {
	fw := worker.asyncFwd.get(int32(plainDecodeConn(userData)), plainDecodeGeneration(userData))
	if fw == nil {
		return nil
	}
	switch op {
	case plainUringOpBackendConnect:
		worker.onBackendConnect(fw, result)
	case plainUringOpBackendSend:
		worker.onBackendSend(fw, result)
	case plainUringOpBackendRecv:
		worker.onBackendRecv(fw, result)
	}
	return nil
}

func (worker *plainUringWorker) onBackendConnect(fw *asyncForward, result int32) {
	if fw.clientIndex < 0 {
		worker.discardForward(fw)
		return
	}
	if result < 0 {
		worker.failForward(fw, 502)
		return
	}
	fw.state = fwdStateSending
	if !worker.submitBackendSend(fw) {
		worker.failForward(fw, 502)
	}
}

func (worker *plainUringWorker) onBackendSend(fw *asyncForward, result int32) {
	if fw.clientIndex < 0 {
		worker.discardForward(fw)
		return
	}
	if result <= 0 {
		worker.failForward(fw, 502)
		return
	}
	fw.reqSent += int(result)
	if fw.reqSent < len(fw.reqBuf) {
		if !worker.submitBackendSend(fw) {
			worker.failForward(fw, 502)
		}
		return
	}
	fw.state = fwdStateReceiving
	if !worker.submitBackendRecv(fw) {
		worker.failForward(fw, 502)
	}
}

func (worker *plainUringWorker) onBackendRecv(fw *asyncForward, result int32) {
	if fw.clientIndex < 0 {
		worker.discardForward(fw)
		return
	}
	if result < 0 {
		worker.failForward(fw, 502)
		return
	}
	if result == 0 {
		if fw.parsed && fw.closeDelim {
			fw.bodyEnd = fw.respN
			worker.completeForward(fw)
			return
		}
		worker.failForward(fw, 502)
		return
	}
	fw.respN += int(result)
	done, bad := worker.asyncCheckComplete(fw)
	if bad {
		worker.failForward(fw, 502)
		return
	}
	if done {
		worker.completeForward(fw)
		return
	}
	if fw.respN > asyncForwardMaxRespBody+asyncForwardMaxHeaderBytes {
		worker.failForward(fw, 502)
		return
	}
	if !worker.submitBackendRecv(fw) {
		worker.failForward(fw, 502)
	}
}

func (worker *plainUringWorker) asyncCheckComplete(fw *asyncForward) (bool, bool) {
	if !fw.parsed {
		idx := bytesIndexSlice(fw.respBuf[:fw.respN], crlfcrlfSlice)
		if idx < 0 {
			if fw.respN > asyncForwardMaxHeaderBytes {
				return false, true
			}
			return false, false
		}
		status, cl, chunked, keep, ok := asyncParseRespHead(fw.respBuf[:idx])
		if !ok || status < 100 {
			return false, true
		}
		fw.parsed = true
		fw.status = status
		fw.chunked = chunked
		fw.respKeep = keep
		fw.headerEnd = idx + 4
		if fw.reqNoBody || status == 204 || status == 304 || (status >= 100 && status < 200) {
			fw.reqNoBody = true
			fw.bodyEnd = fw.headerEnd
			return true, false
		}
		if chunked {
		} else if cl >= 0 {
			fw.bodyLen = cl
			fw.bodyEnd = fw.headerEnd + int(cl)
		} else {
			fw.closeDelim = true
			fw.respKeep = false
		}
	}
	if fw.closeDelim {
		return false, false
	}
	if fw.chunked {
		end, st := asyncChunkedComplete(fw.respBuf[:fw.respN], fw.headerEnd)
		if st < 0 {
			return false, true
		}
		if st == 1 {
			fw.bodyEnd = end
			return true, false
		}
		return false, false
	}
	if fw.respN >= fw.bodyEnd {
		return true, false
	}
	return false, false
}

func (worker *plainUringWorker) completeForward(fw *asyncForward) {
	idx := fw.clientIndex
	clientGen := fw.clientGen
	consumed := fw.consumed
	clientKeep := fw.keepAlive
	backendKeep := fw.respKeep && fw.respN == fw.bodyEnd

	if idx < 0 || int(idx) >= len(worker.connections) {
		worker.discardForward(fw)
		return
	}
	conn := worker.connections[idx]
	if conn.generation != clientGen || conn.state != plainConnStateForwarding {
		worker.discardForward(fw)
		return
	}

	br := newRespReader(fw.respBuf[:fw.bodyEnd])
	status, ct, cl, chunked, _, headers, err := parseHTTPResponse(br)
	if err != nil {
		worker.releaseForwardBackend(fw, false)
		fw.clientIndex = -1
		worker.asyncFwd.release(fw)
		worker.writeAsyncError(conn, consumed, clientKeep, 502)
		return
	}
	var body []byte
	if !fw.reqNoBody {
		if chunked {
			body, _ = readChunkedBody(br, asyncForwardMaxRespBody)
		} else if cl > 0 {
			body = make([]byte, cl)
			readFullResp(br, body)
		}
	}
	conn.resp.Reset()
	conn.resp.Status(status)
	if ct != "" {
		conn.resp.ContentType = ct
	}
	for i := range headers {
		conn.resp.SetHeader(headers[i][0], headers[i][1])
	}
	if len(body) > 0 {
		conn.resp.SetBody(body)
	}
	worker.releaseForwardBackend(fw, backendKeep)
	fw.clientIndex = -1
	worker.asyncFwd.release(fw)
	_ = worker.queueResponse(conn, clientKeep, consumed)
}

func (worker *plainUringWorker) failForward(fw *asyncForward, status int) {
	idx := fw.clientIndex
	clientGen := fw.clientGen
	consumed := fw.consumed
	clientKeep := fw.keepAlive
	worker.releaseForwardBackend(fw, false)
	fw.clientIndex = -1
	worker.asyncFwd.release(fw)
	if idx < 0 || int(idx) >= len(worker.connections) {
		return
	}
	conn := worker.connections[idx]
	if conn.generation != clientGen || conn.state != plainConnStateForwarding {
		return
	}
	worker.writeAsyncError(conn, consumed, clientKeep, status)
}

func (worker *plainUringWorker) writeAsyncError(conn *plainWorkerConn, consumed int, clientKeep bool, status int) {
	conn.resp.Reset()
	conn.resp.Status(status).String("Bad Gateway")
	_ = worker.queueResponse(conn, clientKeep, consumed)
}

func (worker *plainUringWorker) discardForward(fw *asyncForward) {
	worker.releaseForwardBackend(fw, false)
	fw.clientIndex = -1
	worker.asyncFwd.release(fw)
}

func (worker *plainUringWorker) releaseForwardBackend(fw *asyncForward, reuse bool) {
	if fw.backendFd < 0 {
		return
	}
	if reuse {
		worker.asyncFwd.putIdle(&asyncBackendConn{fd: fw.backendFd, addr: fw.backendAddr, lastUsed: turbo.UnixNano()})
	} else {
		asyncBackendClose(fw.backendFd)
	}
	fw.backendFd = -1
}

func (worker *plainUringWorker) forwardClientGone(conn *plainWorkerConn) {
	if worker.asyncFwd == nil {
		return
	}
	fw := worker.asyncFwd.get(conn.fwdIndex, conn.fwdGen)
	if fw == nil {
		return
	}
	fw.clientIndex = -1
}

func (worker *plainUringWorker) sweepForwards(now int64) {
	af := worker.asyncFwd
	if af == nil {
		return
	}
	for i := range af.forwards {
		fw := &af.forwards[i]
		if !fw.inUse || fw.clientIndex < 0 || now <= fw.deadline {
			continue
		}
		idx := fw.clientIndex
		if idx >= 0 && int(idx) < len(worker.connections) {
			conn := worker.connections[idx]
			if conn.generation == fw.clientGen && conn.state == plainConnStateForwarding {
				worker.writeAsyncError(conn, fw.consumed, false, 504)
			}
		}
		fw.clientIndex = -1
		if fw.backendFd >= 0 {
			_ = unix.Shutdown(fw.backendFd, unix.SHUT_RDWR)
		}
	}
}
