package core

import (
	"bytes"
	"io"
	"net"
	"sync"
)

func (s *Server) ServeH1Plain(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	bp := LargeBufPool.Get().(*[]byte)
	readBuf := (*bp)[:0]
	defer func() {
		*bp = readBuf[:0]
		LargeBufPool.Put(bp)
	}()

	rbp := LargeBufPool.Get().(*[]byte)
	respBuf := (*rbp)[:0]
	defer func() {
		*rbp = respBuf[:0]
		LargeBufPool.Put(rbp)
	}()

	var req Request
	req.Headers = make([][2]string, 0, 16)
	req.Body = make([]byte, 0, 1024)
	req.Proto = "HTTP/1.1"
	var resp Response
	resp.Headers = make([][2]string, 0, 8)
	resp.body = make([]byte, 0, 4096)

	maxRead := s.config.MaxReadSize
	if maxRead <= 0 {
		maxRead = 2 << 20
	}
	idleTimeout := s.config.IdleTimeout
	fastDispatch := s.fastDispatch.Load()
	maxWrite := s.config.MaxWriteSize

	var localReqs uint64
	defer func() {
		if localReqs > 0 {
			Stats.TotalReqs.Add(localReqs)
		}
	}()
	for {
		if len(readBuf) == 0 && idleTimeout > 0 {
			conn.SetDeadline(timeNow().Add(idleTimeout))
		}
		if cap(readBuf)-len(readBuf) < 4096 {
			newCap := len(readBuf)*2 + 4096
			if maxRead > 0 && int64(newCap) > maxRead {
				newCap = int(maxRead)
			}
			if newCap <= len(readBuf) {
				return
			}
			newBuf := make([]byte, len(readBuf), newCap)
			copy(newBuf, readBuf)
			readBuf = newBuf
		}

		n, err := conn.Read(readBuf[len(readBuf):cap(readBuf)])
		if n > 0 {
			readBuf = readBuf[:len(readBuf)+n]
		}
		if err != nil {
			return
		}

		for {
			reqEnd := findRequestEnd(readBuf)
			if reqEnd < 0 {
				break
			}

			reqData := readBuf[:reqEnd]
			consumed := reqEnd
			localReqs++
			if localReqs&63 == 0 {
				Stats.TotalReqs.Add(64)
				localReqs = 0
			}

			req.resetFastH1()
			ParseH1Request(reqData, &req)
			if debugFlag.Load() {
				Dbg("H1Plain request: %s %s", req.Method, req.Path)
			}

			if req.cachedTE != "" {
				resp.Reset()
				resp.Status(400).String("Bad Request")
				respBuf = appendPlainResponse(&resp, respBuf[:0])
				conn.Write(respBuf)
				return
			}

			clStr := req.cachedCL
			if clStr != "" {
				cl, ok := parseUint(clStr)
				if !ok {
					resp.Reset()
					resp.Status(400).String("Bad Request")
					respBuf = appendPlainResponse(&resp, respBuf[:0])
					conn.Write(respBuf)
					return
				}
				if s.config.MaxBodySize > 0 && int64(cl) > s.config.MaxBodySize {
					resp.Reset()
					resp.Status(413).String("Payload Too Large")
					respBuf = appendPlainResponse(&resp, respBuf[:0])
					conn.Write(respBuf)
					return
				}
				bodyEnd := reqEnd + cl
				for len(readBuf) < bodyEnd {
					if cap(readBuf) < bodyEnd {
						newCap := cap(readBuf) * 2
						if newCap < bodyEnd {
							newCap = bodyEnd
						}
						if maxRead > 0 && int64(newCap) > maxRead {
							newCap = int(maxRead)
						}
						if newCap < bodyEnd {
							return
						}
						newBuf := make([]byte, len(readBuf), newCap)
						copy(newBuf, readBuf)
						readBuf = newBuf
					}
					nn, rerr := conn.Read(readBuf[len(readBuf):cap(readBuf)])
					if nn > 0 {
						readBuf = readBuf[:len(readBuf)+nn]
					}
					if rerr != nil {
						return
					}
				}
				req.Body = append(req.Body[:0], readBuf[reqEnd:bodyEnd]...)
				consumed = bodyEnd
				if s.config.MaxBodySize > 0 && int64(len(req.Body)) > s.config.MaxBodySize {
					resp.Reset()
					resp.Status(413).String("Payload Too Large")
					respBuf = appendPlainResponse(&resp, respBuf[:0])
					conn.Write(respBuf)
					return
				}
			}

			resp.resetFastH1()

			req.StreamWriter = nil
			req.conn = conn
			req.server = s
			req.Host = req.cachedHost
			req.RemoteAddr = remoteAddr
			resp.SetSW(nil)
			resp.lazyReq = &req

			if fastDispatch {
				handler := s.Router.Lookup(req.Method, req.Path, &req)
				handler(&req, &resp)
				if maxWrite > 0 && int64(resp.BodyLen()) > maxWrite {
					resp.resetFastH1()
					resp.Status(500).String("Response Too Large")
				}
			} else {
				s.dispatch(&req, &resp)
			}

			copy(readBuf, readBuf[consumed:])
			readBuf = readBuf[:len(readBuf)-consumed]

			if req.hijacked {
				return
			}

			if resp.IsStreamed() {
				if sw := req.StreamWriter; sw != nil {
					if psw, ok := sw.(*PlainH1StreamWriter); ok {
						PlainH1StreamWriterPool.Put(psw)
					}
				}
				continue
			}

			respBuf = appendPlainResponse(&resp, respBuf[:0])
			if _, werr := conn.Write(respBuf); werr != nil {
				return
			}

			if EqualFoldASCII(req.cachedConn, "close") {
				return
			}
		}
	}
}

func appendPlainResponse(resp *Response, dst []byte) []byte {
	dst = appendStatusLine(dst, resp.StatusCode)

	if resp.ContentType != "" {
		switch resp.ContentType {
		case "application/json; charset=utf-8":
			dst = append(dst, ctPrefixJSON...)
		case "text/plain; charset=utf-8":
			dst = append(dst, ctPrefixTextPlain...)
		case "text/html; charset=utf-8":
			dst = append(dst, ctPrefixTextHTML...)
		case "application/octet-stream":
			dst = append(dst, ctPrefixOctet...)
		default:
			dst = append(dst, "Content-Type: "...)
			dst = append(dst, resp.ContentType...)
			dst = append(dst, '\r', '\n')
		}
	}

	bodyLen := resp.BodyLen()
	if bodyLen < 256 {
		dst = append(dst, smallCL[bodyLen]...)
	} else {
		dst = append(dst, "Content-Length: "...)
		dst = appendUint(dst, int64(bodyLen))
		dst = append(dst, '\r', '\n')
	}

	for i := range resp.Headers {
		dst = append(dst, resp.Headers[i][0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, resp.Headers[i][1]...)
		dst = append(dst, '\r', '\n')
	}

	dst = append(dst, connKeepAlive...)
	dst = append(dst, '\r', '\n')
	dst = append(dst, resp.GetBody()...)
	return dst
}

var crlfcrlf = [4]byte{13, 10, 13, 10}

func findRequestEnd(data []byte) int {
	if len(data) < 4 {
		return -1
	}
	off := 0
	for {
		idx := bytes.IndexByte(data[off:], '\r')
		if idx < 0 {
			return -1
		}
		pos := off + idx
		if pos+3 >= len(data) {
			return -1
		}
		if data[pos+1] == '\n' && data[pos+2] == '\r' && data[pos+3] == '\n' {
			return pos + 4
		}
		off = pos + 1
	}
}

func (s *Server) ServeH2Plain(conn net.Conn) {
	hc := &H2Conn{
		remoteAddr:        conn.RemoteAddr().String(),
		conn:              conn,
		plain:             true,
		hdrBuf:            make([]byte, 5),
		server:            s,
		decoder:           NewHpackDecoder(),
		initialWindowSize: H2DefaultWindowSize,
		streams:           NewShardedMap[uint32, *H2Stream](Uint32Hash),
		writeCh:           make(chan WriteRequest, 512),
		done:              make(chan struct{}),
		decryptBuf:        make([]byte, 0, MaxRecordSize),
		appBuf:            make([]byte, 0, MaxRecordSize*2),
		headerAccum:       make([]byte, 0, 4096),
	}
	hc.connWindow.Store(int64(H2DefaultWindowSize))
	hc.maxFrameSize.Store(H2DefaultMaxFrameSize)
	hc.recvConnWindow.Store(int64(H2ConnectionWindowSize))
	hc.flowCond = sync.NewCond(&hc.flowMu)

	go hc.writerLoop()

	defer func() {
		close(hc.done)
		hc.flowCond.Broadcast()
		hc.dispatchWg.Wait()
		close(hc.writeCh)
	}()

	if !hc.readAndValidatePreface() {
		return
	}

	hc.sendInitialSettingsAndWindowUpdate()
	hc.serveLoop()
}

func (hc *H2Conn) readAppDataPlain() error {
	bp := RecordBufPool.Get().(*[]byte)
	buf := (*bp)[:cap(*bp)]
	n, err := hc.conn.Read(buf)
	if n > 0 {
		hc.appBuf = append(hc.appBuf, buf[:n]...)
		hc.appBufValid = len(hc.appBuf)
	}
	*bp = buf[:0]
	RecordBufPool.Put(bp)
	if err != nil {
		return err
	}
	return nil
}

func (hc *H2Conn) readAndValidatePrefacePlain() bool {
	var preface [H2PrefaceLen]byte
	if _, err := io.ReadFull(hc.conn, preface[:]); err != nil {
		return false
	}
	for i := 0; i < H2PrefaceLen; i++ {
		if preface[i] != H2ClientPreface[i] {
			return false
		}
	}
	Dbg("[H2-plain] client preface validated")
	return true
}

func (hc *H2Conn) writerLoopPlain() {
	var batch [64]WriteRequest
	batchBuf := make([]byte, 0, 16384)
	for req := range hc.writeCh {
		batch[0] = req
		n := 1

	drain:
		for n < len(batch) {
			select {
			case next, ok := <-hc.writeCh:
				if !ok {
					break drain
				}
				batch[n] = next
				n++
			default:
				break drain
			}
		}

		if n == 1 {
			_, err := hc.conn.Write(req.Data)
			if req.Done != nil {
				req.Done <- err
			}
		} else {
			batchBuf = appendWriteBatch(batchBuf, batch, n)
			_, err := hc.conn.Write(batchBuf)
			for i := 0; i < n; i++ {
				if batch[i].Done != nil {
					batch[i].Done <- err
				}
			}
		}
	}
}
