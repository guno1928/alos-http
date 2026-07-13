//go:build linux && amd64

package core

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	plainUringOpBackendConnect = 6
	plainUringOpBackendSend    = 7
	plainUringOpBackendRecv    = 8
	plainUringOpBackendClose   = 9
)

const (
	fwdStateFree = iota
	fwdStateConnecting
	fwdStateSending
	fwdStateReceiving
	fwdStateDone
)

const (
	asyncForwardSlotsPerWorker = 2048
	asyncForwardRecvChunk      = 32 << 10
	asyncForwardMaxRespBody    = 8 << 20
	asyncForwardMaxHeaderBytes = 32 << 10
	asyncDefaultTimeoutNs      = int64(30) * int64(1e9)
	asyncForwardBufFreeCap     = 256
)

type asyncForward struct {
	index      int32
	nextFree   int32
	generation uint16
	state      uint8
	inUse      bool

	clientIndex int32
	clientGen   uint16
	consumed    int
	keepAlive   bool
	reqNoBody   bool

	backendFd   int
	backendAddr string
	pooled      bool

	sa unix.RawSockaddrInet4

	reqBuf  []byte
	reqSent int

	respBuf   []byte
	respN     int
	parsed    bool
	status    int
	headerEnd int
	bodyEnd   int
	bodyLen   int64
	chunked   bool
	closeDelim bool
	respKeep  bool

	deadline int64
}

type asyncBackendConn struct {
	fd       int
	addr     string
	lastUsed int64
	next     *asyncBackendConn
}

type asyncForwardPool struct {
	forwards    []asyncForward
	freeHead    int32
	idle        map[string]*asyncBackendConn
	idleN       map[string]int
	maxIdle     int
	respBufFree [][]byte
	reqBufFree  [][]byte
}

func (p *asyncForwardPool) getRespBuf() []byte {
	n := len(p.respBufFree)
	if n > 0 {
		b := p.respBufFree[n-1]
		p.respBufFree = p.respBufFree[:n-1]
		return b[:cap(b)]
	}
	return make([]byte, asyncForwardRecvChunk)
}

func (p *asyncForwardPool) putRespBuf(b []byte) {
	if cap(b) != asyncForwardRecvChunk || len(p.respBufFree) >= asyncForwardBufFreeCap {
		return
	}
	p.respBufFree = append(p.respBufFree, b)
}

func (p *asyncForwardPool) getReqBuf() []byte {
	n := len(p.reqBufFree)
	if n > 0 {
		b := p.reqBufFree[n-1]
		p.reqBufFree = p.reqBufFree[:n-1]
		return b[:0]
	}
	return make([]byte, 0, 8192)
}

func (p *asyncForwardPool) putReqBuf(b []byte) {
	if cap(b) == 0 || cap(b) > 1<<20 || len(p.reqBufFree) >= asyncForwardBufFreeCap {
		return
	}
	p.reqBufFree = append(p.reqBufFree, b)
}

func newAsyncForwardPool() *asyncForwardPool {
	p := &asyncForwardPool{
		forwards: make([]asyncForward, asyncForwardSlotsPerWorker),
		freeHead: 0,
		idle:     make(map[string]*asyncBackendConn),
		idleN:    make(map[string]int),
		maxIdle:  256,
	}
	for i := range p.forwards {
		p.forwards[i].index = int32(i)
		if i+1 < len(p.forwards) {
			p.forwards[i].nextFree = int32(i + 1)
		} else {
			p.forwards[i].nextFree = -1
		}
	}
	return p
}

func (p *asyncForwardPool) alloc() *asyncForward {
	if p.freeHead < 0 {
		return nil
	}
	idx := p.freeHead
	fw := &p.forwards[idx]
	p.freeHead = fw.nextFree
	gen := fw.generation
	*fw = asyncForward{index: idx, nextFree: -1, generation: gen}
	fw.inUse = true
	fw.backendFd = -1
	return fw
}

func (p *asyncForwardPool) get(index int32, generation uint16) *asyncForward {
	if index < 0 || int(index) >= len(p.forwards) {
		return nil
	}
	fw := &p.forwards[index]
	if !fw.inUse || fw.generation != generation {
		return nil
	}
	return fw
}

func (p *asyncForwardPool) release(fw *asyncForward) {
	if !fw.inUse {
		return
	}
	fw.inUse = false
	fw.generation++
	fw.state = fwdStateFree
	if fw.reqBuf != nil {
		p.putReqBuf(fw.reqBuf)
		fw.reqBuf = nil
	}
	if fw.respBuf != nil {
		p.putRespBuf(fw.respBuf)
		fw.respBuf = nil
	}
	fw.backendAddr = ""
	fw.backendFd = -1
	fw.nextFree = p.freeHead
	p.freeHead = fw.index
}

func (p *asyncForwardPool) getIdle(addr string) *asyncBackendConn {
	c := p.idle[addr]
	if c == nil {
		return nil
	}
	p.idle[addr] = c.next
	p.idleN[addr]--
	c.next = nil
	return c
}

func (p *asyncForwardPool) putIdle(c *asyncBackendConn) {
	if p.idleN[c.addr] >= p.maxIdle {
		asyncBackendClose(c.fd)
		return
	}
	c.next = p.idle[c.addr]
	p.idle[c.addr] = c
	p.idleN[c.addr]++
}

func asyncBackendClose(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func asyncDialSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		return -1, err
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	return fd, nil
}

func (ring *ioUring) prepConnectUser(fd int, addr unsafe.Pointer, addrLen uint64, userData uint64) error {
	sqe, err := ring.getSqe()
	if err != nil {
		return err
	}
	sqe.Opcode = ioUringOpConnect
	sqe.FD = int32(fd)
	sqe.Addr = uint64(uintptr(addr))
	sqe.Off = addrLen
	sqe.UserData = userData
	return nil
}

func asyncResolveAddr(addr string) ([4]byte, uint16, bool) {
	var ip [4]byte
	i := lastColon(addr)
	if i <= 0 {
		return ip, 0, false
	}
	host := addr[:i]
	p := 0
	for _, c := range addr[i+1:] {
		if c < '0' || c > '9' {
			return ip, 0, false
		}
		p = p*10 + int(c-'0')
	}
	if p <= 0 || p > 65535 {
		return ip, 0, false
	}
	if !parseIPv4Into(host, &ip) {
		return ip, 0, false
	}
	return ip, uint16(p), true
}

func lastColon(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

func parseIPv4Into(s string, ip *[4]byte) bool {
	part := 0
	val := -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if val < 0 || part >= 3 {
				return false
			}
			ip[part] = byte(val)
			part++
			val = -1
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		if val < 0 {
			val = 0
		}
		val = val*10 + int(c-'0')
		if val > 255 {
			return false
		}
	}
	if val < 0 || part != 3 {
		return false
	}
	ip[3] = byte(val)
	return true
}

func asyncPickBackend(ds *domainState) *backend {
	if len(ds.backends) == 0 {
		return nil
	}
	idx := ds.balancer.pick(ds.backends, "")
	if idx >= 0 && idx < len(ds.backends) && ds.backends[idx].Healthy.Load() {
		return ds.backends[idx]
	}
	for _, b := range ds.backends {
		if b.Healthy.Load() {
			return b
		}
	}
	return nil
}

func asyncParseRespHead(block []byte) (status int, contentLength int64, chunked bool, keepAlive bool, ok bool) {
	nl := indexByteFrom(block, '\n', 0)
	if nl < 0 {
		return 0, 0, false, false, false
	}
	line := block[:nl]
	if len(line) < 12 || line[0] != 'H' {
		return 0, 0, false, false, false
	}
	for i := 9; i < 12; i++ {
		d := line[i]
		if d < '0' || d > '9' {
			return 0, 0, false, false, false
		}
		status = status*10 + int(d-'0')
	}
	contentLength = -1
	keepAlive = line[7] != '0'
	rest := block[nl+1:]
	for len(rest) > 0 {
		e := indexByteFrom(rest, '\n', 0)
		var hl []byte
		if e < 0 {
			hl = rest
			rest = nil
		} else {
			hl = rest[:e]
			rest = rest[e+1:]
		}
		for len(hl) > 0 && (hl[len(hl)-1] == '\r' || hl[len(hl)-1] == ' ' || hl[len(hl)-1] == '\t') {
			hl = hl[:len(hl)-1]
		}
		if len(hl) == 0 {
			continue
		}
		c := indexByteFrom(hl, ':', 0)
		if c <= 0 {
			continue
		}
		name := hl[:c]
		val := hl[c+1:]
		for len(val) > 0 && (val[0] == ' ' || val[0] == '\t') {
			val = val[1:]
		}
		switch {
		case EqualFoldASCII(bytesToStr(name), "content-length"):
			n := parseUintBytes(val)
			if n >= 0 {
				contentLength = n
			}
		case EqualFoldASCII(bytesToStr(name), "transfer-encoding"):
			if hasTokenFold(val, "chunked") {
				chunked = true
			}
		case EqualFoldASCII(bytesToStr(name), "connection"):
			if hasTokenFold(val, "close") {
				keepAlive = false
			} else if hasTokenFold(val, "keep-alive") {
				keepAlive = true
			}
		}
	}
	if chunked {
		contentLength = -1
	}
	return status, contentLength, chunked, keepAlive, true
}

func asyncChunkedComplete(buf []byte, pos int) (int, int) {
	for {
		nl := indexByteFrom(buf, '\n', pos)
		if nl < 0 {
			return 0, 0
		}
		line := buf[pos:nl]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if semi := indexByteFrom(line, ';', 0); semi >= 0 {
			line = line[:semi]
		}
		line = trimASCIISpaceBytes(line)
		size, ok := parseHex64Bytes(line)
		if !ok {
			return 0, -1
		}
		pos = nl + 1
		if size == 0 {
			for {
				nl2 := indexByteFrom(buf, '\n', pos)
				if nl2 < 0 {
					return 0, 0
				}
				tline := buf[pos:nl2]
				pos = nl2 + 1
				if len(tline) == 0 || (len(tline) == 1 && tline[0] == '\r') {
					return pos, 1
				}
			}
		}
		pos += int(size) + 2
		if pos > len(buf) {
			return 0, 0
		}
	}
}

func indexByteFrom(b []byte, c byte, from int) int {
	for i := from; i < len(b); i++ {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func parseUintBytes(b []byte) int64 {
	if len(b) == 0 {
		return -1
	}
	var n int64
	for _, c := range b {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return -1
		}
	}
	return n
}

func hasTokenFold(v []byte, tok string) bool {
	start := 0
	for start <= len(v) {
		end := start
		for end < len(v) && v[end] != ',' {
			end++
		}
		part := trimASCIISpaceBytes(v[start:end])
		if EqualFoldASCII(bytesToStr(part), tok) {
			return true
		}
		if end >= len(v) {
			break
		}
		start = end + 1
	}
	return false
}

func bytesToStr(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}
