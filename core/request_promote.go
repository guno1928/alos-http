package core

import "unsafe"

const promoteArenaChunk = 16 << 10

func (r *Request) promoteAlloc(n int) []byte {
	if r.promoteBuf == nil || r.promoteOff+n > len(r.promoteBuf) {
		size := promoteArenaChunk
		if n > size {
			size = n
		}
		r.promoteBuf = make([]byte, size)
		r.promoteOff = 0
	}
	start := r.promoteOff
	r.promoteOff += n
	return r.promoteBuf[start : start+n : start+n]
}

func promoteTake(buf []byte, off int, s string) (string, int) {
	if len(s) == 0 {
		return s, off
	}
	n := copy(buf[off:], s)
	return unsafe.String(&buf[off], n), off + n
}

func promoteRequestStrings(r *Request) {
	if !r.aliasesReadBuf {
		return
	}
	r.aliasesReadBuf = false

	total := len(r.Method) + len(r.Path) + len(r.RawPath) + len(r.Query) + len(r.Proto) +
		len(r.Host) + len(r.RemoteAddr) +
		len(r.cachedCL) + len(r.cachedConn) + len(r.cachedTE) + len(r.cachedHost) +
		len(r.cachedAE) + len(r.cachedOrigin) + len(r.cachedXFF) + len(r.cachedXRI) +
		len(r.cachedAuth) + len(r.cachedUpgrade) + len(r.cachedWSKey) + len(r.cachedWSVer)
	for i := range r.Headers {
		total += len(r.Headers[i][0]) + len(r.Headers[i][1])
	}
	if total == 0 {
		return
	}

	buf := r.promoteAlloc(total)
	off := 0
	r.Method, off = promoteTake(buf, off, r.Method)
	r.Path, off = promoteTake(buf, off, r.Path)
	r.RawPath, off = promoteTake(buf, off, r.RawPath)
	r.Query, off = promoteTake(buf, off, r.Query)
	r.Proto, off = promoteTake(buf, off, r.Proto)
	r.Host, off = promoteTake(buf, off, r.Host)
	r.RemoteAddr, off = promoteTake(buf, off, r.RemoteAddr)
	r.cachedCL, off = promoteTake(buf, off, r.cachedCL)
	r.cachedConn, off = promoteTake(buf, off, r.cachedConn)
	r.cachedTE, off = promoteTake(buf, off, r.cachedTE)
	r.cachedHost, off = promoteTake(buf, off, r.cachedHost)
	r.cachedAE, off = promoteTake(buf, off, r.cachedAE)
	r.cachedOrigin, off = promoteTake(buf, off, r.cachedOrigin)
	r.cachedXFF, off = promoteTake(buf, off, r.cachedXFF)
	r.cachedXRI, off = promoteTake(buf, off, r.cachedXRI)
	r.cachedAuth, off = promoteTake(buf, off, r.cachedAuth)
	r.cachedUpgrade, off = promoteTake(buf, off, r.cachedUpgrade)
	r.cachedWSKey, off = promoteTake(buf, off, r.cachedWSKey)
	r.cachedWSVer, off = promoteTake(buf, off, r.cachedWSVer)
	for i := range r.Headers {
		r.Headers[i][0], off = promoteTake(buf, off, r.Headers[i][0])
		r.Headers[i][1], off = promoteTake(buf, off, r.Headers[i][1])
	}
}
