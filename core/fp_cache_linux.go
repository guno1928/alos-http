//go:build linux

package core

import "strconv"

func (l *eventLoop) writeCachedResponse(ic *inConn, entry *cacheEntry) {
	dst := ic.wbuf.b
	dst = append(dst, "HTTP/1.1 "...)
	dst = strconv.AppendInt(dst, int64(entry.statusCode), 10)
	dst = append(dst, ' ')
	dst = append(dst, statusText(entry.statusCode)...)
	dst = append(dst, '\r', '\n')
	for _, h := range entry.headers {
		if isHopByHopStr(h[0]) {
			continue
		}
		dst = append(dst, h[0]...)
		dst = append(dst, ':', ' ')
		dst = append(dst, h[1]...)
		dst = append(dst, '\r', '\n')
	}
	dst = append(dst, "content-length: "...)
	dst = strconv.AppendInt(dst, int64(len(entry.body)), 10)
	dst = append(dst, '\r', '\n', '\r', '\n')
	dst = append(dst, entry.body...)
	ic.wbuf.b = dst
}

func (l *eventLoop) maybeCacheStore(ic *inConn, resp *fpResponse, pr *ProxyResponse) {
	cache := l.proxyRoutes.cache
	if cache == nil {
		return
	}
	if ic.method != "GET" && ic.method != "HEAD" {
		return
	}
	host := stripPort(ic.host)
	ct := fpHeaderValue(resp.Headers, "content-type")
	if pr != nil && pr.cacheRequested {
		cache.PutManual(ic.method, host, ic.path, resp.Status, resp.Headers, ct, resp.Body, pr.cacheTTL, pr.cacheMaxHits, pr.cacheCompress, pr.cacheCompressMin)
		return
	}
	if !fpReqAllowsCache(ic) {
		return
	}
	cache.Put(ic.method, host, ic.path, resp.Status, resp.Headers, ct, resp.Body)
}

func fpHeaderValue(headers [][2]string, name string) string {
	for _, h := range headers {
		if EqualFoldASCII(h[0], name) {
			return h[1]
		}
	}
	return ""
}

func fpReqAllowsCache(ic *inConn) bool {
	for _, h := range ic.headers {
		if EqualFoldASCII(h[0], "cache-control") {
			vb := []byte(h[1])
			if fpContainsTokenFold(vb, "no-cache") || fpContainsTokenFold(vb, "no-store") {
				return false
			}
		}
		if EqualFoldASCII(h[0], "pragma") && fpContainsTokenFold([]byte(h[1]), "no-cache") {
			return false
		}
	}
	return true
}
