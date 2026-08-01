//go:build linux && amd64

package core

// HTTP/2 inbound proxying runs in the worker loop like the HTTP/1.1 path, so a
// proxied stream no longer parks a goroutine on the backend.
//
// The response stays buffered rather than being relayed frame by frame. That is
// not a shortcut taken here: the HTTP/2 backend has never supported streamed
// responses (finishH2Dispatch rejects resp.IsStreamed with a 500), and it
// already frames a completed response out under flow control with its own
// stalling. Buffering therefore matches the existing capability exactly, and the
// window logic in h2AppendWindowed continues to own backpressure toward the
// client.

// beginProxyH2 serves an HTTP/2 stream from the proxy engine inside the event
// loop. It returns proxyStartServed when stream.resp already holds the answer
// (cache hit or an error), or proxyStartPending when a backend exchange is in
// flight and will finish the stream later.
func (w *epollWorker) beginProxyH2(pe *ProxyEngine, ds *domainState, c *epollConn, stream *H2Stream, streamID uint32) int {
	req := &stream.req
	host := stripPort(req.Host)

	if pe.Cache != nil && (req.Method == "GET" || req.Method == "HEAD") {
		cachePath := req.Path
		if req.Query != "" {
			cachePath = req.Path + "?" + req.Query
		}
		if entry, hit := pe.Cache.Get(req.Method, host, cachePath, req); hit {
			pe.Cache.ServeCached(entry, req, &stream.resp)
			if pe.OnResponse != nil {
				pr := &ProxyResponse{
					Domain:     ds.config.Domain,
					Backend:    "cache",
					ClientAddr: req.RemoteAddr,
					Method:     req.Method,
					Path:       req.Path,
					StatusCode: entry.statusCode,
					Headers:    stream.resp.Headers,
				}
				pe.OnResponse(pr)
				stream.resp.Status(pr.StatusCode)
				stream.resp.Headers = pr.Headers
			}
			return proxyStartServed
		}
	}

	if len(ds.backends) == 0 {
		stream.resp.Reset()
		stream.resp.Status(502).String("No healthy backend available")
		return proxyStartServed
	}

	px := w.pxGet()
	px.w = w
	px.c = c
	px.cGen = c.generation
	px.pe = pe
	px.ds = ds
	px.method = req.Method
	px.path = req.Path
	px.clientAddr = req.RemoteAddr
	// HTTP/2 has no per-request connection reuse decision; the stream ends and
	// the connection carries on.
	px.keepClient = true
	px.h2Stream = stream
	px.h2StreamID = streamID
	for len(px.tried) < len(ds.backends) {
		px.tried = append(px.tried, false)
	}

	if !w.proxyAttemptH2(px) {
		return proxyStartServed
	}
	return proxyStartPending
}

// proxyAttemptH2 mirrors proxyAttempt but reads the request from the stream.
func (w *epollWorker) proxyAttemptH2(px *proxyExchange) bool {
	ds := px.ds
	idx := pickRetryBackend(ds, extractIP(px.clientAddr), px.tried)
	if idx < 0 {
		w.proxyFailStream(px, 502, "No healthy backend available")
		return false
	}
	px.tried[idx] = true
	b := ds.backends[idx]
	px.b = b

	req := &px.h2Stream.req
	hostHdr := ds.config.HostHeader
	if px.pe.OnRequest != nil {
		pr := &ProxyRequest{
			Domain:     ds.config.Domain,
			Backend:    b.Addr,
			ClientAddr: px.clientAddr,
			Method:     req.Method,
			Path:       req.Path,
			Headers:    req.Headers,
			Host:       hostHdr,
		}
		originalPath := req.Path
		if !px.pe.OnRequest(pr) {
			w.proxyFailStream(px, 502, "Request blocked by interceptor")
			return false
		}
		if pr.Path != originalPath {
			// The serialiser prefers RawPath so escaped targets survive; a hook
			// that rewrote Path must therefore drop it, or the rewrite is lost.
			req.RawPath = ""
		}
		req.Path = pr.Path
		req.Headers = pr.Headers
		hostHdr = pr.Host
	}

	authority := fpProxyAuthority(b.Addr)
	if hostHdr == "" {
		if ds.config.PreserveHost {
			hostHdr = req.Host
		} else {
			hostHdr = authority
		}
	}
	px.reqRaw = appendProxyRequest(px.reqRaw[:0], req, hostHdr, extractIP(px.clientAddr))

	ip, port, err := resolveAuthority(authority)
	if err != nil {
		w.proxyRetryOrFailH2(px, err)
		return false
	}

	px.Exchange.ip = ip
	px.Exchange.port = port
	px.Exchange.key = poolKey{authority: authority, tls: b.TLS, skipVerify: b.TLSSkipVerify}
	px.Exchange.connectTimeoutNano = int64(ds.config.ConnectTimeout)
	px.Exchange.readTimeoutNano = int64(ds.config.ReadTimeout)
	px.Exchange.idleTimeoutNano = int64(ds.config.IdleTimeout)
	px.Exchange.maxIdle = ds.config.MaxIdleConns
	px.Exchange.deadline = w.be.nowNano() + proxyStartDeadline(ds)
	px.Exchange.rawRequest = px.reqRaw
	px.Exchange.req.Method = req.Method
	px.Exchange.resp = fpResponse{}
	px.Exchange.err = nil
	px.finished = false
	px.retried = false

	b.ActiveConns.Add(1)
	w.be.startExchange(&px.Exchange)
	return true
}

// proxyFailStream answers the stream with an error and releases the exchange
// without ever contacting a backend.
func (w *epollWorker) proxyFailStream(px *proxyExchange, status int, msg string) {
	if stream := px.h2Stream; stream != nil {
		stream.resp.Reset()
		stream.resp.Status(status).String(msg)
	}
	w.pxPut(px)
}

// proxyRetryOrFailH2 fails over to another backend, or gives up and answers the
// stream. An HTTP/2 response is buffered, so a retry is always possible.
func (w *epollWorker) proxyRetryOrFailH2(px *proxyExchange, err error) {
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		if px.pe.OnError != nil {
			px.pe.OnError(ProxyError{
				Domain:     px.ds.config.Domain,
				Backend:    px.b.Addr,
				ClientAddr: px.clientAddr,
				Method:     px.method,
				Path:       px.path,
				Attempt:    px.attempt + 1,
				Err:        err,
			})
		}
		px.b = nil
	}
	if px.h2Stream == nil {
		w.pxPut(px)
		return
	}
	maxRetries := px.ds.config.MaxRetries
	if maxRetries > len(px.ds.backends)-1 {
		maxRetries = len(px.ds.backends) - 1
	}
	if px.attempt >= maxRetries {
		w.finishProxyStream(px, 502, respHeaders{}, []byte("All backends failed"), "")
		return
	}
	px.attempt++
	if !w.proxyAttemptH2(px) {
		// proxyAttemptH2 already answered the stream and released px, but the
		// stream still has to be handed back to the HTTP/2 writer.
		return
	}
}

// finishProxyStream fills the stream's response and hands it to the HTTP/2
// framing path, which applies flow control on the way out.
func (w *epollWorker) finishProxyStream(px *proxyExchange, status int, headers respHeaders, body []byte, contentType string) {
	stream := px.h2Stream
	c := px.c
	streamID := px.h2StreamID
	gen := px.cGen
	// SetHeader stores strings, so this path materialises before pxPut releases
	// the exchange.
	hdrs := w.headerStrings(headers)
	w.pxPut(px)

	if stream == nil {
		return
	}
	stream.resp.Reset()
	stream.resp.Status(status)
	// Bytes sets ContentType to application/octet-stream, so the body goes in
	// first and the real content type is applied afterwards.
	stream.resp.Bytes(body)
	upstreamType := contentType
	for _, h := range hdrs {
		if isHopByHopStr(h[0]) || headerNameIs(h[0], "content-length") {
			continue
		}
		if headerNameIs(h[0], "content-type") {
			if upstreamType == "" {
				upstreamType = h[1]
			}
			continue
		}
		stream.resp.SetHeader(h[0], h[1])
	}
	if upstreamType != "" {
		stream.resp.ContentType = upstreamType
	}

	if c == nil || c.generation != gen || c.fd < 0 {
		// The connection went away; the HTTP/2 bookkeeping was already cleaned
		// up by closeConn, so the stream is simply dropped.
		return
	}
	c.finishH2Dispatch(w, gen, streamID, stream)
	// finishH2Dispatch only marks the connection for flushing, and flushPending
	// runs solely when a task was posted. The goroutine path always posted one;
	// this path posts nothing, so the write has to be issued here or the framed
	// response sits in the buffer until unrelated activity happens to drain it.
	w.flush(c)
}

// abortProxyStream releases a stream-bound exchange whose connection died.
func (w *epollWorker) abortProxyStream(px *proxyExchange) {
	px.h2Stream = nil
	px.c = nil
	if px.b != nil {
		px.b.ActiveConns.Add(-1)
		px.b = nil
	}
}
