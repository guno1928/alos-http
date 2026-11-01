//go:build linux && amd64

package core

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	streamChunk       = 32 << 10
	streamTestTimeout = 5 * time.Second
	streamQuietPeriod = 150 * time.Millisecond
	h2SpecWindow      = 65535
)

var streamPatternData = func() [1 << 19]byte {
	var pattern [1 << 19]byte
	for position := range pattern {
		pattern[position] = byte(position*31 + position>>11)
	}
	return pattern
}()

func fillStreamPattern(dst []byte, offset int) {
	offset &= len(streamPatternData) - 1
	for len(dst) > 0 {
		copied := copy(dst, streamPatternData[offset:])
		dst = dst[copied:]
		offset = 0
	}
}

func streamPatternSum(size int) [32]byte {
	h := sha256.New()
	buf := make([]byte, streamChunk)
	for off := 0; off < size; {
		n := min(len(buf), size-off)
		fillStreamPattern(buf[:n], off)
		h.Write(buf[:n])
		off += n
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

type streamProbe struct {
	errs chan error
}

func (p *streamProbe) handler(closeAtEnd bool) HandlerFunc {
	return func(req *Request, resp *Response) {
		size, _ := strconv.Atoi(req.ParamValue("size"))
		sw := resp.EnsureStreamWriter()
		if sw == nil {
			resp.Status(500).String("no stream writer")
			return
		}
		resp.SetStreamer(sw)
		err := sw.WriteHeader(200, [][2]string{{"x-streamed", "1"}}, "application/octet-stream")
		buf := make([]byte, streamChunk)
		for off := 0; err == nil && (size < 0 || off < size); {
			n := len(buf)
			if size >= 0 {
				n = min(n, size-off)
			}
			fillStreamPattern(buf[:n], off)
			err = sw.WriteChunk(buf[:n])
			off += n
		}
		if err == nil && closeAtEnd {
			err = sw.Close()
		}
		if p != nil && p.errs != nil {
			p.errs <- err
		}
	}
}

func startStreamServer(t *testing.T, tlsMode bool, probe *streamProbe) string {
	t.Helper()
	addr := freeLoopbackAddr(t)
	cfg := Config{Addr: addr, LogRequests: false, MaxConnsPerIP: -1, Listeners: 1}
	if tlsMode {
		cfg.HTTPAddr = "-"
		cfg.Certs = []CertConfig{{Domain: "stream.test", Source: CertSelfSigned}}
	}
	srv := New(cfg)
	srv.Router.GET("/stream/:size", probe.handler(true))
	srv.Router.HEAD("/stream/:size", probe.handler(true))
	srv.Router.GET("/noclose/:size", probe.handler(false))
	go func() {
		if tlsMode {
			_ = srv.ListenAndServeTLS()
		} else {
			_ = srv.ListenAndServe()
		}
	}()
	t.Cleanup(func() { stopServer(srv) })
	waitForProxy(t, addr)
	return addr
}

func h2TLSClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: "stream.test", NextProtos: []string{"h2"}},
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func h2cClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Client{Transport: &http.Transport{Protocols: protocols}, Timeout: 120 * time.Second}
}

func fetchStreamSum(t *testing.T, cl *http.Client, url string) (int, [32]byte, int64, string) {
	t.Helper()
	resp, err := cl.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	return resp.StatusCode, sum, n, resp.Proto
}

func TestH2StreamedResponseIntegrity(t *testing.T) {
	sizes := []int{0, 1 << 10, 64 << 10, 10 << 20}
	if !testing.Short() {
		sizes = append(sizes, 1<<30)
	}
	for _, mode := range []struct {
		name   string
		tls    bool
		client *http.Client
		scheme string
	}{
		{"tls", true, h2TLSClient(), "https"},
		{"h2c", false, h2cClient(), "http"},
	} {
		addr := startStreamServer(t, mode.tls, nil)
		for _, size := range sizes {
			t.Run(fmt.Sprintf("%s_%d", mode.name, size), func(t *testing.T) {
				status, sum, n, proto := fetchStreamSum(t, mode.client, fmt.Sprintf("%s://%s/stream/%d", mode.scheme, addr, size))
				if proto != "HTTP/2.0" {
					t.Fatalf("negotiated %s, want HTTP/2.0", proto)
				}
				if status != 200 || n != int64(size) || sum != streamPatternSum(size) {
					t.Fatalf("status=%d bytes=%d want %d, sha match=%v", status, n, size, sum == streamPatternSum(size))
				}
			})
		}
	}
}

func TestH2StreamedResponseWithoutCloseStillEnds(t *testing.T) {
	addr := startStreamServer(t, true, nil)
	status, sum, n, _ := fetchStreamSum(t, h2TLSClient(), "https://"+addr+"/noclose/100000")
	if status != 200 || n != 100000 || sum != streamPatternSum(100000) {
		t.Fatalf("status=%d bytes=%d", status, n)
	}
}

func TestH2StreamedHEADHasNoBody(t *testing.T) {
	addr := startStreamServer(t, true, nil)
	req, _ := http.NewRequest(http.MethodHead, "https://"+addr+"/stream/4096", nil)
	resp, err := h2TLSClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) != 0 || resp.Header.Get("x-streamed") != "1" {
		t.Fatalf("status=%d body=%d header=%q", resp.StatusCode, len(body), resp.Header.Get("x-streamed"))
	}
}

func TestH2ManyConcurrentStreamedResponsesGoClient(t *testing.T) {
	addr := startStreamServer(t, true, nil)
	cl := h2TLSClient()
	const streams = 1000
	const size = 16 << 10
	want := streamPatternSum(size)
	var failures atomic.Int64
	var firstErr atomic.Value
	var wg sync.WaitGroup
	for range streams {
		wg.Go(func() {
			resp, err := cl.Get("https://" + addr + "/stream/" + strconv.Itoa(size))
			if err != nil {
				failures.Add(1)
				firstErr.CompareAndSwap(nil, err.Error())
				return
			}
			h := sha256.New()
			_, err = io.Copy(h, resp.Body)
			resp.Body.Close()
			var sum [32]byte
			h.Sum(sum[:0])
			if err != nil || resp.StatusCode != 200 || sum != want {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("failures=%d first error %v", failures.Load(), firstErr.Load())
	}
}

func TestH2ThousandStreamedResponsesOnOneConn(t *testing.T) {
	addr := startStreamServer(t, true, nil)
	r := dialRawH2(t, addr, 1<<20)
	r.windowUpdate(0, 1<<30)
	const total, inFlight, size = 1000, 256, 16 << 10
	want := streamPatternSum(size)
	sums := map[uint32]hash.Hash{}
	next, sent := uint32(1), 0
	open := func() {
		sums[next] = sha256.New()
		r.get(next, "/stream/"+strconv.Itoa(size))
		next += 2
		sent++
	}
	for range inFlight {
		open()
	}
	done := 0
	for done < total {
		f, err := r.next(streamTestTimeout)
		if err != nil {
			t.Fatalf("after %d/%d streams: %v", done, total, err)
		}
		switch f.typ {
		case H2FrameRSTStream:
			t.Fatalf("stream %d reset with code %d", f.stream, binary.BigEndian.Uint32(f.payload))
		case H2FrameData:
			sums[f.stream].Write(f.payload)
			if f.flags&H2FlagEndStream == 0 {
				continue
			}
			var sum [32]byte
			sums[f.stream].Sum(sum[:0])
			if sum != want {
				t.Fatalf("stream %d body corrupted", f.stream)
			}
			delete(sums, f.stream)
			done++
			if sent < total {
				open()
			}
		}
	}
}

type rawH2Conn struct {
	t  *testing.T
	c  net.Conn
	br *bufio.Reader
}

type rawH2Frame struct {
	typ, flags byte
	stream     uint32
	payload    []byte
}

func dialRawH2(t *testing.T, addr string, initialWindow uint32) *rawH2Conn {
	t.Helper()
	c, err := tls.Dial("tcp4", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "stream.test", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("negotiated %q, want h2", c.ConnectionState().NegotiatedProtocol)
	}
	r := &rawH2Conn{t: t, c: c, br: bufio.NewReader(c)}
	if _, err := c.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	var settings [6]byte
	binary.BigEndian.PutUint16(settings[0:], 0x4)
	binary.BigEndian.PutUint32(settings[2:], initialWindow)
	r.write(H2FrameSettings, 0, 0, settings[:])
	return r
}

func (r *rawH2Conn) write(typ, flags byte, stream uint32, payload []byte) {
	r.t.Helper()
	hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(hdr[5:], stream)
	if _, err := r.c.Write(append(hdr, payload...)); err != nil {
		r.t.Fatalf("write frame: %v", err)
	}
}

func (r *rawH2Conn) get(stream uint32, path string) {
	block := []byte{0x82, 0x87, 0x04, byte(len(path))}
	block = append(block, path...)
	block = append(block, 0x01, byte(len("stream.test")))
	block = append(block, "stream.test"...)
	r.write(H2FrameHeaders, H2FlagEndHeaders|H2FlagEndStream, stream, block)
}

func (r *rawH2Conn) windowUpdate(stream, increment uint32) {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], increment)
	r.write(H2FrameWindowUpdate, 0, stream, p[:])
}

func (r *rawH2Conn) next(wait time.Duration) (rawH2Frame, error) {
	for {
		_ = r.c.SetReadDeadline(time.Now().Add(wait))
		var hdr [9]byte
		if _, err := io.ReadFull(r.br, hdr[:]); err != nil {
			return rawH2Frame{}, err
		}
		f := rawH2Frame{
			typ: hdr[3], flags: hdr[4],
			stream:  binary.BigEndian.Uint32(hdr[5:]) & 0x7fffffff,
			payload: make([]byte, int(hdr[0])<<16|int(hdr[1])<<8|int(hdr[2])),
		}
		if _, err := io.ReadFull(r.br, f.payload); err != nil {
			return rawH2Frame{}, err
		}
		switch {
		case f.typ == H2FrameSettings && f.flags&H2FlagAck == 0:
			r.write(H2FrameSettings, H2FlagAck, 0, nil)
		case f.typ == H2FrameSettings, f.typ == H2FrameWindowUpdate, f.typ == H2FramePing:
		case f.typ == H2FrameGoAway:
			return f, errors.New("server sent GOAWAY")
		default:
			return f, nil
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (r *rawH2Conn) readStream(stream uint32, want int, h io.Writer) (int, bool) {
	r.t.Helper()
	got := 0
	for got < want {
		f, err := r.next(streamTestTimeout)
		if err != nil {
			r.t.Fatalf("after %d/%d bytes: %v", got, want, err)
		}
		if f.stream != stream {
			continue
		}
		if f.typ == H2FrameData {
			got += len(f.payload)
			_, _ = h.Write(f.payload)
			if f.flags&H2FlagEndStream != 0 {
				return got, true
			}
		}
	}
	return got, false
}

func (r *rawH2Conn) readStreamToEnd(stream uint32, want int, h io.Writer) (int, bool) {
	r.t.Helper()
	got, ended := r.readStream(stream, want, h)
	if got >= want && !ended {
		var extra int
		extra, ended = r.readStream(stream, 1, h)
		got += extra
	}
	return got, ended
}

func TestH2StreamedResponseHonoursTheClientWindow(t *testing.T) {
	addr := startStreamServer(t, true, nil)
	r := dialRawH2(t, addr, h2SpecWindow)
	const size = 1 << 20
	r.get(1, "/stream/"+strconv.Itoa(size))
	h := sha256.New()
	got, ended := r.readStream(1, h2SpecWindow, h)
	if got != h2SpecWindow || ended {
		t.Fatalf("first window delivered %d bytes (ended=%v), want exactly %d", got, ended, h2SpecWindow)
	}
	if f, err := r.next(streamQuietPeriod); err == nil || !isTimeout(err) {
		t.Fatalf("server sent %+v past an exhausted window (err=%v)", f, err)
	}
	r.windowUpdate(0, size)
	r.windowUpdate(1, size)
	rest, ended := r.readStreamToEnd(1, size-h2SpecWindow, h)
	if got+rest != size || !ended {
		t.Fatalf("total %d bytes ended=%v, want %d and END_STREAM", got+rest, ended, size)
	}
	var sum [32]byte
	h.Sum(sum[:0])
	if sum != streamPatternSum(size) {
		t.Fatal("body corrupted across the window stall")
	}
}

func TestH2ClientResetStopsTheStreamingHandler(t *testing.T) {
	probe := &streamProbe{errs: make(chan error, 4)}
	addr := startStreamServer(t, true, probe)
	r := dialRawH2(t, addr, h2SpecWindow)
	r.get(1, "/stream/-1")
	if _, ended := r.readStream(1, 1, io.Discard); ended {
		t.Fatal("an endless stream ended")
	}
	var code [4]byte
	binary.BigEndian.PutUint32(code[:], H2ErrCancel)
	r.write(H2FrameRSTStream, 0, 1, code[:])
	select {
	case err := <-probe.errs:
		if err == nil {
			t.Fatal("handler finished without seeing the reset")
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("the streaming handler never noticed the client reset")
	}
	r.windowUpdate(0, 1<<20)
	r.get(3, "/stream/1000")
	h := sha256.New()
	if n, ended := r.readStreamToEnd(3, 1000, h); n != 1000 || !ended {
		t.Fatalf("follow-up stream on the same connection: %d bytes ended=%v", n, ended)
	}
	if err := <-probe.errs; err != nil {
		t.Fatalf("follow-up handler error: %v", err)
	}
}

func TestH2StalledStreamIsResetAfterTheStallTimeout(t *testing.T) {
	old := h2StreamStallTimeout
	h2StreamStallTimeout = streamQuietPeriod
	defer func() { h2StreamStallTimeout = old }()
	probe := &streamProbe{errs: make(chan error, 2)}
	addr := startStreamServer(t, true, probe)
	r := dialRawH2(t, addr, h2SpecWindow)
	r.get(1, "/stream/-1")
	var gotRST bool
	deadline := time.Now().Add(streamTestTimeout)
	for !gotRST && time.Now().Before(deadline) {
		f, err := r.next(streamTestTimeout)
		if err != nil {
			t.Fatal(err)
		}
		gotRST = f.typ == H2FrameRSTStream && f.stream == 1
	}
	if !gotRST {
		t.Fatal("a stream stalled on flow control was never reset")
	}
	select {
	case err := <-probe.errs:
		if !errors.Is(err, errH2StreamStalled) {
			t.Fatalf("handler error %v, want the stall error", err)
		}
	case <-time.After(streamTestTimeout):
		t.Fatal("handler never returned")
	}
}
