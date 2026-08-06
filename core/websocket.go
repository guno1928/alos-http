package core

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSOriginMode controls how UpgradeWebSocket validates the Origin header to
// prevent Cross-Site WebSocket Hijacking. WSOriginSameOrigin is the default
// (the zero value): cross-site handshakes carrying an Origin are rejected.
// WSOriginAllowlist checks against WebSocketAllowedOrigins. WSOriginOff disables
// the check entirely and must be selected explicitly.
type WSOriginMode int

const (
	// WSOriginSameOrigin rejects handshakes whose Origin host differs from
	// the request Host. It is the zero value and default.
	WSOriginSameOrigin WSOriginMode = iota
	// WSOriginAllowlist accepts only origins listed in WebSocketAllowedOrigins.
	WSOriginAllowlist
	// WSOriginOff disables Origin checking entirely.
	WSOriginOff
)

func wsOriginHost(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && strings.IndexByte(s, ']') < i {
		s = s[:i]
	}
	return strings.ToLower(s)
}

func checkWebSocketOrigin(req *Request) bool {
	var mode WSOriginMode
	var allowed []string
	if req.server != nil {
		mode = req.server.config.WebSocketOriginMode
		allowed = req.server.config.WebSocketAllowedOrigins
	}
	if mode == WSOriginOff {
		return true
	}
	origin := req.Header("origin")
	if origin == "" {
		return true
	}
	switch mode {
	case WSOriginSameOrigin:
		return wsOriginHost(origin) == wsOriginHost(req.Host)
	case WSOriginAllowlist:
		for _, a := range allowed {
			if EqualFoldASCII(origin, a) {
				return true
			}
		}
		return false
	}
	return true
}

const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

const wsStatusProtocolError uint16 = 1002
const wsStatusInvalidPayload uint16 = 1007
const wsDefaultReadTimeout = 120 * time.Second
const wsDefaultWriteTimeout = 30 * time.Second
const wsDefaultMaxMessageSize = 4 * 1024 * 1024

// WSConn is a server-side WebSocket connection (RFC 6455). Obtain one with ServeWebSocket (or UpgradeWebSocket) inside a route handler, then exchange data with ReadMessage and WriteMessage (or WriteText / WriteBinary).
type WSConn struct {
	conn           net.Conn
	closed         atomic.Bool
	readTimeout    time.Duration
	writeTimeout   time.Duration
	writeMu        sync.Mutex
	lastPing       atomic.Int64
	pingCount      atomic.Uint32
	MaxMessageSize int
}

func wsAcceptKey(clientKey string) string {
	var buf [96]byte
	n := copy(buf[:], clientKey)
	n += copy(buf[n:], wsGUID)
	sum := sha1.Sum(buf[:n])
	var b64 [28]byte
	base64.StdEncoding.Encode(b64[:], sum[:])
	return string(b64[:])
}

// UpgradeWebSocket performs the WebSocket handshake (RFC 6455) on the current request, validating the Upgrade, Connection, Sec-WebSocket-Key, and Sec-WebSocket-Version headers and the Origin per the server's WSOriginMode, then hijacks the connection. It returns a *WSConn on success, or nil if the handshake failed (an error response has already been written).
//
// After a successful upgrade the handler must return promptly and service the connection on its own goroutine: handlers run inline on a shared pool of worker event loops, so a handler that blocks reading the socket pins a worker for the connection's lifetime. Prefer ServeWebSocket, which does this.
//
// Example: ws := UpgradeWebSocket(req, resp); if ws == nil { return }
// Example: if ws := UpgradeWebSocket(req, resp); ws != nil { go handle(ws) }
func UpgradeWebSocket(req *Request, resp *Response) *WSConn {
	upgradeHdr := req.Header("upgrade")
	if !EqualFoldASCII(upgradeHdr, "websocket") {
		resp.Status(400).String("not a websocket request")
		return nil
	}

	wsKey := req.Header("sec-websocket-key")
	if wsKey == "" {
		resp.Status(400).String("missing Sec-WebSocket-Key")
		return nil
	}
	decodedKey, err := base64.StdEncoding.DecodeString(wsKey)
	if err != nil || len(decodedKey) != 16 {
		resp.Status(400).String("invalid Sec-WebSocket-Key")
		return nil
	}

	connHdr := req.Header("connection")
	if !containsTokenFold(connHdr, "upgrade") {
		resp.Status(400).String("missing Connection: Upgrade")
		return nil
	}

	wsVersion := req.Header("sec-websocket-version")
	if wsVersion != "13" {
		resp.Status(426).
			SetHeader("Sec-WebSocket-Version", "13").
			String("unsupported WebSocket version")
		return nil
	}

	if !checkWebSocketOrigin(req) {
		resp.Status(403).String("forbidden websocket origin")
		return nil
	}

	conn := req.HijackConn()
	if conn == nil {
		resp.Status(500).String("connection hijack failed")
		return nil
	}

	conn.SetReadDeadline(time.Time{})
	conn.SetWriteDeadline(time.Time{})

	acceptKey := wsAcceptKey(wsKey)

	var buf [256]byte
	b := buf[:0]
	b = append(b, "HTTP/1.1 101 Switching Protocols\r\n"...)
	b = append(b, "Upgrade: websocket\r\n"...)
	b = append(b, "Connection: Upgrade\r\n"...)
	b = append(b, "Sec-WebSocket-Accept: "...)
	b = append(b, acceptKey...)
	b = append(b, "\r\n\r\n"...)

	if err := writeFull(conn, b); err != nil {
		conn.Close()
		return nil
	}

	if sw := resp.ensureSW(); sw != nil {
		resp.SetStreamer(sw)
	}

	rt, wt := wsDefaultReadTimeout, wsDefaultWriteTimeout
	if req.server != nil {
		rt = optionalDuration(req.server.config.WSReadTimeout, wsDefaultReadTimeout)
		wt = optionalDuration(req.server.config.WSWriteTimeout, wsDefaultWriteTimeout)
	}
	return &WSConn{conn: conn, readTimeout: rt, writeTimeout: wt, MaxMessageSize: wsDefaultMaxMessageSize}
}

// ServeWebSocket upgrades the request and runs fn on a new goroutine, returning immediately so the dispatching worker is released; the connection is closed when fn returns. It reports false if the upgrade failed (an error response has already been written). This is the safe way to host a WebSocket — see the UpgradeWebSocket note about handlers that block on the socket.
//
// Example: ServeWebSocket(req, resp, func(ws *WSConn) { for { _, msg, err := ws.ReadMessage(); if err != nil { return }; ws.WriteText(string(msg)) } })
// Example: if !ServeWebSocket(req, resp, handleWS) { return }
func ServeWebSocket(req *Request, resp *Response, fn func(*WSConn)) bool {
	ws := UpgradeWebSocket(req, resp)
	if ws == nil {
		return false
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[WS-PANIC] handler recovered: %v", r)
			}
			ws.Close()
		}()
		fn(ws)
	}()
	return true
}

// NetConn returns the underlying hijacked connection, e.g. to set per-write deadlines so a dead peer cannot block WriteMessage forever.
func (ws *WSConn) NetConn() net.Conn { return ws.conn }

// ReadMessage reads and reassembles the next WebSocket message, returning its opcode (0x1 text, 0x2 binary), payload, and any error. Close frames are answered and reported as io.EOF, and ping frames are answered with a pong automatically.
func (ws *WSConn) ReadMessage() (byte, []byte, error) {
	var msgOpcode byte
	var assembled []byte

	for {
		if ws.readTimeout > 0 {
			ws.conn.SetReadDeadline(time.Now().Add(ws.readTimeout))
		}
		var header [2]byte
		if _, err := io.ReadFull(ws.conn, header[:]); err != nil {
			return 0, nil, err
		}

		if header[0]&0x70 != 0 {
			ws.Close()
			return 0, nil, ErrWebSocketProtocol
		}
		fin := header[0]&0x80 != 0
		opcode := header[0] & 0x0F
		masked := header[1]&0x80 != 0

		if !masked {
			ws.Close()
			return 0, nil, ErrWebSocketProtocol
		}

		if opcode >= wsOpClose {
			if !fin || header[1]&0x7F > 125 || opcode > wsOpPong {
				ws.closeWithStatus(wsStatusProtocolError)
				return 0, nil, ErrWebSocketProtocol
			}
			payload, err := ws.readFramePayload(header[1], masked)
			if err != nil {
				return 0, nil, err
			}
			if opcode == wsOpClose {
				if len(payload) == 1 {
					ws.closeWithStatus(wsStatusProtocolError)
					return 0, nil, ErrWebSocketProtocol
				}
				if len(payload) >= 2 {
					code := binary.BigEndian.Uint16(payload[:2])
					if !wsValidCloseCode(code) {
						ws.closeWithStatus(wsStatusProtocolError)
						return 0, nil, ErrWebSocketProtocol
					}
					if !utf8.Valid(payload[2:]) {
						ws.closeWithStatus(wsStatusInvalidPayload)
						return 0, nil, ErrWebSocketProtocol
					}
					ws.WriteMessage(wsOpClose, payload[:2])
				} else {
					ws.WriteMessage(wsOpClose, nil)
				}
				ws.Close()
				return opcode, payload, io.EOF
			}
			if opcode == wsOpPing {
				now := time.Now().UnixNano()
				last := ws.lastPing.Swap(now)
				if last != 0 && now-last < int64(100*time.Millisecond) {
					ws.closeWithStatus(wsStatusProtocolError)
					return 0, nil, ErrWebSocketProtocol
				}
				if last == 0 || now-last > int64(10*time.Second) {
					ws.pingCount.Store(1)
				} else if ws.pingCount.Add(1) > 100 {
					ws.closeWithStatus(wsStatusProtocolError)
					return 0, nil, ErrWebSocketProtocol
				}
				ws.WriteMessage(wsOpPong, payload)
			}
			continue
		}

		if opcode > wsOpBinary {
			ws.closeWithStatus(wsStatusProtocolError)
			return 0, nil, ErrWebSocketProtocol
		}

		if assembled == nil {
			if opcode == wsOpContinuation {
				ws.Close()
				return 0, nil, ErrWebSocketProtocol
			}
			msgOpcode = opcode
		} else {
			if opcode != wsOpContinuation {
				ws.Close()
				return 0, nil, ErrWebSocketProtocol
			}
		}

		payload, err := ws.readFramePayload(header[1], masked)
		if err != nil {
			return 0, nil, err
		}
		assembled = append(assembled, payload...)

		if int64(len(assembled)) > ws.maxMessageSize() {
			ws.Close()
			return 0, nil, ErrBodyTooLarge
		}

		if fin {
			if msgOpcode == wsOpText && !utf8.Valid(assembled) {
				ws.closeWithStatus(wsStatusInvalidPayload)
				return 0, nil, ErrWebSocketProtocol
			}
			return msgOpcode, assembled, nil
		}
	}
}

func wsValidCloseCode(code uint16) bool {
	switch {
	case code >= 3000 && code <= 4999:
		return true
	case code == 1000 || code == 1001 || code == 1002 || code == 1003 ||
		code == 1007 || code == 1008 || code == 1009 || code == 1010 || code == 1011:
		return true
	default:
		return false
	}
}

func (ws *WSConn) closeWithStatus(code uint16) {
	var payload [2]byte
	binary.BigEndian.PutUint16(payload[:], code)
	_ = ws.WriteMessage(wsOpClose, payload[:])
	ws.Close()
}

func (ws *WSConn) readFramePayload(secondByte byte, masked bool) ([]byte, error) {
	payloadLen := int64(secondByte & 0x7F)

	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(ws.conn, ext[:]); err != nil {
			return nil, err
		}
		payloadLen = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.conn, ext[:]); err != nil {
			return nil, err
		}
		payloadLen = int64(ext[0])<<56 | int64(ext[1])<<48 | int64(ext[2])<<40 | int64(ext[3])<<32 |
			int64(ext[4])<<24 | int64(ext[5])<<16 | int64(ext[6])<<8 | int64(ext[7])
		if payloadLen < 0 {
			ws.Close()
			return nil, ErrBodyTooLarge
		}
	}

	if payloadLen > ws.maxMessageSize() {
		ws.Close()
		return nil, ErrBodyTooLarge
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.conn, maskKey[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(ws.conn, payload); err != nil {
			return nil, err
		}
	}

	if masked {
		maskXOR(payload, maskKey)
	}

	return payload, nil
}

// WriteMessage writes a single WebSocket frame with the given opcode and payload; prefer WriteText or WriteBinary for ordinary messages.
//
// Example: ws.WriteMessage(0x1, []byte("hi"))
// Example: ws.WriteMessage(0x2, payload)
func (ws *WSConn) WriteMessage(opcode byte, data []byte) error {
	ws.writeMu.Lock()
	defer ws.writeMu.Unlock()

	payloadLen := len(data)
	var header [10]byte
	header[0] = 0x80 | opcode
	n := 2

	switch {
	case payloadLen <= 125:
		header[1] = byte(payloadLen)
	case payloadLen <= 65535:
		header[1] = 126
		header[2] = byte(payloadLen >> 8)
		header[3] = byte(payloadLen)
		n = 4
	default:
		header[1] = 127
		header[2] = byte(payloadLen >> 56)
		header[3] = byte(payloadLen >> 48)
		header[4] = byte(payloadLen >> 40)
		header[5] = byte(payloadLen >> 32)
		header[6] = byte(payloadLen >> 24)
		header[7] = byte(payloadLen >> 16)
		header[8] = byte(payloadLen >> 8)
		header[9] = byte(payloadLen)
		n = 10
	}

	bp := MediumBufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	buf = append(buf, header[:n]...)
	buf = append(buf, data...)
	if ws.writeTimeout > 0 {
		ws.conn.SetWriteDeadline(time.Now().Add(ws.writeTimeout))
	}
	err := writeFull(ws.conn, buf)
	ws.conn.SetWriteDeadline(time.Time{})
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return err
}

// WriteText sends a text WebSocket frame.
//
// Example: ws.WriteText("hello client")
// Example: ws.WriteText(fmt.Sprintf("count=%d", n))
func (ws *WSConn) WriteText(msg string) error {
	return ws.WriteMessage(wsOpText, UnsafeBytes(msg))
}

// WriteBinary sends a binary WebSocket frame.
//
// Example: ws.WriteBinary([]byte{0x01, 0x02})
// Example: ws.WriteBinary(buf)
func (ws *WSConn) WriteBinary(data []byte) error {
	return ws.WriteMessage(wsOpBinary, data)
}

// Ping sends a WebSocket ping frame; a conforming client replies with a pong automatically.
func (ws *WSConn) Ping() error {
	return ws.WriteMessage(wsOpPing, nil)
}

// Close sends a close frame and closes the underlying connection. It is safe to call multiple times.
func (ws *WSConn) Close() error {
	if ws.closed.CompareAndSwap(false, true) {
		ws.WriteMessage(wsOpClose, nil)
		return ws.conn.Close()
	}
	return nil
}

// SetDeadline sets the read and write deadline on the underlying connection.
//
// Example: ws.SetDeadline(time.Now().Add(30 * time.Second))
// Example: ws.SetDeadline(time.Time{})
func (ws *WSConn) SetDeadline(t time.Time) error {
	return ws.conn.SetDeadline(t)
}

// SetReadTimeout sets the idle read timeout applied before each frame read; a value <= 0 disables it. The default prevents a stalled peer from pinning the connection's goroutine indefinitely.
//
// Example: ws.SetReadTimeout(60 * time.Second)
// Example: ws.SetReadTimeout(0)
func (ws *WSConn) SetReadTimeout(d time.Duration) {
	ws.readTimeout = d
}

// SetWriteTimeout sets the timeout applied to each frame write; a value <= 0
// disables it.
//
// Example: ws.SetWriteTimeout(15 * time.Second)
// Example: ws.SetWriteTimeout(0)
func (ws *WSConn) SetWriteTimeout(d time.Duration) {
	ws.writeTimeout = d
}

func (ws *WSConn) maxMessageSize() int64 {
	if ws.MaxMessageSize <= 0 {
		return int64(wsDefaultMaxMessageSize)
	}
	return int64(ws.MaxMessageSize)
}

func containsTokenFold(header, token string) bool {
	for header != "" {
		var part string
		if i := indexOf(header, ','); i >= 0 {
			part = header[:i]
			header = header[i+1:]
		} else {
			part = header
			header = ""
		}
		for len(part) > 0 && part[0] == ' ' {
			part = part[1:]
		}
		for len(part) > 0 && part[len(part)-1] == ' ' {
			part = part[:len(part)-1]
		}
		if EqualFoldASCII(part, token) {
			return true
		}
	}
	return false
}

func indexOf(s string, c byte) int {
	return strings.IndexByte(s, c)
}

// Uint32Hash64 mixes the bits of v through a multiply-xorshift finalizer and
// returns a well-distributed pseudo-random value derived from v.
func Uint32Hash64(v uint64) uint64 {
	x := v
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = ((x >> 16) ^ x) * 0x45d9f3b
	x = (x >> 16) ^ x
	return x
}

func maskXOR(payload []byte, maskKey [4]byte) {
	if len(payload) == 0 {
		return
	}
	var mask8 [8]byte
	mask8[0] = maskKey[0]
	mask8[1] = maskKey[1]
	mask8[2] = maskKey[2]
	mask8[3] = maskKey[3]
	mask8[4] = maskKey[0]
	mask8[5] = maskKey[1]
	mask8[6] = maskKey[2]
	mask8[7] = maskKey[3]
	maskWord := binary.LittleEndian.Uint64(mask8[:])

	n := len(payload)
	i := 0
	for ; i+8 <= n; i += 8 {
		v := binary.LittleEndian.Uint64(payload[i:])
		binary.LittleEndian.PutUint64(payload[i:], v^maskWord)
	}
	for ; i < n; i++ {
		payload[i] ^= maskKey[i&3]
	}
}
