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
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

// WSConn is a server-side WebSocket connection (RFC 6455). Create one with
// ServeWebSocket inside a route handler, then use ReadMessage and WriteMessage
// (or WriteText / WriteBinary) to exchange data.
//
//	r.GET("/ws", func(req *core.Request, resp *core.Response) {
//	    core.ServeWebSocket(req, resp, func(ws *core.WSConn) {
//	        for {
//	            _, msg, err := ws.ReadMessage()
//	            if err != nil {
//	                return
//	            }
//	            ws.WriteText("echo: " + string(msg))
//	        }
//	    })
//	})
type WSConn struct {
	conn   net.Conn
	closed atomic.Bool
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

// UpgradeWebSocket performs the WebSocket handshake on the current request. It
// validates the required headers (Upgrade, Connection, Sec-WebSocket-Key,
// Sec-WebSocket-Version) and hijacks the underlying connection.
//
// Returns a *WSConn on success, or nil if the handshake fails (in which case an
// error response is already written).
//
// WARNING: route handlers run INLINE on a fixed pool of server worker event
// loops. A handler that keeps reading the socket until it closes pins that
// worker's entire event loop for the connection's lifetime — a handful of open
// sockets starves the pool and every other request on those workers hangs.
// After UpgradeWebSocket the handler must RETURN immediately and service the
// connection on its own goroutine. Use ServeWebSocket, which does this for you:
//
//	r.GET("/ws", func(req *core.Request, resp *core.Response) {
//	    core.ServeWebSocket(req, resp, func(ws *core.WSConn) {
//	        for {
//	            _, msg, err := ws.ReadMessage()
//	            if err != nil {
//	                return
//	            }
//	            ws.WriteText(string(msg))
//	        }
//	    })
//	})
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

	// The connection inherits the server's absolute idle deadline, which would
	// silently kill the WebSocket once it elapses. Clear it: liveness is the
	// protocol's job (ping/pong), not the HTTP idle timeout's.
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

	return &WSConn{conn: conn}
}

// ServeWebSocket upgrades the request and services the connection on its own
// goroutine, returning immediately so the worker that dispatched the handler is
// released. This is the safe way to host a WebSocket: see the UpgradeWebSocket
// warning about handlers that block on the socket. fn runs until it returns;
// the connection is closed afterwards. Returns false if the upgrade failed (an
// error response has already been written).
//
//	r.GET("/ws", func(req *core.Request, resp *core.Response) {
//	    core.ServeWebSocket(req, resp, func(ws *core.WSConn) {
//	        for {
//	            _, msg, err := ws.ReadMessage()
//	            if err != nil {
//	                return
//	            }
//	            ws.WriteText(string(msg))
//	        }
//	    })
//	})
func ServeWebSocket(req *Request, resp *Response, fn func(*WSConn)) bool {
	ws := UpgradeWebSocket(req, resp)
	if ws == nil {
		return false
	}
	go func() {
		defer ws.Close()
		fn(ws)
	}()
	return true
}

var wsOriginOffWarnOnce sync.Once

// checkWebSocketOrigin enforces the configured WSOriginMode against the request
// Origin header before the handshake completes. It returns true if the upgrade
// may proceed and false if it must be rejected with 403. Treats all peer input
// as hostile and fails closed: a missing or malformed Origin is rejected in any
// checking mode.
func checkWebSocketOrigin(req *Request) bool {
	var mode WSOriginMode
	if req.server != nil {
		mode = req.server.config.WebSocketOriginMode
	}

	switch mode {
	case WSOriginModeSameOrigin:
		originHost, ok := wsOriginHost(req.Header("Origin"))
		if !ok {
			return false
		}
		return EqualFoldASCII(originHost, wsStripDefaultPort(req.Host))

	case WSOriginModeAllowlist:
		gotScheme, gotHost, ok := wsParseOrigin(req.Header("Origin"))
		if !ok {
			return false
		}
		for _, allowed := range req.server.config.AllowedWebSocketOrigins {
			wantScheme, wantHost, ok := wsParseOrigin(allowed)
			if !ok {
				continue
			}
			if EqualFoldASCII(gotScheme, wantScheme) && EqualFoldASCII(gotHost, wantHost) {
				return true
			}
		}
		return false

	default: // WSOriginModeOff
		wsOriginOffWarnOnce.Do(func() {
			log.Printf("[WARN] WebSocket Origin checking is disabled (WebSocketOriginMode=Off); cross-origin handshakes are accepted, exposing handlers that rely on ambient cookies/session to Cross-Site WebSocket Hijacking")
		})
		return true
	}
}

// wsOriginHost parses an Origin header and returns its host with the default
// port stripped. It returns ok=false for a missing, opaque, or malformed Origin
// (e.g. "null"), so callers in checking modes fail closed.
func wsOriginHost(origin string) (string, bool) {
	_, host, ok := wsParseOrigin(origin)
	if !ok {
		return "", false
	}
	return host, true
}

// wsParseOrigin splits an origin of the form "scheme://host[:port]" into its
// scheme (lowercased) and host with the scheme's default port removed. ok is
// false if the input is not a well-formed scheme://authority origin (this
// rejects "null", empty, and anything carrying a path/query/fragment).
func wsParseOrigin(origin string) (scheme, host string, ok bool) {
	sep := strings.Index(origin, "://")
	if sep <= 0 {
		return "", "", false
	}
	scheme = strings.ToLower(origin[:sep])
	rest := origin[sep+3:]
	if rest == "" {
		return "", "", false
	}

	// An origin authority carries no path/query/fragment; anything past the
	// host is malformed input, reject it rather than parse leniently.
	if strings.ContainsAny(rest, "/?#") {
		return "", "", false
	}

	host = wsStripSchemeDefaultPort(scheme, rest)
	if host == "" {
		return "", "", false
	}
	return scheme, host, true
}

// wsStripDefaultPort removes a trailing :443 or :80 from a request Host so the
// SameOrigin compare treats an explicit default port as equal to none.
func wsStripDefaultPort(host string) string {
	if h, ok := strings.CutSuffix(host, ":443"); ok {
		return h
	}
	if h, ok := strings.CutSuffix(host, ":80"); ok {
		return h
	}
	return host
}

// wsStripSchemeDefaultPort removes the default port for the given scheme from a
// host:port so "https://app:443" and "https://app" compare equal.
func wsStripSchemeDefaultPort(scheme, host string) string {
	switch scheme {
	case "https", "wss":
		if h, ok := strings.CutSuffix(host, ":443"); ok {
			return h
		}
	case "http", "ws":
		if h, ok := strings.CutSuffix(host, ":80"); ok {
			return h
		}
	}
	return host
}

// NetConn exposes the underlying hijacked connection, e.g. to set per-write
// deadlines so a dead peer cannot block WriteMessage forever.
func (ws *WSConn) NetConn() net.Conn { return ws.conn }

// ReadMessage reads the next WebSocket frame. It returns the opcode (0x1 for
// text, 0x2 for binary), the payload, and any error. Close frames are handled
// automatically — a close reply is sent and io.EOF is returned. Ping frames
// trigger an automatic pong response.
func (ws *WSConn) ReadMessage() (byte, []byte, error) {
	var msgOpcode byte
	var assembled []byte

	for {
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
			payload, err := ws.readFramePayload(header[1], masked)
			if err != nil {
				return 0, nil, err
			}
			if opcode == wsOpClose {
				if len(payload) >= 2 {
					ws.WriteMessage(wsOpClose, payload[:2])
				} else {
					ws.WriteMessage(wsOpClose, nil)
				}
				ws.Close()
				return opcode, payload, io.EOF
			}
			if opcode == wsOpPing {
				ws.WriteMessage(wsOpPong, payload)
			}
			continue
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

		if int64(len(assembled)) > 16*1024*1024 {
			ws.Close()
			return 0, nil, ErrBodyTooLarge
		}

		if fin {
			return msgOpcode, assembled, nil
		}
	}
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

	if payloadLen > 16*1024*1024 {
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

// WriteMessage writes a WebSocket frame with the given opcode and payload.
// Typically use WriteText or WriteBinary instead of calling this directly.
func (ws *WSConn) WriteMessage(opcode byte, data []byte) error {
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
	err := writeFull(ws.conn, buf)
	*bp = buf[:0]
	MediumBufPool.Put(bp)
	return err
}

// WriteText sends a text WebSocket frame.
//
//	ws.WriteText("hello client")
func (ws *WSConn) WriteText(msg string) error {
	return ws.WriteMessage(wsOpText, UnsafeBytes(msg))
}

// WriteBinary sends a binary WebSocket frame.
func (ws *WSConn) WriteBinary(data []byte) error {
	return ws.WriteMessage(wsOpBinary, data)
}

// Ping sends a WebSocket ping frame to the client. The client should respond
// with a pong automatically.
func (ws *WSConn) Ping() error {
	return ws.WriteMessage(wsOpPing, nil)
}

// Close sends a close frame and closes the underlying connection. Safe to call
// multiple times.
func (ws *WSConn) Close() error {
	if ws.closed.CompareAndSwap(false, true) {
		ws.WriteMessage(wsOpClose, nil)
		return ws.conn.Close()
	}
	return nil
}

// SetDeadline sets the read and write deadline on the underlying connection.
func (ws *WSConn) SetDeadline(t time.Time) error {
	return ws.conn.SetDeadline(t)
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
