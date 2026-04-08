package core

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-5AB5DC11650B"

const (
	wsOpContinuation byte = 0x0
	wsOpText         byte = 0x1
	wsOpBinary       byte = 0x2
	wsOpClose        byte = 0x8
	wsOpPing         byte = 0x9
	wsOpPong         byte = 0xA
)

// WSConn is a server-side WebSocket connection (RFC 6455). Create one by calling
// UpgradeWebSocket inside a route handler, then use ReadMessage and WriteMessage
// (or WriteText / WriteBinary) to exchange data.
//
//	ws := core.UpgradeWebSocket(req, resp)
//	if ws == nil {
//	    return
//	}
//	defer ws.Close()
//	for {
//	    op, msg, err := ws.ReadMessage()
//	    if err != nil {
//	        break
//	    }
//	    ws.WriteText("echo: " + string(msg))
//	}
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
//	r.GET("/ws", func(req *core.Request, resp *core.Response) {
//	    ws := core.UpgradeWebSocket(req, resp)
//	    if ws == nil {
//	        return
//	    }
//	    defer ws.Close()
//	    for {
//	        _, msg, err := ws.ReadMessage()
//	        if err != nil {
//	            break
//	        }
//	        ws.WriteText(string(msg))
//	    }
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

	conn := req.HijackConn()
	if conn == nil {
		resp.Status(500).String("connection hijack failed")
		return nil
	}

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

// ReadMessage reads the next WebSocket frame. It returns the opcode (0x1 for
// text, 0x2 for binary), the payload, and any error. Close frames are handled
// automatically — a close reply is sent and io.EOF is returned. Ping frames
// trigger an automatic pong response.
func (ws *WSConn) ReadMessage() (byte, []byte, error) {
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
	if !fin || opcode == wsOpContinuation {
		ws.Close()
		return 0, nil, ErrWebSocketProtocol
	}
	switch opcode {
	case wsOpText, wsOpBinary, wsOpClose, wsOpPing, wsOpPong:
	default:
		ws.Close()
		return 0, nil, ErrWebSocketProtocol
	}
	if !masked {
		ws.Close()
		return 0, nil, ErrWebSocketProtocol
	}
	payloadLen := int64(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(ws.conn, ext[:]); err != nil {
			return 0, nil, err
		}
		payloadLen = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(ws.conn, ext[:]); err != nil {
			return 0, nil, err
		}
		payloadLen = int64(ext[0])<<56 | int64(ext[1])<<48 | int64(ext[2])<<40 | int64(ext[3])<<32 |
			int64(ext[4])<<24 | int64(ext[5])<<16 | int64(ext[6])<<8 | int64(ext[7])
		if payloadLen < 0 {
			ws.Close()
			return 0, nil, ErrBodyTooLarge
		}
	}

	if payloadLen > 16*1024*1024 {
		ws.Close()
		return 0, nil, ErrBodyTooLarge
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(ws.conn, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(ws.conn, payload); err != nil {
			return 0, nil, err
		}
	}

	if masked {
		maskXOR(payload, maskKey)
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

	return opcode, payload, nil
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
