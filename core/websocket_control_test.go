package core

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// maskedFrame builds a client-to-server WebSocket frame with the given FIN bit,
// opcode, and payload. The payload is masked as RFC 6455 requires for
// client-originated frames. payloadLenField lets a test forge a length field
// that disagrees with the actual payload (to exercise the pre-allocation gate
// without ever sending the bytes).
func maskedFrame(fin bool, opcode byte, payload []byte, payloadLenField int) []byte {
	first := opcode
	if fin {
		first |= 0x80
	}

	frame := []byte{first}

	maskBit := byte(0x80)
	switch {
	case payloadLenField <= 125:
		frame = append(frame, maskBit|byte(payloadLenField))
	case payloadLenField <= 65535:
		frame = append(frame, maskBit|126, byte(payloadLenField>>8), byte(payloadLenField))
	default:
		frame = append(frame, maskBit|127,
			byte(payloadLenField>>56), byte(payloadLenField>>48), byte(payloadLenField>>40), byte(payloadLenField>>32),
			byte(payloadLenField>>24), byte(payloadLenField>>16), byte(payloadLenField>>8), byte(payloadLenField))
	}

	mask := [4]byte{0xA1, 0xB2, 0xC3, 0xD4}
	frame = append(frame, mask[:]...)

	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	frame = append(frame, masked...)
	return frame
}

// readServerFrame parses a single unmasked server-to-client frame from r.
func readServerFrame(t *testing.T, r io.Reader) (opcode byte, payload []byte) {
	t.Helper()

	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatalf("read server frame header: %v", err)
	}
	opcode = header[0] & 0x0F

	length := int(header[1] & 0x7F)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			t.Fatalf("read ext len: %v", err)
		}
		length = int(ext[0])<<8 | int(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			t.Fatalf("read ext len: %v", err)
		}
		length = 0
		for _, b := range ext {
			length = length<<8 | int(b)
		}
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			t.Fatalf("read server payload: %v", err)
		}
	}
	return opcode, payload
}

// wsTestConn pairs a WSConn (server side) with the client end of a net.Pipe.
func wsTestConn(t *testing.T) (*WSConn, net.Conn) {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	ws := &WSConn{conn: serverEnd}
	_ = ws.SetDeadline(time.Now().Add(2 * time.Second))
	_ = clientEnd.SetDeadline(time.Now().Add(2 * time.Second))
	return ws, clientEnd
}

// TestControlFrameOversizedPingRejected verifies that a PING with a length
// field of 126 is rejected as a protocol error before the payload is read or
// echoed.
func TestControlFrameOversizedPingRejected(t *testing.T) {
	ws, client := wsTestConn(t)
	defer client.Close()

	// Length field claims 126 (> 125), so the gate must fire before reading
	// any payload. We send the mask bytes (which the synchronous pipe needs
	// drained) but no payload — proving the server rejects on the parsed
	// length field alone, before allocating/reading 126 bytes.
	frame := maskedFrame(true, wsOpPing, nil, 126)

	done := make(chan struct{})
	var readErr error
	go func() {
		_, _, readErr = ws.ReadMessage()
		close(done)
	}()

	// Write from a goroutine: net.Pipe is synchronous and the server rejects
	// before draining the whole frame, so a foreground write would deadlock
	// or error once the server closes the pipe.
	go client.Write(frame)

	// Server must send a close frame (status 1002), never a pong echo.
	opcode, payload := readServerFrame(t, client)
	if opcode != wsOpClose {
		t.Fatalf("expected close frame (0x8), got opcode 0x%X", opcode)
	}
	if len(payload) < 2 || uint16(payload[0])<<8|uint16(payload[1]) != wsStatusProtocolError {
		t.Fatalf("expected close status 1002, got payload %v", payload)
	}

	<-done
	if !errors.Is(readErr, ErrWebSocketProtocol) {
		t.Fatalf("expected ErrWebSocketProtocol, got %v", readErr)
	}
}

// TestFragmentedControlFrameRejected verifies a control frame with FIN=0 is
// rejected.
func TestFragmentedControlFrameRejected(t *testing.T) {
	ws, client := wsTestConn(t)
	defer client.Close()

	frame := maskedFrame(false, wsOpPing, []byte("hi"), 2)

	done := make(chan struct{})
	var readErr error
	go func() {
		_, _, readErr = ws.ReadMessage()
		close(done)
	}()

	go client.Write(frame)

	opcode, payload := readServerFrame(t, client)
	if opcode != wsOpClose {
		t.Fatalf("expected close frame, got opcode 0x%X", opcode)
	}
	if len(payload) < 2 || uint16(payload[0])<<8|uint16(payload[1]) != wsStatusProtocolError {
		t.Fatalf("expected close status 1002, got payload %v", payload)
	}

	<-done
	if !errors.Is(readErr, ErrWebSocketProtocol) {
		t.Fatalf("expected ErrWebSocketProtocol, got %v", readErr)
	}
}

// TestReservedControlOpcodeRejected verifies an undefined control opcode
// (0xB-0xF) is rejected.
func TestReservedControlOpcodeRejected(t *testing.T) {
	ws, client := wsTestConn(t)
	defer client.Close()

	const reservedOpcode byte = 0xB
	frame := maskedFrame(true, reservedOpcode, nil, 0)

	done := make(chan struct{})
	var readErr error
	go func() {
		_, _, readErr = ws.ReadMessage()
		close(done)
	}()

	go client.Write(frame)

	opcode, payload := readServerFrame(t, client)
	if opcode != wsOpClose {
		t.Fatalf("expected close frame, got opcode 0x%X", opcode)
	}
	if len(payload) < 2 || uint16(payload[0])<<8|uint16(payload[1]) != wsStatusProtocolError {
		t.Fatalf("expected close status 1002, got payload %v", payload)
	}

	<-done
	if !errors.Is(readErr, ErrWebSocketProtocol) {
		t.Fatalf("expected ErrWebSocketProtocol, got %v", readErr)
	}
}

// TestValidPingAnswered verifies a 125-byte ping (the maximum allowed control
// payload) is still answered with a pong echoing the payload.
func TestValidPingAnswered(t *testing.T) {
	ws, client := wsTestConn(t)
	defer client.Close()

	pingPayload := make([]byte, 125)
	for i := range pingPayload {
		pingPayload[i] = byte(i)
	}
	pingFrame := maskedFrame(true, wsOpPing, pingPayload, len(pingPayload))

	// Follow the ping with a text frame so ReadMessage returns after handling
	// the ping internally.
	textFrame := maskedFrame(true, wsOpText, []byte("done"), len("done"))

	type result struct {
		opcode  byte
		payload []byte
		err     error
	}
	resCh := make(chan result, 1)
	go func() {
		op, p, err := ws.ReadMessage()
		resCh <- result{op, p, err}
	}()

	if _, err := client.Write(pingFrame); err != nil {
		t.Fatalf("write ping: %v", err)
	}

	// Server must answer the ping with a pong echoing the payload.
	opcode, payload := readServerFrame(t, client)
	if opcode != wsOpPong {
		t.Fatalf("expected pong (0xA), got opcode 0x%X", opcode)
	}
	if string(payload) != string(pingPayload) {
		t.Fatalf("pong payload mismatch: got %d bytes", len(payload))
	}

	if _, err := client.Write(textFrame); err != nil {
		t.Fatalf("write text: %v", err)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("ReadMessage returned error: %v", res.err)
	}
	if res.opcode != wsOpText || string(res.payload) != "done" {
		t.Fatalf("expected text 'done', got opcode 0x%X payload %q", res.opcode, res.payload)
	}
}
