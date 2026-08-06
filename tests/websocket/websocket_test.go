package websocket_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func handshake(headers [][2]string) *core.Response {
	req := &core.Request{Method: "GET", Path: "/ws", Host: "example.test", Headers: headers}
	resp := &core.Response{}
	resp.Reset()
	if core.UpgradeWebSocket(req, resp) != nil {
		panic("handshake unexpectedly returned a connection")
	}
	return resp
}

func validHeaders() [][2]string {
	return [][2]string{
		{"Upgrade", "websocket"},
		{"Connection", "keep-alive, Upgrade"},
		{"Sec-WebSocket-Key", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))},
		{"Sec-WebSocket-Version", "13"},
	}
}

func TestWebSocketUpgradeHeaderMatrix(t *testing.T) {
	values := []string{"", "h2c", "WebSocketx", "web socket", "upgrade", "HTTP/1.1", "websocket, h2c", " websocket "}
	for repeat := 0; repeat < 4; repeat++ {
		for i, value := range values {
			value := value
			t.Run(fmt.Sprintf("upgrade_%02d_%d", repeat, i), func(t *testing.T) {
				h := validHeaders()
				h[0][1] = value
				resp := handshake(h)
				if resp.StatusCode != 400 || string(resp.GetBody()) != "not a websocket request" {
					t.Fatalf("status=%d body=%q", resp.StatusCode, resp.GetBody())
				}
			})
		}
	}
}

func TestWebSocketKeyValidationMatrix(t *testing.T) {
	for length := 0; length <= 32; length++ {
		length := length
		t.Run(fmt.Sprintf("key_length_%02d", length), func(t *testing.T) {
			h := validHeaders()
			h[2][1] = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", length)))
			resp := handshake(h)
			if length == 16 {
				if resp.StatusCode != 500 || string(resp.GetBody()) != "connection hijack failed" {
					t.Fatalf("valid key did not reach hijack: status=%d body=%q", resp.StatusCode, resp.GetBody())
				}
				return
			}
			if resp.StatusCode != 400 {
				t.Fatalf("invalid key length %d returned %d", length, resp.StatusCode)
			}
		})
	}
	for i, key := range []string{"%%%%", "not-base64", "=broken", "AAAA", "AA=A", "!!!!"} {
		t.Run(fmt.Sprintf("invalid_base64_%d", i), func(t *testing.T) {
			h := validHeaders()
			h[2][1] = key
			if resp := handshake(h); resp.StatusCode != 400 {
				t.Fatalf("invalid key returned %d", resp.StatusCode)
			}
		})
	}
}

func TestWebSocketConnectionTokenMatrix(t *testing.T) {
	valid := []string{"Upgrade", "upgrade", "keep-alive, Upgrade", "Upgrade, keep-alive", "close,upgrade", "keep-alive, upgrade, test"}
	for i, value := range valid {
		t.Run(fmt.Sprintf("valid_%d", i), func(t *testing.T) {
			h := validHeaders()
			h[1][1] = value
			if resp := handshake(h); resp.StatusCode != 500 {
				t.Fatalf("valid token returned %d", resp.StatusCode)
			}
		})
	}
	invalid := []string{"", "keep-alive", "upgrader", "xupgrade", "upgrade-x", "close"}
	for i, value := range invalid {
		t.Run(fmt.Sprintf("invalid_%d", i), func(t *testing.T) {
			h := validHeaders()
			h[1][1] = value
			if resp := handshake(h); resp.StatusCode != 400 {
				t.Fatalf("invalid token returned %d", resp.StatusCode)
			}
		})
	}
}

func TestWebSocketVersionCorrectionMatrix(t *testing.T) {
	versions := []string{"", "1", "7", "8", "12", "14", "13.0", " 13", "13 ", "v13"}
	for i, version := range versions {
		t.Run(fmt.Sprintf("version_%02d", i), func(t *testing.T) {
			h := validHeaders()
			h[3][1] = version
			resp := handshake(h)
			if resp.StatusCode != 426 || len(resp.Headers) != 1 || resp.Headers[0] != [2]string{"Sec-WebSocket-Version", "13"} {
				t.Fatalf("status=%d headers=%v", resp.StatusCode, resp.Headers)
			}
		})
	}
}
