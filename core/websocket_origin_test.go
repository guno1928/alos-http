package core

import "testing"

func wsTestRequest(host, origin string, mode WSOriginMode, allowed []string) *Request {
	req := &Request{
		Host:   host,
		server: &Server{config: Config{WebSocketOriginMode: mode, AllowedWebSocketOrigins: allowed}},
	}
	if origin != "" {
		req.Headers = append(req.Headers, [2]string{"Origin", origin})
	}
	return req
}

func TestCheckWebSocketOriginOff(t *testing.T) {
	cases := []struct {
		name   string
		origin string
	}{
		{"matching", "https://example.com"},
		{"cross-origin", "https://evil.example"},
		{"missing", ""},
		{"garbage", "not an origin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := wsTestRequest("example.com", tc.origin, WSOriginModeOff, nil)
			if !checkWebSocketOrigin(req) {
				t.Fatalf("Off mode must accept origin %q", tc.origin)
			}
		})
	}
}

func TestCheckWebSocketOriginSameOrigin(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"exact match", "example.com", "https://example.com", true},
		{"scheme agnostic", "example.com", "http://example.com", true},
		{"default port on origin", "example.com", "https://example.com:443", true},
		{"default port on host", "example.com:443", "https://example.com", true},
		{"case insensitive host", "Example.COM", "https://example.com", true},
		{"explicit nondefault port match", "example.com:8443", "https://example.com:8443", true},
		{"cross origin", "example.com", "https://evil.example", false},
		{"port mismatch", "example.com:8443", "https://example.com", false},
		{"missing origin", "example.com", "", false},
		{"garbage origin", "example.com", "garbage", false},
		{"null origin", "example.com", "null", false},
		{"origin with path", "example.com", "https://example.com/evil", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := wsTestRequest(tc.host, tc.origin, WSOriginModeSameOrigin, nil)
			if got := checkWebSocketOrigin(req); got != tc.want {
				t.Fatalf("SameOrigin host=%q origin=%q: got %v want %v", tc.host, tc.origin, got, tc.want)
			}
		})
	}
}

func TestCheckWebSocketOriginAllowlist(t *testing.T) {
	allowed := []string{"https://app.example.com", "https://admin.example.com:8443"}
	cases := []struct {
		name   string
		origin string
		want   bool
	}{
		{"listed", "https://app.example.com", true},
		{"listed case insensitive", "HTTPS://APP.EXAMPLE.COM", true},
		{"listed default port explicit", "https://app.example.com:443", true},
		{"listed nondefault port", "https://admin.example.com:8443", true},
		{"unlisted host", "https://other.example.com", false},
		{"unlisted scheme", "http://app.example.com", false},
		{"port mismatch", "https://admin.example.com", false},
		{"missing", "", false},
		{"garbage", "%%%", false},
		{"null", "null", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := wsTestRequest("app.example.com", tc.origin, WSOriginModeAllowlist, allowed)
			if got := checkWebSocketOrigin(req); got != tc.want {
				t.Fatalf("Allowlist origin=%q: got %v want %v", tc.origin, got, tc.want)
			}
		})
	}
}

func TestWSParseOrigin(t *testing.T) {
	cases := []struct {
		in     string
		scheme string
		host   string
		ok     bool
	}{
		{"https://example.com", "https", "example.com", true},
		{"HTTPS://Example.com:443", "https", "Example.com", true},
		{"http://example.com:80", "http", "example.com", true},
		{"http://example.com:8080", "http", "example.com:8080", true},
		{"wss://example.com:443", "wss", "example.com", true},
		{"ws://example.com:80", "ws", "example.com", true},
		{"https://example.com:443/path", "", "", false},
		{"https://", "", "", false},
		{"://example.com", "", "", false},
		{"null", "", "", false},
		{"", "", "", false},
		{"example.com", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			scheme, host, ok := wsParseOrigin(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok: got %v want %v", ok, tc.ok)
			}
			if !ok {
				return
			}
			if scheme != tc.scheme || host != tc.host {
				t.Fatalf("got scheme=%q host=%q want scheme=%q host=%q", scheme, host, tc.scheme, tc.host)
			}
		})
	}
}
