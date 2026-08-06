package correctness_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/guno1928/alos-http/core"
)

func TestStatusTextMatrix(t *testing.T) {
	cases := map[int]string{
		200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
		301: "Moved Permanently", 302: "Found", 304: "Not Modified",
		400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
		405: "Method Not Allowed", 408: "Request Timeout", 413: "Payload Too Large",
		416: "Range Not Satisfiable", 429: "Too Many Requests",
		431: "Request Header Fields Too Large", 500: "Internal Server Error",
		502: "Bad Gateway", 503: "Service Unavailable",
	}
	for code, want := range cases {
		t.Run(fmt.Sprintf("status_%d", code), func(t *testing.T) {
			if got := core.StatusText(code); got != want {
				t.Fatalf("StatusText(%d) = %q, want %q", code, got, want)
			}
		})
	}
	for _, code := range []int{-1, 0, 99, 100, 199, 202, 299, 305, 399, 402, 499, 501, 599, 600} {
		t.Run(fmt.Sprintf("unknown_%d", code), func(t *testing.T) {
			if got := core.StatusText(code); got != "Unknown" {
				t.Fatalf("StatusText(%d) = %q", code, got)
			}
		})
	}
}

func TestJSONStringCompatibilityMatrix(t *testing.T) {
	values := []string{"", "plain", "quote\"", "slash\\", "line\nfeed", "tab\tvalue", "carriage\rreturn", "nul\x00byte", "emoji-😀", "日本語", "<script>", "a/b/c"}
	for i := 0; i < 84; i++ {
		values = append(values, fmt.Sprintf("case-%03d-%c-%c", i, byte(i%32), byte(32+i%90)))
	}
	for i, value := range values {
		t.Run(fmt.Sprintf("json_%03d", i), func(t *testing.T) {
			got := core.AppendJSONString(nil, value)
			want, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var gotValue string
			if err := json.Unmarshal(got, &gotValue); err != nil {
				t.Fatalf("invalid JSON %q: %v", got, err)
			}
			if gotValue != value {
				t.Fatalf("round trip = %q, want %q", gotValue, value)
			}
			if strings.ContainsAny(value, "<>&") || strings.IndexFunc(value, func(r rune) bool { return r < 0x20 }) >= 0 {
				return
			}
			if string(got) != string(want) {
				t.Fatalf("encoding = %q, want %q", got, want)
			}
		})
	}
}

func TestHostValidationMatrix(t *testing.T) {
	valid := []string{"", "localhost", "example.com", "example.com:443", "127.0.0.1", "[::1]:8443", "xn--bcher-kva.example", "UPPER.EXAMPLE"}
	for i := 0; i < 32; i++ {
		valid = append(valid, fmt.Sprintf("node-%02d.service.internal:%d", i, 8000+i))
	}
	for i, host := range valid {
		t.Run(fmt.Sprintf("valid_%02d", i), func(t *testing.T) {
			if !core.ValidateHost(host) {
				t.Fatalf("valid host rejected: %q", host)
			}
		})
	}
	invalid := []string{"a/b", `a\b`, "a\rb", "a\nb", "a\x00b", "/", `\`, "host/path", "host\\path"}
	for i, host := range invalid {
		t.Run(fmt.Sprintf("invalid_%02d", i), func(t *testing.T) {
			if core.ValidateHost(host) {
				t.Fatalf("invalid host accepted: %q", host)
			}
		})
	}
}

func TestRequestQueryMatrix(t *testing.T) {
	for i := 0; i < 64; i++ {
		key := fmt.Sprintf("key %d", i)
		value := fmt.Sprintf("value/%d+%s", i, strings.Repeat("x", i%9))
		query := url.Values{key: {value, value + "-second"}}
		req := &core.Request{Query: query.Encode()}
		t.Run(fmt.Sprintf("query_%02d", i), func(t *testing.T) {
			if got := req.QueryParam(key); got != value {
				t.Fatalf("QueryParam(%q) = %q, want %q", key, got, value)
			}
			if got := req.QueryParamAll(key); !reflect.DeepEqual(got, []string{value, value + "-second"}) {
				t.Fatalf("QueryParamAll(%q) = %#v", key, got)
			}
			if got := req.QueryParam("missing"); got != "" {
				t.Fatalf("missing query value = %q", got)
			}
		})
	}
}

func TestRequestStateResetMatrix(t *testing.T) {
	for i := 0; i < 32; i++ {
		req := &core.Request{
			Method:  "POST",
			Path:    fmt.Sprintf("/resource/%d", i),
			Query:   "q=value",
			Headers: [][2]string{{"X-Test", "value"}},
			Body:    []byte(strings.Repeat("b", i+1)),
		}
		req.SetParam("id", fmt.Sprint(i))
		req.Set("state", i)
		_ = req.QueryParam("q")
		t.Run(fmt.Sprintf("reset_%02d", i), func(t *testing.T) {
			req.Reset()
			if req.Method != "" || req.Path != "" || req.Query != "" || len(req.Headers) != 0 || len(req.Body) != 0 || req.ParamCount != 0 {
				t.Fatalf("request retained state: %#v", req)
			}
			if _, ok := req.Get("state"); ok {
				t.Fatal("request store retained state")
			}
			if got := req.QueryParam("q"); got != "" {
				t.Fatalf("query cache retained %q", got)
			}
		})
	}
}

func TestResponseRepresentationMatrix(t *testing.T) {
	types := []struct {
		name        string
		contentType string
		set         func(*core.Response, string)
	}{
		{"text", "text/plain; charset=utf-8", func(r *core.Response, s string) { r.String(s) }},
		{"html", "text/html; charset=utf-8", func(r *core.Response, s string) { r.HTML(s) }},
		{"json", "application/json; charset=utf-8", func(r *core.Response, s string) { r.JSONString(s) }},
		{"bytes", "application/octet-stream", func(r *core.Response, s string) { r.Bytes([]byte(s)) }},
	}
	for i := 0; i < 16; i++ {
		for _, typ := range types {
			name := fmt.Sprintf("%s_%02d", typ.name, i)
			t.Run(name, func(t *testing.T) {
				body := fmt.Sprintf("payload-%d-%s", i, strings.Repeat("x", i))
				resp := &core.Response{}
				resp.Reset()
				resp.Status(200 + i%6)
				typ.set(resp, body)
				if string(resp.GetBody()) != body || resp.BodyLen() != len(body) {
					t.Fatalf("body mismatch: %q, %d", resp.GetBody(), resp.BodyLen())
				}
				if resp.ContentType != typ.contentType {
					t.Fatalf("content type = %q, want %q", resp.ContentType, typ.contentType)
				}
			})
		}
	}
}

func TestResponseHeaderSanitizationMatrix(t *testing.T) {
	bad := []string{"line\rbreak", "line\nbreak", "nul\x00value", "all\r\n\x00three"}
	for i := 0; i < 32; i++ {
		value := fmt.Sprintf("value-%d-%s", i, bad[i%len(bad)])
		t.Run(fmt.Sprintf("header_%02d", i), func(t *testing.T) {
			resp := &core.Response{}
			resp.SetHeader("X-Test\r\n", value)
			if len(resp.Headers) != 1 {
				t.Fatalf("headers = %d", len(resp.Headers))
			}
			if strings.ContainsAny(resp.Headers[0][0], "\r\n\x00") || strings.ContainsAny(resp.Headers[0][1], "\r\n\x00") {
				t.Fatalf("unsafe header survived: %#v", resp.Headers[0])
			}
		})
	}
}
