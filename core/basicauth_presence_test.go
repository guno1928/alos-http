//go:build linux && amd64

package core

import (
	"encoding/base64"
	"testing"
)

func basicAuthRequest(user, password string) *Request {
	req := newTestReq()
	req.Headers = append(req.Headers, [2]string{"authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))})
	return req
}

func TestBasicAuthEmptyCredentials(t *testing.T) {
	cases := []struct {
		name       string
		users      map[string]string
		user       string
		password   string
		wantStatus int
	}{
		{"empty configured username", map[string]string{"": "test-password"}, "", "test-password", 200},
		{"empty configured password", map[string]string{"test-user": ""}, "test-user", "", 200},
		{"both configured empty", map[string]string{"": ""}, "", "", 200},
		{"wrong empty password", map[string]string{"test-user": "test-password"}, "test-user", "", 401},
		{"unknown empty username", map[string]string{"test-user": "test-password"}, "", "test-password", 401},
		{"unknown empty password", map[string]string{"test-user": ""}, "unknown", "", 401},
		{"empty user map", nil, "", "", 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := BasicAuth(BasicAuthConfig{Users: tc.users})(func(_ *Request, resp *Response) {
				called = true
				resp.Status(200)
			})
			resp := newTestResp()
			handler(basicAuthRequest(tc.user, tc.password), resp)
			if resp.StatusCode != tc.wantStatus || called != (tc.wantStatus == 200) {
				t.Fatalf("status=%d called=%v, want status=%d", resp.StatusCode, called, tc.wantStatus)
			}
		})
	}
}

func BenchmarkBasicAuthUserPresence(b *testing.B) {
	handler := BasicAuth(BasicAuthConfig{Users: map[string]string{"admin": "secret"}})(func(_ *Request, resp *Response) { resp.Status(200) })
	for _, tc := range []struct{ name, user, password string }{
		{"known_wrong_password", "admin", "guess"},
		{"unknown_user", "nobody", "guess"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			req := basicAuthRequest(tc.user, tc.password)
			resp := newTestResp()
			b.ReportAllocs()
			for b.Loop() {
				resp.StatusCode = 0
				resp.Headers = resp.Headers[:0]
				resp.body = resp.body[:0]
				handler(req, resp)
			}
			if resp.StatusCode != 401 {
				b.Fatalf("status %d, want 401", resp.StatusCode)
			}
		})
	}
}
