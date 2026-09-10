//go:build linux && amd64

package core

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestH2EmptyDataEndStreamDoesNotEmitZeroWindowUpdate(t *testing.T) {
	addr := startPlainRouteTLSServer(t)
	for i := 0; i < 3; i++ {
		body := io.NopCloser(strings.NewReader("h2-unknown-length-body"))
		req, err := http.NewRequest("POST", "https://"+addr+"/echo", body)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Host = "stray.test"
		resp, err := h2ProxyClient("stray.test").Do(req)
		if err != nil {
			t.Fatalf("POST with an unknown-length body over HTTP/2 failed (the client ends the body with an empty DATA+END_STREAM frame): %v", err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("negotiated HTTP/%d", resp.ProtoMajor)
		}
		if string(got) != "h2-unknown-length-body" {
			t.Fatalf("echo = %q", got)
		}
	}
}
