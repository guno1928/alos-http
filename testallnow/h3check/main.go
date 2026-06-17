// Command h3check is an end-to-end HTTP/3 conformance probe for the ALOS QUIC
// server. The framework's QUIC/HTTP-3 stack is hand-written and cannot be
// exercised by the plain TCP-based test runner, so this binary spins up a real
// ALOS QUIC server and drives it with the third-party quic-go HTTP/3 client.
//
// It verifies, among other things, that a connection survives a peer-initiated
// QUIC key update (RFC 9001 §6) — the regression that previously wedged the
// connection after the first large response.
//
// Requires Linux + io_uring (the ALOS QUIC listener is io_uring-only). Exits
// non-zero if any check fails.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	core "github.com/guno1928/alos-http/core"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const addr = "127.0.0.1:18553"

func main() {
	os.Exit(run())
}

func run() int {
	cfg := core.Config{
		Addr:         addr,
		IdleTimeout:  30 * time.Second,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		MaxBodySize:  20 << 20,
		WorkerCount:  4,
		Listeners:    1,
		ServerName:   "ALOS-H3-Check",
		Certs:        []core.CertConfig{{Domain: "localhost", Source: core.CertSelfSigned}},
	}
	s := core.New(cfg)
	s.Router.GET("/hello", func(req *core.Request, resp *core.Response) {
		resp.Status(200).String("hello-over-h3")
	})
	s.Router.POST("/echo", func(req *core.Request, resp *core.Response) {
		resp.Status(200).Bytes(req.Body)
	})
	big := strings.Repeat("A", 512<<10) // 512 KiB: spans many packets + a key update
	s.Router.GET("/big", func(req *core.Request, resp *core.Response) {
		resp.Status(200).String(big)
	})
	// 8 MiB exceeds the peer's initial flow-control window many times over, so it
	// exercises flow control, congestion control, and loss recovery end to end.
	huge := strings.Repeat("B", 8<<20)
	s.Router.GET("/huge", func(req *core.Request, resp *core.Response) {
		resp.Status(200).String(huge)
	})

	go func() { _ = s.ListenAndServeQUIC() }()
	time.Sleep(1500 * time.Millisecond)

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 20 * time.Second},
	}
	defer rt.Close()
	client := &http.Client{Transport: rt, Timeout: 20 * time.Second}

	fails := 0
	check := func(name string, ok bool, detail string) {
		if ok {
			fmt.Printf("PASS  %s\n", name)
			return
		}
		fmt.Printf("FAIL  %s — %s\n", name, detail)
		fails++
	}

	body, proto, err := do(client, "GET", "https://"+addr+"/hello", nil)
	check("GET /hello (handshake + HTTP/3)", err == nil && proto == "HTTP/3.0" && body == "hello-over-h3",
		fmt.Sprintf("proto=%q body=%q err=%v", proto, body, err))

	payload := strings.Repeat("payload-", 4096) // 32 KiB
	body, _, err = do(client, "POST", "https://"+addr+"/echo", []byte(payload))
	check("POST /echo (32 KiB round-trip)", err == nil && body == payload,
		fmt.Sprintf("len=%d err=%v", len(body), err))

	body, _, err = do(client, "GET", "https://"+addr+"/big", nil)
	check("GET /big (512 KiB integrity, spans key update)",
		err == nil && len(body) == 512<<10 && strings.Trim(body, "A") == "",
		fmt.Sprintf("len=%d err=%v", len(body), err))

	body, _, err = do(client, "GET", "https://"+addr+"/big", nil)
	_ = body
	body, _, err = do(client, "GET", "https://"+addr+"/huge", nil)
	check("GET /huge (8 MiB integrity, flow + congestion control)",
		err == nil && len(body) == 8<<20 && strings.Trim(body, "B") == "",
		fmt.Sprintf("len=%d err=%v", len(body), err))

	body, _, err = do(client, "GET", "https://"+addr+"/hello", nil)
	check("GET /hello after /huge (connection still usable)",
		err == nil && body == "hello-over-h3", fmt.Sprintf("body=%q err=%v", body, err))

	// Several multi-MB responses concurrently: stresses per-stream + connection
	// flow control and the shared congestion window together.
	var hugeWg sync.WaitGroup
	var hugeMu sync.Mutex
	hugeOK := 0
	for i := 0; i < 6; i++ {
		hugeWg.Add(1)
		go func() {
			defer hugeWg.Done()
			b, _, e := do(client, "GET", "https://"+addr+"/huge", nil)
			if e == nil && len(b) == 8<<20 {
				hugeMu.Lock()
				hugeOK++
				hugeMu.Unlock()
			}
		}()
	}
	hugeWg.Wait()
	check(fmt.Sprintf("6x 8 MiB concurrent (%d/6)", hugeOK), hugeOK == 6,
		fmt.Sprintf("%d/6 succeeded", hugeOK))

	const n = 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, _, e := do(client, "GET", "https://"+addr+"/hello", nil)
			if e == nil && b == "hello-over-h3" {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	check(fmt.Sprintf("%d concurrent requests after key update", n), ok == n,
		fmt.Sprintf("%d/%d succeeded", ok, n))

	if fails == 0 {
		fmt.Println("\nRESULT: ALL HTTP/3 CHECKS PASSED")
		return 0
	}
	fmt.Printf("\nRESULT: %d HTTP/3 CHECK(S) FAILED\n", fails)
	return 1
}

func do(c *http.Client, method, url string, reqBody []byte) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var r io.Reader
	if reqBody != nil {
		r = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return "", "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), resp.Proto, nil
}
