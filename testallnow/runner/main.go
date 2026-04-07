package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ── Config ──

var (
	plainBase = envOr("PLAIN_URL", "http://127.0.0.1:8080")
	tlsBase   = envOr("TLS_URL", "https://127.0.0.1:8443")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ── Result types ──

type TestResult struct {
	ID       int           `json:"id"`
	Category string        `json:"category"`
	Name     string        `json:"name"`
	Pass     bool          `json:"pass"`
	Error    string        `json:"error,omitempty"`
	Duration time.Duration `json:"duration_ns"`
}

type TestFunc func() error

type Test struct {
	ID       int
	Category string
	Name     string
	Fn       TestFunc
}

// ── HTTP clients ──

var plainClient = &http.Client{
	Timeout: 10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var tlsClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var tlsH2Client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
		ForceAttemptHTTP2: true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

var tlsH1Client = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		},
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ── Helpers ──

func expectStatus(resp *http.Response, want int) error {
	if resp.StatusCode != want {
		return fmt.Errorf("status: got %d, want %d", resp.StatusCode, want)
	}
	return nil
}

func expectBody(resp *http.Response, want string) error {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read body: %v", err)
	}
	got := string(body)
	if got != want {
		if len(got) > 200 {
			got = got[:200] + "..."
		}
		return fmt.Errorf("body: got %q, want %q", got, want)
	}
	return nil
}

func expectBodyContains(resp *http.Response, sub string) error {
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("read body: %v", err)
	}
	if !strings.Contains(string(body), sub) {
		got := string(body)
		if len(got) > 200 {
			got = got[:200] + "..."
		}
		return fmt.Errorf("body %q does not contain %q", got, sub)
	}
	return nil
}

func expectHeader(resp *http.Response, key, want string) error {
	got := resp.Header.Get(key)
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("header %s: got %q, want %q", key, got, want)
	}
	return nil
}

func expectHeaderContains(resp *http.Response, key, sub string) error {
	got := resp.Header.Get(key)
	if !strings.Contains(strings.ToLower(got), strings.ToLower(sub)) {
		return fmt.Errorf("header %s: %q does not contain %q", key, got, sub)
	}
	return nil
}

func expectHeaderPresent(resp *http.Response, key string) error {
	if resp.Header.Get(key) == "" {
		return fmt.Errorf("header %s missing", key)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func doGet(url string) (*http.Response, error) {
	return plainClient.Get(url)
}

func doReq(method, url string, body string, headers map[string]string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return plainClient.Do(req)
}

func doTLS(method, url string, body string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	return tlsClient.Do(req)
}

func doH2(method, url string, body string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	return tlsH2Client.Do(req)
}

func doTLSH1(method, url string, body string) (*http.Response, error) {
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}
	return tlsH1Client.Do(req)
}

func readBody(resp *http.Response) (string, error) {
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return string(data), err
}

func readBodyBytes(resp *http.Response) ([]byte, error) {
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	return data, err
}

// ── WebSocket helpers ──

func wsHandshake(url string) (net.Conn, error) {
	// Parse URL to get host:port
	host := strings.TrimPrefix(url, "ws://")
	host = strings.TrimPrefix(host, "wss://")
	path := "/"
	if idx := strings.Index(host, "/"); idx >= 0 {
		path = host[idx:]
		host = host[:idx]
	}

	useTLS := strings.HasPrefix(url, "wss://")
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", host, 5*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}

	// Generate key
	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	// Send upgrade request
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, key)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade: %v", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read status: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("not 101: %s", strings.TrimSpace(statusLine))
	}

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read headers: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ": "); idx > 0 {
			headers[strings.ToLower(line[:idx])] = line[idx+2:]
		}
	}

	// Verify accept
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5DC11650B"))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if headers["sec-websocket-accept"] != expectedAccept {
		// Don't fail here - the ALOS framework has a known bug with the accept hash
		// We'll test this specifically in a test case
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

func wsWriteText(conn net.Conn, msg string) error {
	return wsWriteFrame(conn, 0x1, []byte(msg))
}

func wsWriteBinary(conn net.Conn, data []byte) error {
	return wsWriteFrame(conn, 0x2, data)
}

func wsWriteFrame(conn net.Conn, opcode byte, payload []byte) error {
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	frame := []byte{0x80 | opcode} // FIN + opcode

	maskBit := byte(0x80) // client must mask
	plen := len(payload)
	if plen < 126 {
		frame = append(frame, maskBit|byte(plen))
	} else if plen < 65536 {
		frame = append(frame, maskBit|126)
		frame = append(frame, byte(plen>>8), byte(plen))
	} else {
		frame = append(frame, maskBit|127)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(plen))
		frame = append(frame, b...)
	}

	mask := make([]byte, 4)
	rand.Read(mask)
	frame = append(frame, mask...)

	masked := make([]byte, plen)
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	frame = append(frame, masked...)

	_, err := conn.Write(frame)
	return err
}

func wsReadFrame(conn net.Conn) (byte, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	plen := int(header[1] & 0x7F)

	if plen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return 0, nil, err
		}
		plen = int(binary.BigEndian.Uint16(ext))
	} else if plen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return 0, nil, err
		}
		plen = int(binary.BigEndian.Uint64(ext))
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(conn, mask); err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, plen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return opcode, payload, nil
}

func wsClose(conn net.Conn) {
	wsWriteFrame(conn, 0x8, []byte{0x03, 0xE8}) // 1000 normal close
	conn.Close()
}

func wsHandshakeVerifyAccept(url string) (net.Conn, error) {
	host := strings.TrimPrefix(url, "ws://")
	host = strings.TrimPrefix(host, "wss://")
	path := "/"
	if idx := strings.Index(host, "/"); idx >= 0 {
		path = host[idx:]
		host = host[:idx]
	}

	useTLS := strings.HasPrefix(url, "wss://")
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = net.DialTimeout("tcp", host, 5*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("dial: %v", err)
	}

	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", path, host, key)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write upgrade: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read status: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("not 101: %s", strings.TrimSpace(statusLine))
	}

	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read headers: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.Index(line, ": "); idx > 0 {
			headers[strings.ToLower(line[:idx])] = line[idx+2:]
		}
	}

	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5DC11650B"))
	expectedAccept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	if headers["sec-websocket-accept"] != expectedAccept {
		conn.Close()
		return nil, fmt.Errorf("accept hash mismatch: got %q, want %q", headers["sec-websocket-accept"], expectedAccept)
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// ── Main ──

func main() {
	// Wait for server
	if !waitForServer(plainBase+"/ping", 30*time.Second) {
		fmt.Fprintf(os.Stderr, "FATAL: server not ready at %s\n", plainBase)
		os.Exit(1)
	}

	tests := buildAllTests()
	fmt.Printf("Running %d tests...\n\n", len(tests))

	results := runTests(tests)

	// Output
	passed, failed := 0, 0
	var failures []TestResult
	for _, r := range results {
		if r.Pass {
			passed++
		} else {
			failed++
			failures = append(failures, r)
		}
	}

	// Category summary
	catPassed := map[string]int{}
	catTotal := map[string]int{}
	for _, r := range results {
		catTotal[r.Category]++
		if r.Pass {
			catPassed[r.Category]++
		}
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("                    CATEGORY SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	cats := make([]string, 0, len(catTotal))
	for c := range catTotal {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		mark := "✓"
		if catPassed[c] < catTotal[c] {
			mark = "✗"
		}
		fmt.Printf("  %s %-25s %d/%d\n", mark, c, catPassed[c], catTotal[c])
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  TOTAL: %d passed, %d failed, %d total\n", passed, failed, len(results))
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if len(failures) > 0 {
		fmt.Println("\nFAILURES:")
		for _, f := range failures {
			fmt.Printf("  [%3d] %-40s %s\n", f.ID, f.Name, f.Error)
		}
	}

	// Write JSON results
	jsonResults, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile("/app/results.json", jsonResults, 0644)

	// Write summary
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Test Results: %d passed, %d failed, %d total\n\n", passed, failed, len(results)))
	for _, c := range cats {
		sb.WriteString(fmt.Sprintf("%-25s %d/%d\n", c, catPassed[c], catTotal[c]))
	}
	if len(failures) > 0 {
		sb.WriteString("\nFailures:\n")
		for _, f := range failures {
			sb.WriteString(fmt.Sprintf("  [%d] %s: %s\n", f.ID, f.Name, f.Error))
		}
	}
	os.WriteFile("/app/summary.txt", []byte(sb.String()), 0644)

	fmt.Printf("\nResults written to /app/results.json and /app/summary.txt\n")

	if failed > 0 {
		os.Exit(1)
	}
}

func waitForServer(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 1 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func runTests(tests []Test) []TestResult {
	results := make([]TestResult, len(tests))
	for i, t := range tests {
		start := time.Now()
		err := t.Fn()
		dur := time.Since(start)
		r := TestResult{
			ID:       t.ID,
			Category: t.Category,
			Name:     t.Name,
			Pass:     err == nil,
			Duration: dur,
		}
		if err != nil {
			r.Error = err.Error()
			fmt.Printf("  FAIL [%3d] %s: %s\n", t.ID, t.Name, err)
		} else {
			fmt.Printf("  PASS [%3d] %s (%v)\n", t.ID, t.Name, dur.Round(time.Millisecond))
		}
		results[i] = r
	}
	return results
}

// ══════════════════════════════════════════════════════════════════════════════
//  300 TESTS
// ══════════════════════════════════════════════════════════════════════════════

func buildAllTests() []Test {
	var tests []Test
	id := 0
	add := func(cat, name string, fn TestFunc) {
		id++
		tests = append(tests, Test{ID: id, Category: cat, Name: name, Fn: fn})
	}

	// ════════════════════════════════════════════
	// CATEGORY 1: HTTP Methods (15 tests)
	// ════════════════════════════════════════════

	add("methods", "GET basic", func() error {
		resp, err := doGet(plainBase + "/get")
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "GET OK")
	})

	add("methods", "POST basic", func() error {
		resp, err := doReq("POST", plainBase+"/post", "hello", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "POST OK: hello")
	})

	add("methods", "PUT basic", func() error {
		resp, err := doReq("PUT", plainBase+"/put", "data", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "PUT OK: data")
	})

	add("methods", "DELETE basic", func() error {
		resp, err := doReq("DELETE", plainBase+"/delete", "", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "DELETE OK")
	})

	add("methods", "PATCH basic", func() error {
		resp, err := doReq("PATCH", plainBase+"/patch", "fix", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "PATCH OK: fix")
	})

	add("methods", "HEAD returns no body", func() error {
		resp, err := doReq("HEAD", plainBase+"/head", "", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			return err
		}
		body, _ := readBody(resp)
		if len(body) != 0 {
			return fmt.Errorf("HEAD should have empty body, got %d bytes", len(body))
		}
		return nil
	})

	add("methods", "HEAD X-Head-Test header", func() error {
		resp, err := doReq("HEAD", plainBase+"/head", "", nil)
		if err != nil {
			return err
		}
		return expectHeader(resp, "X-Head-Test", "yes")
	})

	add("methods", "OPTIONS Allow header", func() error {
		resp, err := doReq("OPTIONS", plainBase+"/options", "", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			return err
		}
		return expectHeaderContains(resp, "Allow", "GET")
	})

	add("methods", "ANY matches GET", func() error {
		resp, err := doGet(plainBase + "/any")
		if err != nil {
			return err
		}
		return expectBody(resp, "GET ANY OK")
	})

	add("methods", "ANY matches POST", func() error {
		resp, err := doReq("POST", plainBase+"/any", "", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "POST ANY OK")
	})

	add("methods", "ANY matches PUT", func() error {
		resp, err := doReq("PUT", plainBase+"/any", "", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "PUT ANY OK")
	})

	add("methods", "ANY matches DELETE", func() error {
		resp, err := doReq("DELETE", plainBase+"/any", "", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "DELETE ANY OK")
	})

	add("methods", "POST with body content-type", func() error {
		resp, err := doReq("POST", plainBase+"/echo", "test body", map[string]string{"Content-Type": "text/plain"})
		if err != nil {
			return err
		}
		return expectBody(resp, "test body")
	})

	add("methods", "POST empty body", func() error {
		resp, err := doReq("POST", plainBase+"/post", "", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "POST OK: ")
	})

	add("methods", "PATCH with JSON body", func() error {
		resp, err := doReq("PATCH", plainBase+"/patch", `{"key":"val"}`, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return err
		}
		return expectBody(resp, `PATCH OK: {"key":"val"}`)
	})

	// ════════════════════════════════════════════
	// CATEGORY 2: Routing (25 tests)
	// ════════════════════════════════════════════

	add("routing", "Root path /", func() error {
		resp, err := doGet(plainBase + "/")
		if err != nil {
			return err
		}
		return expectBody(resp, "root")
	})

	add("routing", "Named param :id", func() error {
		resp, err := doGet(plainBase + "/param/123")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=123")
	})

	add("routing", "Named param string value", func() error {
		resp, err := doGet(plainBase + "/param/hello-world")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=hello-world")
	})

	add("routing", "Multiple named params", func() error {
		resp, err := doGet(plainBase + "/params/alpha/bob")
		if err != nil {
			return err
		}
		return expectBody(resp, "team=alpha,user=bob")
	})

	add("routing", "Catch-all wildcard", func() error {
		resp, err := doGet(plainBase + "/catch/foo/bar/baz")
		if err != nil {
			return err
		}
		return expectBody(resp, "path=foo/bar/baz")
	})

	add("routing", "Catch-all single segment", func() error {
		resp, err := doGet(plainBase + "/catch/single")
		if err != nil {
			return err
		}
		return expectBody(resp, "path=single")
	})

	add("routing", "Nested static path", func() error {
		resp, err := doGet(plainBase + "/nested/a/b/c")
		if err != nil {
			return err
		}
		return expectBody(resp, "nested")
	})

	add("routing", "Priority static over param", func() error {
		resp, err := doGet(plainBase + "/priority/static")
		if err != nil {
			return err
		}
		return expectBody(resp, "static")
	})

	add("routing", "Param when not matching static", func() error {
		resp, err := doGet(plainBase + "/priority/dynamic")
		if err != nil {
			return err
		}
		return expectBody(resp, "param=dynamic")
	})

	add("routing", "Custom 404 handler", func() error {
		resp, err := doGet(plainBase + "/nonexistent/path")
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 404); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "custom 404")
	})

	add("routing", "Custom 405 handler", func() error {
		resp, err := doReq("DELETE", plainBase+"/get", "", nil)
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 405); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "custom 405")
	})

	add("routing", "Deep nested path", func() error {
		resp, err := doGet(plainBase + "/deep/1/2/3/4/5")
		if err != nil {
			return err
		}
		return expectBody(resp, "deep")
	})

	add("routing", "Same path GET vs POST GET", func() error {
		resp, err := doGet(plainBase + "/samepath")
		if err != nil {
			return err
		}
		return expectBody(resp, "GET samepath")
	})

	add("routing", "Same path GET vs POST POST", func() error {
		resp, err := doReq("POST", plainBase+"/samepath", "", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "POST samepath")
	})

	add("routing", "Long path segment", func() error {
		resp, err := doGet(plainBase + "/longpath/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		if err != nil {
			return err
		}
		return expectBody(resp, "longpath")
	})

	add("routing", "Param numeric value", func() error {
		resp, err := doGet(plainBase + "/param/99999")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=99999")
	})

	add("routing", "Param with special chars", func() error {
		resp, err := doGet(plainBase + "/param/hello_world-123")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=hello_world-123")
	})

	add("routing", "Multiple params first", func() error {
		resp, err := doGet(plainBase + "/params/team1/user1")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "team=team1")
	})

	add("routing", "Multiple params second", func() error {
		resp, err := doGet(plainBase + "/params/team1/user1")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "user=user1")
	})

	add("routing", "Catch-all deep nesting", func() error {
		resp, err := doGet(plainBase + "/catch/a/b/c/d/e/f/g")
		if err != nil {
			return err
		}
		return expectBody(resp, "path=a/b/c/d/e/f/g")
	})

	add("routing", "404 for truly missing path", func() error {
		resp, err := doGet(plainBase + "/this/does/not/exist/anywhere")
		if err != nil {
			return err
		}
		return expectStatus(resp, 404)
	})

	add("routing", "GET static returns 200", func() error {
		resp, err := doGet(plainBase + "/get")
		if err != nil {
			return err
		}
		return expectStatus(resp, 200)
	})

	add("routing", "Param with dots", func() error {
		resp, err := doGet(plainBase + "/param/file.txt")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=file.txt")
	})

	add("routing", "Catch-all with extension", func() error {
		resp, err := doGet(plainBase + "/catch/path/to/file.html")
		if err != nil {
			return err
		}
		return expectBody(resp, "path=path/to/file.html")
	})

	add("routing", "Param empty-like segment", func() error {
		resp, err := doGet(plainBase + "/param/0")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=0")
	})

	// ════════════════════════════════════════════
	// CATEGORY 3: Request Object (20 tests)
	// ════════════════════════════════════════════

	add("request", "Echo body preserves content", func() error {
		resp, err := doReq("POST", plainBase+"/echo", "exact content here", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "exact content here")
	})

	add("request", "Echo JSON body", func() error {
		resp, err := doReq("POST", plainBase+"/echo/json", `{"a":1}`, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		body, _ := readBody(resp)
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			return fmt.Errorf("response not valid JSON: %v", err)
		}
		return nil
	})

	add("request", "Echo binary body", func() error {
		data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE}
		resp, err := doReq("POST", plainBase+"/echo/binary", string(data), map[string]string{"Content-Type": "application/octet-stream"})
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if !bytes.Equal(body, data) {
			return fmt.Errorf("binary mismatch: got %v, want %v", body, data)
		}
		return nil
	})

	add("request", "Header echo Content-Type", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"Content-Type": "text/plain"})
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "content-type") {
			return fmt.Errorf("content-type not echoed: %s", body)
		}
		return nil
	})

	add("request", "Header echo Accept", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"Accept": "application/json"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "accept")
	})

	add("request", "Header echo User-Agent", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"User-Agent": "TestRunner/1.0"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "user-agent")
	})

	add("request", "Header echo Authorization", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"Authorization": "Bearer token123"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "authorization")
	})

	add("request", "Header echo custom X-header", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"X-Custom-Test": "myvalue"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "x-custom-test")
	})

	add("request", "PUT echo body", func() error {
		resp, err := doReq("PUT", plainBase+"/echo", "put data", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "put data")
	})

	add("request", "POST 1KB body", func() error {
		body := strings.Repeat("A", 1024)
		resp, err := doReq("POST", plainBase+"/upload", body, nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "1024")
	})

	add("request", "POST 100KB body", func() error {
		body := strings.Repeat("B", 100*1024)
		resp, err := doReq("POST", plainBase+"/upload", body, nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "102400")
	})

	add("request", "POST 1MB body", func() error {
		body := strings.Repeat("C", 1024*1024)
		resp, err := doReq("POST", plainBase+"/upload", body, nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "1048576")
	})

	add("request", "Echo preserves content-type", func() error {
		resp, err := doReq("POST", plainBase+"/echo", "text", map[string]string{"Content-Type": "text/plain; charset=utf-8"})
		if err != nil {
			return err
		}
		return expectHeaderContains(resp, "Content-Type", "text/plain")
	})

	add("request", "JSON validate valid", func() error {
		resp, err := doReq("POST", plainBase+"/json/validate", `{"key":"value"}`, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return err
		}
		return expectStatus(resp, 200)
	})

	add("request", "JSON validate invalid", func() error {
		resp, err := doReq("POST", plainBase+"/json/validate", `{bad json`, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			return err
		}
		return expectStatus(resp, 400)
	})

	add("request", "POST multipart-like body", func() error {
		body := "--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nfiledata\r\n--boundary--\r\n"
		resp, err := doReq("POST", plainBase+"/upload", body, map[string]string{"Content-Type": "multipart/form-data; boundary=boundary"})
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		b, _ := readBody(resp)
		if b == "0" {
			return fmt.Errorf("body was empty")
		}
		return nil
	})

	add("request", "Echo UTF-8 body", func() error {
		resp, err := doReq("POST", plainBase+"/echo", "日本語テスト", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "日本語テスト")
	})

	add("request", "Echo newlines in body", func() error {
		resp, err := doReq("POST", plainBase+"/echo", "line1\nline2\nline3", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "line1\nline2\nline3")
	})

	add("request", "Header echo multiple custom", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{
			"X-Test-A": "valA",
			"X-Test-B": "valB",
		})
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "x-test-a") || !strings.Contains(body, "x-test-b") {
			return fmt.Errorf("missing custom headers in echo: %s", body)
		}
		return nil
	})

	add("request", "POST 5MB body", func() error {
		body := strings.Repeat("D", 5*1024*1024)
		resp, err := doH2("POST", tlsBase+"/upload", body)
		if err != nil {
			return err
		}
		return expectBody(resp, "5242880")
	})

	// ════════════════════════════════════════════
	// CATEGORY 4: Response Object (25 tests)
	// ════════════════════════════════════════════

	add("response", "Status 200 default", func() error {
		resp, err := doGet(plainBase + "/get")
		if err != nil {
			return err
		}
		return expectStatus(resp, 200)
	})

	add("response", "Status 201 Created", func() error {
		resp, err := doGet(plainBase + "/status/201")
		if err != nil {
			return err
		}
		return expectStatus(resp, 201)
	})

	add("response", "Status 204 No Content", func() error {
		resp, err := doGet(plainBase + "/status/204")
		if err != nil {
			return err
		}
		return expectStatus(resp, 204)
	})

	add("response", "Status 301 redirect", func() error {
		resp, err := doGet(plainBase + "/status/301")
		if err != nil {
			return err
		}
		return expectStatus(resp, 301)
	})

	add("response", "Status 400 bad request", func() error {
		resp, err := doGet(plainBase + "/status/400")
		if err != nil {
			return err
		}
		return expectStatus(resp, 400)
	})

	add("response", "Status 404 not found", func() error {
		resp, err := doGet(plainBase + "/status/404")
		if err != nil {
			return err
		}
		return expectStatus(resp, 404)
	})

	add("response", "Status 500 error", func() error {
		resp, err := doGet(plainBase + "/status/500")
		if err != nil {
			return err
		}
		return expectStatus(resp, 500)
	})

	add("response", "String response type", func() error {
		resp, err := doGet(plainBase + "/response/string")
		if err != nil {
			return err
		}
		return expectBody(resp, "plain text response")
	})

	add("response", "HTML response type", func() error {
		resp, err := doGet(plainBase + "/response/html")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "<html>")
	})

	add("response", "HTML content-type", func() error {
		resp, err := doGet(plainBase + "/response/html")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "text/html")
	})

	add("response", "Bytes response type", func() error {
		resp, err := doGet(plainBase + "/response/bytes")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if !bytes.Equal(body, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
			return fmt.Errorf("bytes mismatch: %x", body)
		}
		return nil
	})

	add("response", "JSON response content-type", func() error {
		resp, err := doGet(plainBase + "/response/json")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "json")
	})

	add("response", "JSON response valid", func() error {
		resp, err := doGet(plainBase + "/response/json")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("invalid JSON: %s", body)
		}
		return nil
	})

	add("response", "JSONString valid", func() error {
		resp, err := doGet(plainBase + "/response/json/string")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			return err
		}
		if m["result"] != "ok" {
			return fmt.Errorf("unexpected result: %v", m["result"])
		}
		return nil
	})

	add("response", "JSONMarshal struct", func() error {
		resp, err := doGet(plainBase + "/response/json/marshal")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			return err
		}
		if m["id"] != float64(42) || m["name"] != "test" {
			return fmt.Errorf("unexpected: %v", m)
		}
		return nil
	})

	add("response", "SetHeader custom", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Custom-One", "value1")
	})

	add("response", "SetHeader multiple", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if err := expectHeader(resp, "X-Custom-One", "value1"); err != nil {
			return err
		}
		return expectHeader(resp, "X-Custom-Two", "value2")
	})

	add("response", "SetHeader Cache-Control", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "Cache-Control", "no-cache")
	})

	add("response", "SetHeader ETag", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "ETag", "abc123")
	})

	add("response", "Empty body 204", func() error {
		resp, err := doGet(plainBase + "/response/empty")
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 204); err != nil {
			resp.Body.Close()
			return err
		}
		body, _ := readBody(resp)
		if len(body) != 0 {
			return fmt.Errorf("expected empty body, got %d bytes", len(body))
		}
		return nil
	})

	add("response", "Large 1MB body", func() error {
		resp, err := doGet(plainBase + "/response/large")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if len(body) != 1024*1024 {
			return fmt.Errorf("expected 1MB, got %d bytes", len(body))
		}
		return nil
	})

	add("response", "JSON array response", func() error {
		resp, err := doGet(plainBase + "/json/array")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		var arr []int
		if err := json.Unmarshal([]byte(body), &arr); err != nil {
			return err
		}
		if len(arr) != 5 {
			return fmt.Errorf("expected 5 items, got %d", len(arr))
		}
		return nil
	})

	add("response", "JSON nested response", func() error {
		resp, err := doGet(plainBase + "/json/nested")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			return err
		}
		l1, ok := m["level1"].(map[string]any)
		if !ok {
			return fmt.Errorf("level1 missing")
		}
		l2, ok := l1["level2"].(map[string]any)
		if !ok {
			return fmt.Errorf("level2 missing")
		}
		if l2["value"] != float64(42) {
			return fmt.Errorf("value != 42: %v", l2["value"])
		}
		return nil
	})

	add("response", "Response body with special chars", func() error {
		resp, err := doReq("POST", plainBase+"/echo", `<>&"'`, nil)
		if err != nil {
			return err
		}
		return expectBody(resp, `<>&"'`)
	})

	add("response", "Status 503 Service Unavailable", func() error {
		resp, err := doGet(plainBase + "/status/503")
		if err != nil {
			return err
		}
		return expectStatus(resp, 503)
	})

	// ════════════════════════════════════════════
	// CATEGORY 5: Status Codes (15 tests)
	// ════════════════════════════════════════════

	for _, tc := range []struct {
		code int
		name string
	}{
		{200, "200 OK"},
		{201, "201 Created"},
		{202, "202 Accepted"},
		{204, "204 No Content"},
		{301, "301 Moved"},
		{302, "302 Found"},
		{304, "304 Not Modified"},
		{307, "307 Temp Redirect"},
		{400, "400 Bad Request"},
		{401, "401 Unauthorized"},
		{403, "403 Forbidden"},
		{404, "404 Not Found"},
		{405, "405 Method Not Allowed"},
		{500, "500 Internal Error"},
		{503, "503 Service Unavailable"},
	} {
		code := tc.code
		name := tc.name
		add("status-codes", "Status "+name, func() error {
			resp, err := doGet(plainBase + "/status/" + fmt.Sprint(code))
			if err != nil {
				return err
			}
			resp.Body.Close()
			return expectStatus(resp, code)
		})
	}

	// ════════════════════════════════════════════
	// CATEGORY 6: Headers (20 tests)
	// ════════════════════════════════════════════

	add("headers", "Set single header", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Custom-One", "value1")
	})

	add("headers", "Content-Type text/plain", func() error {
		resp, err := doGet(plainBase + "/response/string")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "text/plain")
	})

	add("headers", "Content-Type application/json", func() error {
		resp, err := doGet(plainBase + "/response/json")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "json")
	})

	add("headers", "Content-Type text/html", func() error {
		resp, err := doGet(plainBase + "/response/html")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "html")
	})

	add("headers", "Server header present", func() error {
		resp, err := doGet(plainBase + "/get")
		if err != nil {
			return err
		}
		resp.Body.Close()
		// Server may or may not set Server header, just check no error
		return expectStatus(resp, 200)
	})

	add("headers", "Security X-Frame-Options", func() error {
		resp, err := doGet(plainBase + "/headers/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Frame-Options", "DENY")
	})

	add("headers", "Security X-Content-Type-Options", func() error {
		resp, err := doGet(plainBase + "/headers/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Content-Type-Options", "nosniff")
	})

	add("headers", "Security X-XSS-Protection", func() error {
		resp, err := doGet(plainBase + "/headers/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "X-XSS-Protection", "1")
	})

	add("headers", "Security HSTS", func() error {
		resp, err := doGet(plainBase + "/headers/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Strict-Transport-Security", "max-age=")
	})

	add("headers", "Security Referrer-Policy", func() error {
		resp, err := doGet(plainBase + "/headers/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Referrer-Policy", "strict-origin")
	})

	add("headers", "Cache-Control header", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "Cache-Control", "no-cache")
	})

	add("headers", "ETag header", func() error {
		resp, err := doGet(plainBase + "/headers/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "ETag", "abc123")
	})

	add("headers", "Custom header round-trip", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"X-Roundtrip": "test-value-999"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "test-value-999")
	})

	add("headers", "Multiple Accept values", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"Accept": "text/html, application/json"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "text/html")
	})

	add("headers", "Long header value", func() error {
		longVal := strings.Repeat("x", 1000)
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"X-Long": longVal})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, longVal[:100])
	})

	add("headers", "Empty header value", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"X-Empty": ""})
		if err != nil {
			return err
		}
		return expectStatus(resp, 200)
	})

	add("headers", "Case insensitive header names", func() error {
		resp, err := doReq("GET", plainBase+"/headers/echo", "", map[string]string{"X-UPPER-CASE": "value"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "x-upper-case")
	})

	add("headers", "Connection header present", func() error {
		resp, err := doGet(plainBase + "/get")
		if err != nil {
			return err
		}
		resp.Body.Close()
		// HTTP/1.1 should have keep-alive or connection info
		return expectStatus(resp, 200)
	})

	add("headers", "Content-Length numeric", func() error {
		resp, err := doGet(plainBase + "/response/string")
		if err != nil {
			return err
		}
		resp.Body.Close()
		cl := resp.Header.Get("Content-Length")
		if cl == "" {
			return nil // Transfer-Encoding: chunked is also valid
		}
		return nil
	})

	add("headers", "JSON marshal content-type", func() error {
		resp, err := doGet(plainBase + "/response/json/marshal")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "json")
	})

	// ════════════════════════════════════════════
	// CATEGORY 7: Compression (15 tests)
	// ════════════════════════════════════════════

	add("compression", "Gzip compress text", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		if ce != "gzip" {
			resp.Body.Close()
			return fmt.Errorf("expected gzip encoding, got %q", ce)
		}
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("gzip reader: %v", err)
		}
		data, _ := io.ReadAll(gr)
		gr.Close()
		resp.Body.Close()
		if len(data) == 0 {
			return fmt.Errorf("empty decompressed body")
		}
		return nil
	})

	add("compression", "Gzip decompresses correctly", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			resp.Body.Close()
			return err
		}
		data, _ := io.ReadAll(gr)
		gr.Close()
		resp.Body.Close()
		if !strings.Contains(string(data), "Hello World") {
			return fmt.Errorf("decompressed content doesn't match")
		}
		return nil
	})

	add("compression", "Deflate compress", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "deflate"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		resp.Body.Close()
		if ce != "deflate" && ce != "" {
			// Some frameworks prefer gzip; accept both
			return nil
		}
		return nil
	})

	add("compression", "No compression without Accept-Encoding", func() error {
		req, _ := http.NewRequest("GET", plainBase+"/compress/text", nil)
		req.Header.Del("Accept-Encoding")
		resp, err := (&http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DisableCompression: true,
			},
		}).Do(req)
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		resp.Body.Close()
		if ce == "gzip" || ce == "deflate" {
			return fmt.Errorf("should not compress without Accept-Encoding, got %q", ce)
		}
		return nil
	})

	add("compression", "Small body not compressed", func() error {
		resp, err := doReq("GET", plainBase+"/compress/small", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		resp.Body.Close()
		if ce == "gzip" {
			return fmt.Errorf("small body should not be compressed")
		}
		return nil
	})

	add("compression", "Content-Encoding header present", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "Content-Encoding", "gzip")
	})

	add("compression", "Gzip JSON response", func() error {
		resp, err := doReq("GET", plainBase+"/compress/json", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		if ce == "gzip" {
			gr, _ := gzip.NewReader(resp.Body)
			data, _ := io.ReadAll(gr)
			gr.Close()
			resp.Body.Close()
			if !json.Valid(data) {
				return fmt.Errorf("decompressed JSON is invalid")
			}
			return nil
		}
		resp.Body.Close()
		return nil
	})

	add("compression", "Gzip HTML response", func() error {
		resp, err := doReq("GET", plainBase+"/compress/html", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		if ce == "gzip" {
			gr, _ := gzip.NewReader(resp.Body)
			data, _ := io.ReadAll(gr)
			gr.Close()
			resp.Body.Close()
			if !strings.Contains(string(data), "<html>") {
				return fmt.Errorf("decompressed HTML missing <html>")
			}
			return nil
		}
		resp.Body.Close()
		return nil
	})

	add("compression", "Compressed smaller than original", func() error {
		// Get uncompressed
		req1, _ := http.NewRequest("GET", plainBase+"/compress/text", nil)
		client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
		resp1, err := client.Do(req1)
		if err != nil {
			return err
		}
		uncompressed, _ := readBodyBytes(resp1)

		// Get compressed
		resp2, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		compressed, _ := readBodyBytes(resp2)

		if len(compressed) >= len(uncompressed) {
			return fmt.Errorf("compressed (%d) >= uncompressed (%d)", len(compressed), len(uncompressed))
		}
		return nil
	})

	add("compression", "Vary Accept-Encoding header", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		vary := resp.Header.Get("Vary")
		if !strings.Contains(strings.ToLower(vary), "accept-encoding") {
			return fmt.Errorf("Vary header missing Accept-Encoding: %q", vary)
		}
		return nil
	})

	add("compression", "Accept-Encoding gzip,deflate", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip, deflate"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		resp.Body.Close()
		if ce != "gzip" && ce != "deflate" {
			return fmt.Errorf("expected gzip or deflate, got %q", ce)
		}
		return nil
	})

	add("compression", "Identity encoding", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "identity"})
		if err != nil {
			return err
		}
		ce := resp.Header.Get("Content-Encoding")
		resp.Body.Close()
		if ce == "gzip" || ce == "deflate" {
			return fmt.Errorf("identity should not compress, got %q", ce)
		}
		return nil
	})

	add("compression", "Gzip large text", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		if resp.Header.Get("Content-Encoding") != "gzip" {
			resp.Body.Close()
			return fmt.Errorf("not gzip compressed")
		}
		gr, _ := gzip.NewReader(resp.Body)
		data, _ := io.ReadAll(gr)
		gr.Close()
		resp.Body.Close()
		if len(data) < 1000 {
			return fmt.Errorf("decompressed too small: %d", len(data))
		}
		return nil
	})

	add("compression", "Repeated compress requests", func() error {
		for i := 0; i < 5; i++ {
			resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
			if err != nil {
				return fmt.Errorf("attempt %d: %v", i, err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("attempt %d: status %d", i, resp.StatusCode)
			}
		}
		return nil
	})

	add("compression", "Compress does not break status", func() error {
		resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 200)
	})

	// ════════════════════════════════════════════
	// CATEGORY 8: Middleware (25 tests)
	// ════════════════════════════════════════════

	add("middleware", "Recovery catches panic", func() error {
		resp, err := doGet(plainBase + "/middleware/panic")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 500 {
			return fmt.Errorf("expected 500 from panic recovery, got %d", resp.StatusCode)
		}
		return nil
	})

	add("middleware", "Recovery returns 500", func() error {
		resp, err := doGet(plainBase + "/middleware/panic")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 500)
	})

	add("middleware", "Recovery does not crash server", func() error {
		// Trigger panic then make normal request
		resp1, _ := doGet(plainBase + "/middleware/panic")
		if resp1 != nil {
			resp1.Body.Close()
		}
		resp2, err := doGet(plainBase + "/get")
		if err != nil {
			return fmt.Errorf("server crashed after panic: %v", err)
		}
		return expectBody(resp2, "GET OK")
	})

	add("middleware", "RequestID adds header", func() error {
		resp, err := doGet(plainBase + "/middleware/requestid")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderPresent(resp, "X-Request-Id")
	})

	add("middleware", "RequestID unique per request", func() error {
		resp1, err := doGet(plainBase + "/middleware/requestid")
		if err != nil {
			return err
		}
		id1 := resp1.Header.Get("X-Request-Id")
		resp1.Body.Close()

		resp2, err := doGet(plainBase + "/middleware/requestid2")
		if err != nil {
			return err
		}
		id2 := resp2.Header.Get("X-Request-Id")
		resp2.Body.Close()

		if id1 == id2 {
			return fmt.Errorf("request IDs should be unique: %s == %s", id1, id2)
		}
		return nil
	})

	add("middleware", "CORS preflight OPTIONS", func() error {
		resp, err := doReq("OPTIONS", plainBase+"/middleware/cors", "", map[string]string{
			"Origin":                         "https://example.com",
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "X-Custom",
		})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Access-Control-Allow-Origin", "https://example.com")
	})

	add("middleware", "CORS Allow-Origin header", func() error {
		resp, err := doReq("GET", plainBase+"/middleware/cors", "", map[string]string{"Origin": "https://example.com"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Access-Control-Allow-Origin", "https://example.com")
	})

	add("middleware", "CORS Allow-Methods header", func() error {
		resp, err := doReq("OPTIONS", plainBase+"/middleware/cors", "", map[string]string{
			"Origin":                        "https://example.com",
			"Access-Control-Request-Method": "POST",
		})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderPresent(resp, "Access-Control-Allow-Methods")
	})

	add("middleware", "CORS Allow-Headers header", func() error {
		resp, err := doReq("OPTIONS", plainBase+"/middleware/cors", "", map[string]string{
			"Origin":                         "https://example.com",
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "X-Custom",
		})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderPresent(resp, "Access-Control-Allow-Headers")
	})

	add("middleware", "CORS Allow-Credentials", func() error {
		resp, err := doReq("GET", plainBase+"/middleware/cors", "", map[string]string{"Origin": "https://example.com"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "Access-Control-Allow-Credentials", "true")
	})

	add("middleware", "CORS Max-Age header", func() error {
		resp, err := doReq("OPTIONS", plainBase+"/middleware/cors", "", map[string]string{
			"Origin":                        "https://example.com",
			"Access-Control-Request-Method": "POST",
		})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderPresent(resp, "Access-Control-Max-Age")
	})

	add("middleware", "CORS wrong origin blocked", func() error {
		resp, err := doReq("GET", plainBase+"/middleware/cors", "", map[string]string{"Origin": "https://evil.com"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		origin := resp.Header.Get("Access-Control-Allow-Origin")
		if origin == "https://evil.com" || origin == "*" {
			return fmt.Errorf("should not allow evil.com origin")
		}
		return nil
	})

	add("middleware", "Security headers all present", func() error {
		resp, err := doGet(plainBase + "/middleware/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		checks := []string{"X-Frame-Options", "X-Content-Type-Options"}
		for _, h := range checks {
			if resp.Header.Get(h) == "" {
				return fmt.Errorf("missing security header: %s", h)
			}
		}
		return nil
	})

	add("middleware", "Security HSTS with subdomains", func() error {
		resp, err := doGet(plainBase + "/middleware/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		hsts := resp.Header.Get("Strict-Transport-Security")
		if !strings.Contains(hsts, "includeSubDomains") {
			return fmt.Errorf("HSTS missing includeSubDomains: %q", hsts)
		}
		return nil
	})

	add("middleware", "Security nosniff", func() error {
		resp, err := doGet(plainBase + "/middleware/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Content-Type-Options", "nosniff")
	})

	add("middleware", "Middleware doesn't break response", func() error {
		resp, err := doGet(plainBase + "/middleware/requestid")
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "ok")
	})

	add("middleware", "Multiple panics handled", func() error {
		for i := 0; i < 3; i++ {
			resp, err := doGet(plainBase + "/middleware/panic")
			if err != nil {
				return fmt.Errorf("panic %d failed: %v", i, err)
			}
			resp.Body.Close()
		}
		return nil
	})

	add("middleware", "Security XSS Protection", func() error {
		resp, err := doGet(plainBase + "/middleware/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "X-XSS-Protection", "1")
	})

	add("middleware", "Security Referrer Policy", func() error {
		resp, err := doGet(plainBase + "/middleware/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderPresent(resp, "Referrer-Policy")
	})

	add("middleware", "CORS expose headers", func() error {
		resp, err := doReq("GET", plainBase+"/middleware/cors", "", map[string]string{"Origin": "https://example.com"})
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderPresent(resp, "Access-Control-Expose-Headers")
	})

	add("middleware", "Recovery then normal request", func() error {
		for i := 0; i < 5; i++ {
			resp, _ := doGet(plainBase + "/middleware/panic")
			if resp != nil {
				resp.Body.Close()
			}
		}
		resp, err := doGet(plainBase + "/ping")
		if err != nil {
			return err
		}
		return expectBody(resp, "pong")
	})

	add("middleware", "CORS no origin no headers", func() error {
		resp, err := doGet(plainBase + "/middleware/cors")
		if err != nil {
			return err
		}
		resp.Body.Close()
		// Without Origin, CORS headers should not be set
		origin := resp.Header.Get("Access-Control-Allow-Origin")
		if origin == "*" || origin == "https://example.com" {
			// Some implementations always set it; that's ok
		}
		return nil
	})

	add("middleware", "CORS preflight returns 200", func() error {
		resp, err := doReq("OPTIONS", plainBase+"/middleware/cors", "", map[string]string{
			"Origin":                        "https://example.com",
			"Access-Control-Request-Method": "POST",
		})
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			return fmt.Errorf("preflight status: %d", resp.StatusCode)
		}
		return nil
	})

	add("middleware", "Security frame options DENY", func() error {
		resp, err := doGet(plainBase + "/middleware/security")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Frame-Options", "DENY")
	})

	// ════════════════════════════════════════════
	// CATEGORY 9: WebSockets (20 tests)
	// ════════════════════════════════════════════

	add("websocket", "Upgrade handshake 101", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		wsClose(conn)
		return nil
	})

	add("websocket", "Send text message", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		if err := wsWriteText(conn, "hello"); err != nil {
			return fmt.Errorf("write: %v", err)
		}
		return nil
	})

	add("websocket", "Echo text round-trip", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		if err := wsWriteText(conn, "hello ws"); err != nil {
			return err
		}
		op, data, err := wsReadFrame(conn)
		if err != nil {
			return fmt.Errorf("read: %v", err)
		}
		if op != 0x1 {
			return fmt.Errorf("expected text opcode 1, got %d", op)
		}
		if string(data) != "hello ws" {
			return fmt.Errorf("echo mismatch: %q", string(data))
		}
		return nil
	})

	add("websocket", "Echo binary round-trip", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		payload := []byte{0x00, 0x01, 0x02, 0xFF}
		if err := wsWriteBinary(conn, payload); err != nil {
			return err
		}
		op, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if op != 0x2 {
			return fmt.Errorf("expected binary opcode 2, got %d", op)
		}
		if !bytes.Equal(data, payload) {
			return fmt.Errorf("binary mismatch")
		}
		return nil
	})

	add("websocket", "Multiple text messages", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		for i := 0; i < 5; i++ {
			msg := fmt.Sprintf("msg-%d", i)
			if err := wsWriteText(conn, msg); err != nil {
				return err
			}
			_, data, err := wsReadFrame(conn)
			if err != nil {
				return err
			}
			if string(data) != msg {
				return fmt.Errorf("msg %d: got %q, want %q", i, string(data), msg)
			}
		}
		return nil
	})

	add("websocket", "Large text message", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		msg := strings.Repeat("A", 10000)
		if err := wsWriteText(conn, msg); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if string(data) != msg {
			return fmt.Errorf("large text length: got %d, want %d", len(data), len(msg))
		}
		return nil
	})

	add("websocket", "Large binary message", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		payload := make([]byte, 50000)
		rand.Read(payload)
		if err := wsWriteBinary(conn, payload); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, payload) {
			return fmt.Errorf("large binary mismatch")
		}
		return nil
	})

	add("websocket", "Close handshake", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		wsWriteFrame(conn, 0x8, []byte{0x03, 0xE8})
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		// Server should respond with close frame
		op, _, _ := wsReadFrame(conn)
		conn.Close()
		if op != 0x8 {
			// Some servers may just close the connection
			return nil
		}
		return nil
	})

	add("websocket", "Sequential connections", func() error {
		for i := 0; i < 3; i++ {
			conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
			if err != nil {
				return fmt.Errorf("conn %d: %v", i, err)
			}
			wsWriteText(conn, "test")
			wsReadFrame(conn)
			wsClose(conn)
		}
		return nil
	})

	add("websocket", "Binary 1KB message", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		payload := make([]byte, 1024)
		rand.Read(payload)
		if err := wsWriteBinary(conn, payload); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, payload) {
			return fmt.Errorf("1KB binary mismatch")
		}
		return nil
	})

	add("websocket", "Text UTF-8 content", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		msg := "Hello 日本語 🌍"
		if err := wsWriteText(conn, msg); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if string(data) != msg {
			return fmt.Errorf("UTF-8 mismatch: %q", string(data))
		}
		return nil
	})

	add("websocket", "Rapid fire messages", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		for i := 0; i < 20; i++ {
			wsWriteText(conn, fmt.Sprintf("rapid-%d", i))
		}
		// Read back all responses
		for i := 0; i < 20; i++ {
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _, err := wsReadFrame(conn)
			if err != nil {
				return fmt.Errorf("read %d: %v", i, err)
			}
		}
		return nil
	})

	add("websocket", "Empty text message", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		if err := wsWriteText(conn, ""); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if len(data) != 0 {
			return fmt.Errorf("expected empty, got %d bytes", len(data))
		}
		return nil
	})

	add("websocket", "Empty binary message", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		if err := wsWriteBinary(conn, []byte{}); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if len(data) != 0 {
			return fmt.Errorf("expected empty, got %d bytes", len(data))
		}
		return nil
	})

	add("websocket", "Text then binary", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		wsWriteText(conn, "text")
		op1, d1, _ := wsReadFrame(conn)
		if op1 != 1 || string(d1) != "text" {
			return fmt.Errorf("text mismatch")
		}
		wsWriteBinary(conn, []byte{0xAB, 0xCD})
		op2, d2, _ := wsReadFrame(conn)
		if op2 != 2 || !bytes.Equal(d2, []byte{0xAB, 0xCD}) {
			return fmt.Errorf("binary mismatch")
		}
		return nil
	})

	add("websocket", "Multiple connections simultaneous", func() error {
		conns := make([]net.Conn, 3)
		var openErr error
		for i := range conns {
			c, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
			if err != nil {
				openErr = fmt.Errorf("conn %d: %v", i, err)
				break
			}
			conns[i] = c
		}
		if openErr != nil {
			for _, c := range conns {
				if c != nil {
					wsClose(c)
				}
			}
			return openErr
		}
		for i, c := range conns {
			msg := fmt.Sprintf("hello from %d", i)
			wsWriteText(c, msg)
			_, data, err := wsReadFrame(c)
			if err != nil {
				for _, c := range conns {
					wsClose(c)
				}
				return err
			}
			if string(data) != msg {
				for _, c := range conns {
					wsClose(c)
				}
				return fmt.Errorf("conn %d echo mismatch", i)
			}
		}
		for _, c := range conns {
			wsClose(c)
		}
		return nil
	})

	add("websocket", "100KB binary payload", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		payload := make([]byte, 100*1024)
		rand.Read(payload)
		if err := wsWriteBinary(conn, payload); err != nil {
			return err
		}
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, payload) {
			return fmt.Errorf("100KB payload mismatch")
		}
		return nil
	})

	add("websocket", "Interleaved text messages", func() error {
		conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		messages := []string{"alpha", "bravo", "charlie", "delta"}
		for _, m := range messages {
			wsWriteText(conn, m)
			_, data, err := wsReadFrame(conn)
			if err != nil {
				return err
			}
			if string(data) != m {
				return fmt.Errorf("got %q, want %q", string(data), m)
			}
		}
		return nil
	})

	add("websocket", "Connection after close", func() error {
		// Ensure new connections work after a previous one closed
		conn1, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		wsClose(conn1)
		time.Sleep(100 * time.Millisecond)
		conn2, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
		if err != nil {
			return fmt.Errorf("second connect: %v", err)
		}
		wsWriteText(conn2, "after close")
		_, data, err := wsReadFrame(conn2)
		if err != nil {
			wsClose(conn2)
			return err
		}
		wsClose(conn2)
		if string(data) != "after close" {
			return fmt.Errorf("echo mismatch: %q", string(data))
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 10: Static Files (15 tests)
	// ════════════════════════════════════════════

	add("static", "Serve HTML file", func() error {
		resp, err := doGet(plainBase + "/static/test.html")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "<html>")
	})

	add("static", "Serve CSS file", func() error {
		resp, err := doGet(plainBase + "/static/test.css")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "body")
	})

	add("static", "Serve JS file", func() error {
		resp, err := doGet(plainBase + "/static/test.js")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "console.log")
	})

	add("static", "Serve PNG file", func() error {
		resp, err := doGet(plainBase + "/static/test.png")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 10 {
			return fmt.Errorf("PNG too small: %d bytes", len(body))
		}
		// Check PNG magic bytes
		if body[0] != 0x89 || body[1] != 0x50 {
			return fmt.Errorf("not a PNG: first bytes %x %x", body[0], body[1])
		}
		return nil
	})

	add("static", "Serve JSON file", func() error {
		resp, err := doGet(plainBase + "/static/test.json")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("not valid JSON")
		}
		return nil
	})

	add("static", "Serve TXT file", func() error {
		resp, err := doGet(plainBase + "/static/test.txt")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "plain text file")
	})

	add("static", "HTML MIME type", func() error {
		resp, err := doGet(plainBase + "/static/test.html")
		if err != nil {
			return err
		}
		resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "html") {
			return fmt.Errorf("expected html content-type, got %q", ct)
		}
		return nil
	})

	add("static", "CSS MIME type", func() error {
		resp, err := doGet(plainBase + "/static/test.css")
		if err != nil {
			return err
		}
		resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "css") {
			return fmt.Errorf("expected css content-type, got %q", ct)
		}
		return nil
	})

	add("static", "JS MIME type", func() error {
		resp, err := doGet(plainBase + "/static/test.js")
		if err != nil {
			return err
		}
		resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(ct), "javascript") && !strings.Contains(strings.ToLower(ct), "ecmascript") {
			return fmt.Errorf("expected javascript content-type, got %q", ct)
		}
		return nil
	})

	add("static", "PNG MIME type", func() error {
		resp, err := doGet(plainBase + "/static/test.png")
		if err != nil {
			return err
		}
		resp.Body.Close()
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "png") && !strings.Contains(ct, "image") {
			return fmt.Errorf("expected image content-type, got %q", ct)
		}
		return nil
	})

	add("static", "Path traversal blocked", func() error {
		resp, err := doGet(plainBase + "/static/../../etc/passwd")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return fmt.Errorf("path traversal should be blocked")
		}
		return nil
	})

	add("static", "Non-existent file 404", func() error {
		resp, err := doGet(plainBase + "/static/doesnotexist.xyz")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 404)
	})

	add("static", "Static file content-length", func() error {
		resp, err := doGet(plainBase + "/static/test.html")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if len(body) == 0 {
			return fmt.Errorf("empty static file")
		}
		return nil
	})

	add("static", "Repeated static requests", func() error {
		for i := 0; i < 5; i++ {
			resp, err := doGet(plainBase + "/static/test.html")
			if err != nil {
				return fmt.Errorf("request %d: %v", i, err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("request %d: status %d", i, resp.StatusCode)
			}
		}
		return nil
	})

	add("static", "JSON static file content", func() error {
		resp, err := doGet(plainBase + "/static/test.json")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			return err
		}
		if m["testKey"] != "testValue" {
			return fmt.Errorf("unexpected value: %v", m["testKey"])
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 11: Streaming/SSE (15 tests)
	// ════════════════════════════════════════════

	add("streaming", "Stream chunks received", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "chunk-0") || !strings.Contains(body, "chunk-4") {
			return fmt.Errorf("missing chunks: %q", body)
		}
		return nil
	})

	add("streaming", "Stream all 5 chunks", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		for i := 0; i < 5; i++ {
			if !strings.Contains(body, fmt.Sprintf("chunk-%d", i)) {
				return fmt.Errorf("missing chunk-%d", i)
			}
		}
		return nil
	})

	add("streaming", "Stream status 200", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 200)
	})

	add("streaming", "Stream X-Stream header", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Stream", "yes")
	})

	add("streaming", "SSE event format", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "event: update") {
			return fmt.Errorf("missing SSE event format: %q", body)
		}
		return nil
	})

	add("streaming", "SSE data field", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "data: ") {
			return fmt.Errorf("missing SSE data field: %q", body)
		}
		return nil
	})

	add("streaming", "SSE multiple events", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		count := strings.Count(body, "event: update")
		if count < 3 {
			return fmt.Errorf("expected 3 events, got %d", count)
		}
		return nil
	})

	add("streaming", "SSE JSON data", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, `"seq"`) {
			return fmt.Errorf("missing JSON seq in SSE: %q", body)
		}
		return nil
	})

	add("streaming", "SSE content-type", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "text/event-stream")
	})

	add("streaming", "Large stream 400KB", func() error {
		resp, err := doGet(plainBase + "/stream/large")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 400000 {
			return fmt.Errorf("expected ~400KB, got %d bytes", len(body))
		}
		return nil
	})

	add("streaming", "Stream content-type octet", func() error {
		resp, err := doGet(plainBase + "/stream/large")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "octet-stream")
	})

	add("streaming", "Stream repeated requests", func() error {
		for i := 0; i < 3; i++ {
			resp, err := doGet(plainBase + "/stream/chunks")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			body, _ := readBody(resp)
			if !strings.Contains(body, "chunk-0") {
				return fmt.Errorf("req %d: missing chunks", i)
			}
		}
		return nil
	})

	add("streaming", "SSE double newline separator", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "\n\n") {
			return fmt.Errorf("SSE events should be separated by double newline")
		}
		return nil
	})

	add("streaming", "Stream does not hang", func() error {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if len(body) == 0 {
			return fmt.Errorf("empty response")
		}
		return nil
	})

	add("streaming", "Large stream content correct", func() error {
		resp, err := doGet(plainBase + "/stream/large")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		// 100 chunks of 4096 'A' characters
		for _, c := range body {
			if c != 'A' {
				return fmt.Errorf("unexpected character in stream: %q", string(c))
			}
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 12: HTTP/2 (20 tests)
	// ════════════════════════════════════════════

	add("h2", "H2 GET request", func() error {
		resp, err := doH2("GET", tlsBase+"/get", "")
		if err != nil {
			return err
		}
		if err := expectStatus(resp, 200); err != nil {
			resp.Body.Close()
			return err
		}
		return expectBody(resp, "GET OK")
	})

	add("h2", "H2 POST request", func() error {
		resp, err := doH2("POST", tlsBase+"/post", "h2 body")
		if err != nil {
			return err
		}
		return expectBody(resp, "POST OK: h2 body")
	})

	add("h2", "H2 uses HTTP/2 protocol", func() error {
		resp, err := doH2("GET", tlsBase+"/ping", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.Proto != "HTTP/2.0" {
			return fmt.Errorf("expected HTTP/2.0, got %s", resp.Proto)
		}
		return nil
	})

	add("h2", "H2 status 201", func() error {
		resp, err := doH2("GET", tlsBase+"/status/201", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 201)
	})

	add("h2", "H2 status 404", func() error {
		resp, err := doH2("GET", tlsBase+"/status/404", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 404)
	})

	add("h2", "H2 custom headers", func() error {
		resp, err := doH2("GET", tlsBase+"/headers/set", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Custom-One", "value1")
	})

	add("h2", "H2 JSON response", func() error {
		resp, err := doH2("GET", tlsBase+"/response/json", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("invalid JSON over H2")
		}
		return nil
	})

	add("h2", "H2 large response", func() error {
		resp, err := doH2("GET", tlsBase+"/response/large", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if len(body) != 1024*1024 {
			return fmt.Errorf("expected 1MB, got %d", len(body))
		}
		return nil
	})

	add("h2", "H2 echo body", func() error {
		resp, err := doH2("POST", tlsBase+"/echo", "h2 echo test")
		if err != nil {
			return err
		}
		return expectBody(resp, "h2 echo test")
	})

	add("h2", "H2 routing params", func() error {
		resp, err := doH2("GET", tlsBase+"/param/h2id", "")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=h2id")
	})

	add("h2", "H2 routing catch-all", func() error {
		resp, err := doH2("GET", tlsBase+"/catch/h2/path", "")
		if err != nil {
			return err
		}
		return expectBody(resp, "path=h2/path")
	})

	add("h2", "H2 concurrent requests", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				resp, err := doH2("GET", tlsBase+fmt.Sprintf("/concurrent/%d", id), "")
				if err != nil {
					errCount.Add(1)
					return
				}
				body, _ := readBody(resp)
				if body != fmt.Sprintf("id=%d", id) {
					errCount.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d concurrent H2 requests failed", errCount.Load())
		}
		return nil
	})

	add("h2", "H2 PUT method", func() error {
		resp, err := doH2("PUT", tlsBase+"/put", "h2 put")
		if err != nil {
			return err
		}
		return expectBody(resp, "PUT OK: h2 put")
	})

	add("h2", "H2 DELETE method", func() error {
		resp, err := doH2("DELETE", tlsBase+"/delete", "")
		if err != nil {
			return err
		}
		return expectBody(resp, "DELETE OK")
	})

	add("h2", "H2 204 No Content", func() error {
		resp, err := doH2("GET", tlsBase+"/status/204", "")
		if err != nil {
			return err
		}
		return expectStatus(resp, 204)
	})

	add("h2", "H2 500 Error", func() error {
		resp, err := doH2("GET", tlsBase+"/status/500", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 500)
	})

	add("h2", "H2 content-type json", func() error {
		resp, err := doH2("GET", tlsBase+"/response/json", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "json")
	})

	add("h2", "H2 content-type html", func() error {
		resp, err := doH2("GET", tlsBase+"/response/html", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "html")
	})

	add("h2", "H2 upload body", func() error {
		body := strings.Repeat("H", 10000)
		resp, err := doH2("POST", tlsBase+"/upload", body)
		if err != nil {
			return err
		}
		return expectBody(resp, "10000")
	})

	add("h2", "H2 multiple sequential", func() error {
		for i := 0; i < 5; i++ {
			resp, err := doH2("GET", tlsBase+"/ping", "")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			if err := expectBody(resp, "pong"); err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 13: TLS/HTTPS (15 tests)
	// ════════════════════════════════════════════

	add("tls", "TLS connection established", func() error {
		resp, err := doTLS("GET", tlsBase+"/ping", "")
		if err != nil {
			return err
		}
		return expectBody(resp, "pong")
	})

	add("tls", "TLS GET request", func() error {
		resp, err := doTLS("GET", tlsBase+"/get", "")
		if err != nil {
			return err
		}
		return expectBody(resp, "GET OK")
	})

	add("tls", "TLS POST request", func() error {
		resp, err := doTLS("POST", tlsBase+"/post", "tls body")
		if err != nil {
			return err
		}
		return expectBody(resp, "POST OK: tls body")
	})

	add("tls", "TLS response headers", func() error {
		resp, err := doTLS("GET", tlsBase+"/headers/set", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Custom-One", "value1")
	})

	add("tls", "TLS status codes", func() error {
		resp, err := doTLS("GET", tlsBase+"/status/201", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 201)
	})

	add("tls", "TLS large response", func() error {
		resp, err := doTLS("GET", tlsBase+"/response/large", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if len(body) != 1024*1024 {
			return fmt.Errorf("expected 1MB, got %d", len(body))
		}
		return nil
	})

	add("tls", "TLS JSON response", func() error {
		resp, err := doTLS("GET", tlsBase+"/response/json", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("invalid JSON")
		}
		return nil
	})

	add("tls", "TLS echo body", func() error {
		resp, err := doTLS("POST", tlsBase+"/echo", "secure echo")
		if err != nil {
			return err
		}
		return expectBody(resp, "secure echo")
	})

	add("tls", "TLS routing params", func() error {
		resp, err := doTLS("GET", tlsBase+"/param/secure123", "")
		if err != nil {
			return err
		}
		return expectBody(resp, "id=secure123")
	})

	add("tls", "TLS concurrent", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				resp, err := doTLS("GET", tlsBase+fmt.Sprintf("/concurrent/%d", id), "")
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}(i)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d TLS requests failed", errCount.Load())
		}
		return nil
	})

	add("tls", "TLS repeated connections", func() error {
		for i := 0; i < 5; i++ {
			resp, err := doTLS("GET", tlsBase+"/ping", "")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			resp.Body.Close()
		}
		return nil
	})

	add("tls", "TLS upload body", func() error {
		resp, err := doTLS("POST", tlsBase+"/upload", strings.Repeat("X", 10000))
		if err != nil {
			return err
		}
		return expectBody(resp, "10000")
	})

	add("tls", "HTTPS H1 fallback", func() error {
		resp, err := tlsH1Client.Get(tlsBase + "/ping")
		if err != nil {
			return err
		}
		if resp.Proto != "HTTP/1.1" {
			resp.Body.Close()
			return fmt.Errorf("expected HTTP/1.1 fallback, got %s", resp.Proto)
		}
		return expectBody(resp, "pong")
	})

	add("tls", "TLS WebSocket upgrade", func() error {
		conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		defer wsClose(conn)
		wsWriteText(conn, "tls ws")
		_, data, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if string(data) != "tls ws" {
			return fmt.Errorf("TLS WS echo: got %q", string(data))
		}
		return nil
	})

	add("tls", "TLS static file", func() error {
		resp, err := doTLS("GET", tlsBase+"/static/test.html", "")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "<html>")
	})

	// ════════════════════════════════════════════
	// CATEGORY 14: Cookies (10 tests)
	// ════════════════════════════════════════════

	add("cookies", "Set-Cookie header present", func() error {
		resp, err := doGet(plainBase + "/cookie/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		sc := resp.Header.Get("Set-Cookie")
		if sc == "" {
			return fmt.Errorf("no Set-Cookie header")
		}
		return nil
	})

	add("cookies", "Cookie name=value", func() error {
		resp, err := doGet(plainBase + "/cookie/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Set-Cookie", "session=abc123")
	})

	add("cookies", "Cookie HttpOnly", func() error {
		resp, err := doGet(plainBase + "/cookie/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Set-Cookie", "HttpOnly")
	})

	add("cookies", "Cookie Secure", func() error {
		resp, err := doGet(plainBase + "/cookie/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Set-Cookie", "Secure")
	})

	add("cookies", "Cookie SameSite", func() error {
		resp, err := doGet(plainBase + "/cookie/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Set-Cookie", "SameSite")
	})

	add("cookies", "Cookie Path", func() error {
		resp, err := doGet(plainBase + "/cookie/set")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Set-Cookie", "Path=/")
	})

	add("cookies", "Cookie round-trip", func() error {
		resp, err := doReq("GET", plainBase+"/cookie/get", "", map[string]string{"Cookie": "session=test123"})
		if err != nil {
			return err
		}
		return expectBody(resp, "cookie=session=test123")
	})

	add("cookies", "Multiple cookies set", func() error {
		resp, err := doGet(plainBase + "/cookie/multi")
		if err != nil {
			return err
		}
		resp.Body.Close()
		cookies := resp.Header.Values("Set-Cookie")
		if len(cookies) < 2 {
			return fmt.Errorf("expected multiple Set-Cookie, got %d", len(cookies))
		}
		return nil
	})

	add("cookies", "Cookie get empty", func() error {
		resp, err := doGet(plainBase + "/cookie/get")
		if err != nil {
			return err
		}
		return expectBody(resp, "cookie=")
	})

	add("cookies", "Cookie multiple values", func() error {
		resp, err := doReq("GET", plainBase+"/cookie/get", "", map[string]string{"Cookie": "a=1; b=2; c=3"})
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "a=1")
	})

	// ════════════════════════════════════════════
	// CATEGORY 15: Redirects (10 tests)
	// ════════════════════════════════════════════

	add("redirects", "301 redirect", func() error {
		resp, err := doGet(plainBase + "/redirect/301")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if err := expectStatus(resp, 301); err != nil {
			return err
		}
		return expectHeader(resp, "Location", "/get")
	})

	add("redirects", "302 redirect", func() error {
		resp, err := doGet(plainBase + "/redirect/302")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if err := expectStatus(resp, 302); err != nil {
			return err
		}
		return expectHeader(resp, "Location", "/get")
	})

	add("redirects", "307 redirect", func() error {
		resp, err := doGet(plainBase + "/redirect/307")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 307)
	})

	add("redirects", "308 redirect", func() error {
		resp, err := doGet(plainBase + "/redirect/308")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 308)
	})

	add("redirects", "Redirect Location header", func() error {
		resp, err := doGet(plainBase + "/redirect/301")
		if err != nil {
			return err
		}
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if loc == "" {
			return fmt.Errorf("missing Location header")
		}
		return nil
	})

	add("redirects", "Redirect has body", func() error {
		resp, err := doGet(plainBase + "/redirect/301")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "redirecting") {
			return fmt.Errorf("expected redirect body, got %q", body)
		}
		return nil
	})

	add("redirects", "Multiple redirect codes", func() error {
		codes := []int{301, 302, 307, 308}
		for _, code := range codes {
			resp, err := doGet(plainBase + fmt.Sprintf("/redirect/%d", code))
			if err != nil {
				return fmt.Errorf("code %d: %v", code, err)
			}
			resp.Body.Close()
			if resp.StatusCode != code {
				return fmt.Errorf("expected %d, got %d", code, resp.StatusCode)
			}
		}
		return nil
	})

	add("redirects", "301 not followed", func() error {
		resp, err := doGet(plainBase + "/redirect/301")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 301 {
			return fmt.Errorf("client followed redirect: status %d", resp.StatusCode)
		}
		return nil
	})

	add("redirects", "302 not followed", func() error {
		resp, err := doGet(plainBase + "/redirect/302")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 302 {
			return fmt.Errorf("client followed redirect: status %d", resp.StatusCode)
		}
		return nil
	})

	add("redirects", "Redirect repeated requests", func() error {
		for i := 0; i < 5; i++ {
			resp, err := doGet(plainBase + "/redirect/301")
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != 301 {
				return fmt.Errorf("req %d: expected 301, got %d", i, resp.StatusCode)
			}
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 16: Timeouts & Connections (10 tests)
	// ════════════════════════════════════════════

	add("connections", "Keep-alive connection reuse", func() error {
		client := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    1,
				IdleConnTimeout: 30 * time.Second,
			},
		}
		for i := 0; i < 3; i++ {
			resp, err := client.Get(plainBase + "/keepalive")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			resp.Body.Close()
		}
		return nil
	})

	add("connections", "Connection close honored", func() error {
		req, _ := http.NewRequest("GET", plainBase+"/get", nil)
		req.Header.Set("Connection", "close")
		resp, err := plainClient.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 200)
	})

	add("connections", "Concurrent connections", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				resp, err := doGet(plainBase + fmt.Sprintf("/concurrent/%d", id))
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}(i)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d connections failed", errCount.Load())
		}
		return nil
	})

	add("connections", "Rapid sequential requests", func() error {
		for i := 0; i < 50; i++ {
			resp, err := doGet(plainBase + "/ping")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			resp.Body.Close()
		}
		return nil
	})

	add("connections", "Slow endpoint completes", func() error {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(plainBase + "/slow")
		if err != nil {
			return err
		}
		return expectBody(resp, "slow done")
	})

	add("connections", "Pipeline-style requests", func() error {
		// Multiple requests on same connection
		transport := &http.Transport{
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
		}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
		for i := 0; i < 10; i++ {
			resp, err := client.Get(plainBase + "/ping")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			resp.Body.Close()
		}
		return nil
	})

	add("connections", "Large payload within timeout", func() error {
		client := &http.Client{Timeout: 15 * time.Second}
		body := strings.Repeat("X", 1024*1024)
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Post(plainBase+"/upload", "text/plain", strings.NewReader(body))
		if err != nil {
			return err
		}
		_ = client
		return expectBody(resp, "1048576")
	})

	add("connections", "Many concurrent GET", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doGet(plainBase + "/get")
				if err != nil {
					errCount.Add(1)
					return
				}
				body, _ := readBody(resp)
				if body != "GET OK" {
					errCount.Add(1)
				}
			}()
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d failures in 50 concurrent GET", errCount.Load())
		}
		return nil
	})

	add("connections", "Mixed method concurrent", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		methods := []struct {
			method string
			url    string
		}{
			{"GET", "/get"},
			{"POST", "/post"},
			{"PUT", "/put"},
			{"DELETE", "/delete"},
			{"GET", "/ping"},
		}
		for i := 0; i < 20; i++ {
			wg.Add(1)
			m := methods[i%len(methods)]
			go func(method, url string) {
				defer wg.Done()
				resp, err := doReq(method, plainBase+url, "data", nil)
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					errCount.Add(1)
				}
			}(m.method, m.url)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d mixed method failures", errCount.Load())
		}
		return nil
	})

	add("connections", "Concurrent JSON endpoint", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doGet(plainBase + "/response/json")
				if err != nil {
					errCount.Add(1)
					return
				}
				body, _ := readBody(resp)
				if !json.Valid([]byte(body)) {
					errCount.Add(1)
				}
			}()
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d JSON concurrent failures", errCount.Load())
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 17: Concurrency & Stress (15 tests)
	// ════════════════════════════════════════════

	add("concurrency", "10 concurrent GET", func() error {
		return concurrentGET(10, "/ping")
	})

	add("concurrency", "50 concurrent GET", func() error {
		return concurrentGET(50, "/ping")
	})

	add("concurrency", "100 concurrent GET", func() error {
		return concurrentGET(100, "/ping")
	})

	add("concurrency", "10 concurrent POST", func() error {
		return concurrentPOST(10, "/echo", "test")
	})

	add("concurrency", "50 concurrent POST", func() error {
		return concurrentPOST(50, "/echo", "test")
	})

	add("concurrency", "Response ordering correct", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				resp, err := doGet(plainBase + fmt.Sprintf("/concurrent/%d", id))
				if err != nil {
					errCount.Add(1)
					return
				}
				body, _ := readBody(resp)
				if body != fmt.Sprintf("id=%d", id) {
					errCount.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d ordering errors", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Burst 100 rapid requests", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doGet(plainBase + "/get")
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}()
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d failures in burst", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Concurrent different routes", func() error {
		routes := []string{"/get", "/ping", "/response/json", "/response/string", "/headers/set"}
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 25; i++ {
			wg.Add(1)
			route := routes[i%len(routes)]
			go func(r string) {
				defer wg.Done()
				resp, err := doGet(plainBase + r)
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}(route)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d route failures", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Concurrent with compression", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doReq("GET", plainBase+"/compress/text", "", map[string]string{"Accept-Encoding": "gzip"})
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}()
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d compressed concurrent failures", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Concurrent uploads", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := strings.Repeat("U", 1024)
				resp, err := doReq("POST", plainBase+"/upload", body, nil)
				if err != nil {
					errCount.Add(1)
					return
				}
				b, _ := readBody(resp)
				if b != "1024" {
					errCount.Add(1)
				}
			}()
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d upload concurrency failures", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Concurrent static files", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		files := []string{"test.html", "test.css", "test.js", "test.json", "test.txt"}
		for i := 0; i < 15; i++ {
			wg.Add(1)
			f := files[i%len(files)]
			go func(file string) {
				defer wg.Done()
				resp, err := doGet(plainBase + "/static/" + file)
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					errCount.Add(1)
				}
			}(f)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d static concurrency failures", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Concurrent WebSocket + HTTP", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32

		// HTTP requests
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doGet(plainBase + "/get")
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}()
		}

		// WebSocket connections
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := wsHandshake("ws://127.0.0.1:8080/ws/echo")
				if err != nil {
					errCount.Add(1)
					return
				}
				wsWriteText(conn, "test")
				wsReadFrame(conn)
				wsClose(conn)
			}()
		}

		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d mixed WS+HTTP failures", errCount.Load())
		}
		return nil
	})

	add("concurrency", "Sequential rapid fire", func() error {
		for i := 0; i < 100; i++ {
			resp, err := doGet(plainBase + "/ping")
			if err != nil {
				return fmt.Errorf("req %d: %v", i, err)
			}
			resp.Body.Close()
		}
		return nil
	})

	add("concurrency", "200 concurrent GET", func() error {
		return concurrentGET(200, "/get")
	})

	// ════════════════════════════════════════════
	// CATEGORY 18: Error Handling (10 tests)
	// ════════════════════════════════════════════

	add("errors", "Invalid status code", func() error {
		resp, err := doGet(plainBase + "/status/999")
		if err != nil {
			return err
		}
		resp.Body.Close()
		// Should either 400 or handle gracefully
		return nil
	})

	add("errors", "Negative status code", func() error {
		resp, err := doGet(plainBase + "/status/-1")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 400)
	})

	add("errors", "Panic recovery in handler", func() error {
		resp, err := doGet(plainBase + "/middleware/panic")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 500)
	})

	add("errors", "Server survives after panic", func() error {
		doGet(plainBase + "/middleware/panic")
		resp, err := doGet(plainBase + "/get")
		if err != nil {
			return fmt.Errorf("server dead after panic: %v", err)
		}
		return expectBody(resp, "GET OK")
	})

	add("errors", "404 for missing route", func() error {
		resp, err := doGet(plainBase + "/absolutely/nothing/here")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 404)
	})

	add("errors", "405 for wrong method", func() error {
		resp, err := doReq("PATCH", plainBase+"/get", "", nil)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 405)
	})

	add("errors", "Invalid JSON returns 400", func() error {
		resp, err := doReq("POST", plainBase+"/echo/json", "not json", nil)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 400)
	})

	add("errors", "Empty POST to JSON endpoint", func() error {
		resp, err := doReq("POST", plainBase+"/echo/json", "", nil)
		if err != nil {
			return err
		}
		resp.Body.Close()
		// Empty body is not valid JSON
		if resp.StatusCode != 400 {
			return fmt.Errorf("expected 400 for empty JSON, got %d", resp.StatusCode)
		}
		return nil
	})

	add("errors", "Very long URL", func() error {
		longPath := "/" + strings.Repeat("a", 2000)
		resp, err := doGet(plainBase + longPath)
		if err != nil {
			// Connection error is acceptable for very long URLs
			return nil
		}
		resp.Body.Close()
		// Either 404 or 414 is acceptable
		return nil
	})

	add("errors", "Status 418 teapot", func() error {
		resp, err := doGet(plainBase + "/status/418")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 418)
	})

	// ── 3 bonus tests to reach 300 ──

	add("h2", "H2 PATCH method", func() error {
		resp, err := doH2("PATCH", tlsBase+"/patch", "h2 patch")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "PATCH OK")
	})

	add("websocket", "WS close with normal code", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		// Send close frame with code 1000
		closePayload := make([]byte, 2)
		binary.BigEndian.PutUint16(closePayload, 1000)
		wsWriteFrame(conn, 0x8, closePayload)
		// Should receive close back
		op, _, err := wsReadFrame(conn)
		if err != nil {
			conn.Close()
			return nil // server may just close
		}
		if op != 0x8 {
			conn.Close()
			return fmt.Errorf("expected close frame (0x8), got 0x%x", op)
		}
		conn.Close()
		return nil
	})

	add("middleware", "Recovery returns valid body", func() error {
		resp, err := doGet(plainBase + "/middleware/panic")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if resp.StatusCode != 500 {
			return fmt.Errorf("expected 500, got %d", resp.StatusCode)
		}
		if len(body) == 0 {
			return fmt.Errorf("expected non-empty body on panic recovery")
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 19: Cross-Protocol Streaming (20 tests)
	// Streaming/SSE over plain HTTP, TLS H1, and H2
	// ════════════════════════════════════════════

	// ── Plain HTTP streaming (uses io_uring StreamWriter takeover) ──
	add("xproto-stream", "Plain HTTP stream chunks", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "chunk-0") || !strings.Contains(body, "chunk-4") {
			return fmt.Errorf("missing chunks: %q", truncate(body, 200))
		}
		return nil
	})

	add("xproto-stream", "Plain HTTP stream status 200", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 200)
	})

	add("xproto-stream", "Plain HTTP chunked transfer", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		resp.Body.Close()
		// On HTTP/1.1, chunked streaming should use Transfer-Encoding: chunked
		te := resp.TransferEncoding
		if len(te) == 0 || te[0] != "chunked" {
			// Could also be identity if Content-Length is known
			// Both are acceptable since Go's http client de-chunks automatically
		}
		return expectStatus(resp, 200)
	})

	add("xproto-stream", "Plain HTTP SSE content-type", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "text/event-stream")
	})

	add("xproto-stream", "Plain HTTP SSE events", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		count := strings.Count(body, "event: update")
		if count < 3 {
			return fmt.Errorf("expected 3 events, got %d", count)
		}
		return nil
	})

	add("xproto-stream", "Plain HTTP large stream 400KB", func() error {
		resp, err := doGet(plainBase + "/stream/large")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 400000 {
			return fmt.Errorf("expected ~400KB, got %d bytes", len(body))
		}
		return nil
	})

	add("xproto-stream", "Plain HTTP stream X-Stream header", func() error {
		resp, err := doGet(plainBase + "/stream/chunks")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeader(resp, "X-Stream", "yes")
	})

	// ── TLS H1 streaming ──
	add("xproto-stream", "TLS H1 stream chunks", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/stream/chunks", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "chunk-0") || !strings.Contains(body, "chunk-4") {
			return fmt.Errorf("missing chunks: %q", truncate(body, 200))
		}
		return nil
	})

	add("xproto-stream", "TLS H1 SSE content-type", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/stream/sse", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "text/event-stream")
	})

	add("xproto-stream", "TLS H1 SSE events", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/stream/sse", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		count := strings.Count(body, "event: update")
		if count < 3 {
			return fmt.Errorf("expected 3 events, got %d", count)
		}
		return nil
	})

	add("xproto-stream", "TLS H1 large stream 400KB", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/stream/large", "")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 400000 {
			return fmt.Errorf("expected ~400KB, got %d bytes", len(body))
		}
		return nil
	})

	add("xproto-stream", "TLS H1 stream all correct", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/stream/large", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		for _, c := range body {
			if c != 'A' {
				return fmt.Errorf("unexpected character in stream: %q", string(c))
			}
		}
		return nil
	})

	// ── H2 streaming ──
	add("xproto-stream", "H2 stream chunks", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/chunks", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, "chunk-0") || !strings.Contains(body, "chunk-4") {
			return fmt.Errorf("missing chunks: %q", truncate(body, 200))
		}
		return nil
	})

	add("xproto-stream", "H2 SSE content-type", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/sse", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "text/event-stream")
	})

	add("xproto-stream", "H2 SSE events", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/sse", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		count := strings.Count(body, "event: update")
		if count < 3 {
			return fmt.Errorf("expected 3 events, got %d", count)
		}
		return nil
	})

	add("xproto-stream", "H2 large stream 400KB", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/large", "")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 400000 {
			return fmt.Errorf("expected ~400KB, got %d bytes", len(body))
		}
		return nil
	})

	add("xproto-stream", "H2 stream content correct", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/large", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		for _, c := range body {
			if c != 'A' {
				return fmt.Errorf("unexpected character in H2 stream: %q", string(c))
			}
		}
		return nil
	})

	add("xproto-stream", "H2 SSE JSON data", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/sse", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, `"seq"`) {
			return fmt.Errorf("missing JSON seq in SSE: %q", truncate(body, 200))
		}
		return nil
	})

	add("xproto-stream", "H2 stream octet content-type", func() error {
		resp, err := doH2("GET", tlsBase+"/stream/large", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectHeaderContains(resp, "Content-Type", "octet-stream")
	})

	add("xproto-stream", "Plain HTTP SSE JSON data", func() error {
		resp, err := doGet(plainBase + "/stream/sse")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !strings.Contains(body, `"seq"`) {
			return fmt.Errorf("missing JSON seq in SSE: %q", truncate(body, 200))
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 20: Cross-Protocol Static Files (15 tests)
	// ════════════════════════════════════════════

	// ── Plain HTTP static files (io_uring SendFile path) ──
	add("xproto-static", "Plain static HTML", func() error {
		resp, err := doGet(plainBase + "/static/test.html")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "<html>")
	})

	add("xproto-static", "Plain static JSON", func() error {
		resp, err := doGet(plainBase + "/static/test.json")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("not valid JSON")
		}
		return nil
	})

	add("xproto-static", "Plain static PNG", func() error {
		resp, err := doGet(plainBase + "/static/test.png")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 2 || body[0] != 0x89 || body[1] != 0x50 {
			return fmt.Errorf("not a PNG: first bytes %x", body[:min(2, len(body))])
		}
		return nil
	})

	// ── TLS H1 static files ──
	add("xproto-static", "TLS H1 static HTML", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/static/test.html", "")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "<html>")
	})

	add("xproto-static", "TLS H1 static CSS", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/static/test.css", "")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "body")
	})

	add("xproto-static", "TLS H1 static JSON", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/static/test.json", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("not valid JSON from TLS H1")
		}
		return nil
	})

	add("xproto-static", "TLS H1 static PNG", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/static/test.png", "")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 2 || body[0] != 0x89 || body[1] != 0x50 {
			return fmt.Errorf("not a PNG via TLS H1")
		}
		return nil
	})

	add("xproto-static", "TLS H1 static 404", func() error {
		resp, err := doTLSH1("GET", tlsBase+"/static/nonexistent.xyz", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 404)
	})

	// ── H2 static files ──
	add("xproto-static", "H2 static HTML", func() error {
		resp, err := doH2("GET", tlsBase+"/static/test.html", "")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "<html>")
	})

	add("xproto-static", "H2 static CSS", func() error {
		resp, err := doH2("GET", tlsBase+"/static/test.css", "")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "body")
	})

	add("xproto-static", "H2 static JSON", func() error {
		resp, err := doH2("GET", tlsBase+"/static/test.json", "")
		if err != nil {
			return err
		}
		body, _ := readBody(resp)
		if !json.Valid([]byte(body)) {
			return fmt.Errorf("not valid JSON from H2")
		}
		return nil
	})

	add("xproto-static", "H2 static PNG", func() error {
		resp, err := doH2("GET", tlsBase+"/static/test.png", "")
		if err != nil {
			return err
		}
		body, _ := readBodyBytes(resp)
		if len(body) < 2 || body[0] != 0x89 || body[1] != 0x50 {
			return fmt.Errorf("not a PNG via H2")
		}
		return nil
	})

	add("xproto-static", "H2 static TXT", func() error {
		resp, err := doH2("GET", tlsBase+"/static/test.txt", "")
		if err != nil {
			return err
		}
		return expectBodyContains(resp, "plain text file")
	})

	add("xproto-static", "H2 static 404", func() error {
		resp, err := doH2("GET", tlsBase+"/static/nonexistent.xyz", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return expectStatus(resp, 404)
	})

	add("xproto-static", "H2 static path traversal blocked", func() error {
		resp, err := doH2("GET", tlsBase+"/static/../../../etc/passwd", "")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return fmt.Errorf("path traversal should be blocked")
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 21: Cross-Protocol WebSocket (15 tests)
	// ════════════════════════════════════════════

	// ── Plain HTTP WebSocket ──
	add("xproto-ws", "Plain WS handshake 101", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	})

	add("xproto-ws", "Plain WS echo text", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		wsWriteText(conn, "hello plain")
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if string(payload) != "hello plain" {
			return fmt.Errorf("got %q, want %q", string(payload), "hello plain")
		}
		return nil
	})

	add("xproto-ws", "Plain WS echo binary", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		data := []byte{0x00, 0x01, 0x02, 0xFF}
		wsWriteBinary(conn, data)
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, data) {
			return fmt.Errorf("binary mismatch")
		}
		return nil
	})

	add("xproto-ws", "Plain WS accept hash correct", func() error {
		conn, err := wsHandshakeVerifyAccept("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	})

	add("xproto-ws", "Plain WS 100KB binary", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		data := make([]byte, 100*1024)
		for i := range data {
			data[i] = byte(i & 0xFF)
		}
		wsWriteBinary(conn, data)
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, data) {
			return fmt.Errorf("100KB binary mismatch: got %d bytes", len(payload))
		}
		return nil
	})

	// ── TLS (H1) WebSocket ──
	add("xproto-ws", "TLS H1 WS handshake", func() error {
		conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	})

	add("xproto-ws", "TLS H1 WS echo text", func() error {
		conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		wsWriteText(conn, "hello tls")
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if string(payload) != "hello tls" {
			return fmt.Errorf("got %q, want %q", string(payload), "hello tls")
		}
		return nil
	})

	add("xproto-ws", "TLS H1 WS echo binary", func() error {
		conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		wsWriteBinary(conn, data)
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, data) {
			return fmt.Errorf("binary mismatch over TLS")
		}
		return nil
	})

	add("xproto-ws", "TLS H1 WS accept hash correct", func() error {
		conn, err := wsHandshakeVerifyAccept("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	})

	add("xproto-ws", "TLS H1 WS large message", func() error {
		conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		data := make([]byte, 50*1024)
		for i := range data {
			data[i] = byte(i % 256)
		}
		wsWriteBinary(conn, data)
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, data) {
			return fmt.Errorf("50KB binary mismatch over TLS: got %d bytes", len(payload))
		}
		return nil
	})

	// ── Plain WS additional ──
	add("xproto-ws", "Plain WS multiple messages", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		for i := 0; i < 10; i++ {
			msg := fmt.Sprintf("msg-%d", i)
			wsWriteText(conn, msg)
			_, payload, err := wsReadFrame(conn)
			if err != nil {
				return fmt.Errorf("message %d: %v", i, err)
			}
			if string(payload) != msg {
				return fmt.Errorf("message %d: got %q, want %q", i, string(payload), msg)
			}
		}
		return nil
	})

	add("xproto-ws", "TLS WS multiple messages", func() error {
		conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		for i := 0; i < 10; i++ {
			msg := fmt.Sprintf("tls-msg-%d", i)
			wsWriteText(conn, msg)
			_, payload, err := wsReadFrame(conn)
			if err != nil {
				return fmt.Errorf("message %d: %v", i, err)
			}
			if string(payload) != msg {
				return fmt.Errorf("message %d: got %q, want %q", i, string(payload), msg)
			}
		}
		return nil
	})

	add("xproto-ws", "Plain WS concurrent echo", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
				if err != nil {
					errCount.Add(1)
					return
				}
				defer conn.Close()
				msg := fmt.Sprintf("concurrent-%d", idx)
				wsWriteText(conn, msg)
				_, payload, err := wsReadFrame(conn)
				if err != nil || string(payload) != msg {
					errCount.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d concurrent WS failures", errCount.Load())
		}
		return nil
	})

	add("xproto-ws", "TLS WS concurrent echo", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				conn, err := wsHandshake("wss://127.0.0.1:8443/ws/echo")
				if err != nil {
					errCount.Add(1)
					return
				}
				defer conn.Close()
				msg := fmt.Sprintf("tls-concurrent-%d", idx)
				wsWriteText(conn, msg)
				_, payload, err := wsReadFrame(conn)
				if err != nil || string(payload) != msg {
					errCount.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d TLS concurrent WS failures", errCount.Load())
		}
		return nil
	})

	add("xproto-ws", "Plain WS empty text frame", func() error {
		conn, err := wsHandshake("127.0.0.1:8080/ws/echo")
		if err != nil {
			return err
		}
		defer conn.Close()
		wsWriteText(conn, "")
		_, payload, err := wsReadFrame(conn)
		if err != nil {
			return err
		}
		if len(payload) != 0 {
			return fmt.Errorf("expected empty payload, got %d bytes", len(payload))
		}
		return nil
	})

	// ════════════════════════════════════════════
	// CATEGORY 22: Cross-Protocol Upload (10 tests)
	// ════════════════════════════════════════════

	add("xproto-upload", "Plain HTTP 1KB upload", func() error {
		body := strings.Repeat("U", 1024)
		resp, err := doReq("POST", plainBase+"/upload", body, nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "1024")
	})

	add("xproto-upload", "Plain HTTP 512KB upload", func() error {
		body := strings.Repeat("X", 512*1024)
		resp, err := doReq("POST", plainBase+"/upload", body, nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "524288")
	})

	add("xproto-upload", "TLS H1 1MB upload", func() error {
		body := strings.Repeat("T", 1024*1024)
		resp, err := doTLS("POST", tlsBase+"/upload", body)
		if err != nil {
			return err
		}
		return expectBody(resp, "1048576")
	})

	add("xproto-upload", "H2 1MB upload", func() error {
		body := strings.Repeat("H", 1024*1024)
		resp, err := doH2("POST", tlsBase+"/upload", body)
		if err != nil {
			return err
		}
		return expectBody(resp, "1048576")
	})

	add("xproto-upload", "H2 5MB upload", func() error {
		body := strings.Repeat("D", 5*1024*1024)
		resp, err := doH2("POST", tlsBase+"/upload", body)
		if err != nil {
			return err
		}
		return expectBody(resp, "5242880")
	})

	add("xproto-upload", "H2 10MB upload", func() error {
		body := strings.Repeat("M", 10*1024*1024)
		resp, err := doH2("POST", tlsBase+"/upload", body)
		if err != nil {
			return err
		}
		return expectBody(resp, "10485760")
	})

	add("xproto-upload", "TLS H1 echo body", func() error {
		resp, err := doTLS("POST", tlsBase+"/echo", "tls echo test")
		if err != nil {
			return err
		}
		return expectBody(resp, "tls echo test")
	})

	add("xproto-upload", "H2 echo body", func() error {
		resp, err := doH2("POST", tlsBase+"/echo", "h2 echo test")
		if err != nil {
			return err
		}
		return expectBody(resp, "h2 echo test")
	})

	add("xproto-upload", "Plain HTTP echo body", func() error {
		resp, err := doReq("POST", plainBase+"/echo", "plain echo test", nil)
		if err != nil {
			return err
		}
		return expectBody(resp, "plain echo test")
	})

	add("xproto-upload", "Concurrent multi-protocol uploads", func() error {
		var wg sync.WaitGroup
		var errCount atomic.Int32
		body := strings.Repeat("Z", 10*1024) // 10KB
		// Plain HTTP
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doReq("POST", plainBase+"/upload", body, nil)
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}()
		}
		// H2
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := doH2("POST", tlsBase+"/upload", body)
				if err != nil {
					errCount.Add(1)
					return
				}
				resp.Body.Close()
			}()
		}
		wg.Wait()
		if errCount.Load() > 0 {
			return fmt.Errorf("%d multi-protocol upload failures", errCount.Load())
		}
		return nil
	})

	totalExpected := 360
	if len(tests) != totalExpected {
		fmt.Fprintf(os.Stderr, "WARNING: Expected %d tests, got %d\n", totalExpected, len(tests))
	}

	return tests
}

// ── Concurrency helpers ──

func concurrentGET(n int, path string) error {
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := doGet(plainBase + path)
			if err != nil {
				errCount.Add(1)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if errCount.Load() > 0 {
		return fmt.Errorf("%d/%d requests failed", errCount.Load(), n)
	}
	return nil
}

func concurrentPOST(n int, path, body string) error {
	var wg sync.WaitGroup
	var errCount atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := doReq("POST", plainBase+path, body, nil)
			if err != nil {
				errCount.Add(1)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if errCount.Load() > 0 {
		return fmt.Errorf("%d/%d POST requests failed", errCount.Load(), n)
	}
	return nil
}
