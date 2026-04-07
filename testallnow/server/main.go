package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/guno1928/alos-http/core"
)

const (
	plainAddr       = ":8080"
	tlsAddr         = ":8443"
	tlsHTTPRedirect = "127.0.0.1:18080"
	staticDir       = "static"
)

func main() {
	runtime.GOMAXPROCS(max(1, runtime.NumCPU()))

	plainServer := newPlainServer()
	tlsServer := newTLSServer()

	errCh := make(chan error, 2)
	go func() { errCh <- plainServer.ListenAndServe() }()
	go func() { errCh <- tlsServer.ListenAndServeTLS() }()

	// Write ready marker
	time.Sleep(500 * time.Millisecond)
	os.WriteFile("/tmp/server-ready", []byte("1"), 0644)
	log.Println("[testserver] ready on :8080 (plain) and :8443 (TLS)")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)

	select {
	case err := <-errCh:
		log.Fatalf("[testserver] fatal: %v", err)
	case <-sig:
		log.Println("[testserver] shutting down")
	}
}

func newPlainServer() *core.Server {
	cfg := baseConfig()
	cfg.Addr = plainAddr
	cfg.PlainHTTP = true

	s := core.New(cfg)
	registerRoutes(s)
	addMiddleware(s)
	return s
}

func newTLSServer() *core.Server {
	cfg := baseConfig()
	cfg.Addr = tlsAddr
	cfg.HTTPAddr = tlsHTTPRedirect
	cfg.PlainHTTP = false
	cfg.Certs = []core.CertConfig{
		{Domain: "localhost", Source: core.CertSelfSigned},
	}

	s := core.New(cfg)
	registerRoutes(s)
	addMiddleware(s)
	return s
}

func baseConfig() core.Config {
	return core.Config{
		IdleTimeout:  60 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		MaxBodySize:  50 << 20,
		WorkerCount:  max(1, runtime.NumCPU()),
		Listeners:    1,
		ServerName:   "ALOS-Test",
		LogRequests:  false,
	}
}

func addMiddleware(s *core.Server) {
	s.Router.Use(core.Recovery())
}

func registerRoutes(s *core.Server) {
	// ── Basic HTTP methods ──
	s.Router.GET("/get", handleGet)
	s.Router.POST("/post", handlePost)
	s.Router.PUT("/put", handlePut)
	s.Router.DELETE("/delete", handleDelete)
	s.Router.PATCH("/patch", handlePatch)
	s.Router.HEAD("/head", handleHead)
	s.Router.OPTIONS("/options", handleOptions)
	s.Router.ANY("/any", handleAny)

	// ── Routing ──
	s.Router.GET("/", handleRoot)
	s.Router.GET("/param/:id", handleParam)
	s.Router.GET("/params/:team/:user", handleMultiParam)
	s.Router.GET("/catch/*path", handleCatchAll)
	s.Router.GET("/nested/a/b/c", handleNested)
	s.Router.GET("/priority/static", handlePriorityStatic)
	s.Router.GET("/priority/:param", handlePriorityParam)
	s.Router.GET("/deep/1/2/3/4/5", handleDeep)
	s.Router.GET("/samepath", handleSamePathGet)
	s.Router.POST("/samepath", handleSamePathPost)
	s.Router.GET("/longpath/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", handleLongPath)

	// custom 404/405
	s.Router.NotFound(handleCustomNotFound)
	s.Router.MethodNotAllowed(handleCustomMethodNotAllowed)

	// ── Echo ──
	s.Router.POST("/echo", handleEcho)
	s.Router.PUT("/echo", handleEcho)
	s.Router.POST("/echo/json", handleEchoJSON)
	s.Router.POST("/echo/binary", handleEchoBinary)

	// ── Status codes ──
	s.Router.GET("/status/:code", handleStatus)

	// ── Headers ──
	s.Router.GET("/headers/echo", handleHeadersEcho)
	s.Router.GET("/headers/set", handleHeadersSet)
	s.Router.GET("/headers/multi", handleHeadersMulti)
	s.Router.GET("/headers/security", handleHeadersSecurity)

	// ── Response types ──
	s.Router.GET("/response/string", handleRespString)
	s.Router.GET("/response/html", handleRespHTML)
	s.Router.GET("/response/bytes", handleRespBytes)
	s.Router.GET("/response/json", handleRespJSON)
	s.Router.GET("/response/json/string", handleRespJSONString)
	s.Router.GET("/response/json/marshal", handleRespJSONMarshal)
	s.Router.GET("/response/empty", handleRespEmpty)
	s.Router.GET("/response/large", handleRespLarge)

	// ── Compression ──
	compressedGet := core.Chain(handleCompressLarge, core.Compress(core.CompressConfig{Level: 6, MinSize: 64}))
	s.Router.GET("/compress/text", compressedGet)
	compressedJSON := core.Chain(handleCompressJSON, core.Compress(core.CompressConfig{Level: 6, MinSize: 64}))
	s.Router.GET("/compress/json", compressedJSON)
	compressedHTML := core.Chain(handleCompressHTML, core.Compress(core.CompressConfig{Level: 6, MinSize: 64}))
	s.Router.GET("/compress/html", compressedHTML)
	noCompSmall := core.Chain(handleCompressSmall, core.Compress(core.CompressConfig{Level: 6, MinSize: 1024}))
	s.Router.GET("/compress/small", noCompSmall)

	// ── Middleware-specific routes ──
	s.Router.GET("/middleware/panic", handlePanic)
	s.Router.GET("/middleware/requestid", core.Chain(handleRequestID, core.RequestID()))
	s.Router.GET("/middleware/requestid2", core.Chain(handleRequestID, core.RequestID()))
	s.Router.GET("/middleware/cors", core.Chain(handleSimple, core.CORS(core.CORSConfig{
		AllowOrigins:     []string{"https://example.com"},
		AllowMethods:     []string{"GET", "POST", "PUT"},
		AllowHeaders:     []string{"X-Custom", "Authorization"},
		ExposeHeaders:    []string{"X-Response-ID"},
		AllowCredentials: true,
		MaxAge:           3600,
	})))
	s.Router.OPTIONS("/middleware/cors", core.Chain(handleSimple, core.CORS(core.CORSConfig{
		AllowOrigins:     []string{"https://example.com"},
		AllowMethods:     []string{"GET", "POST", "PUT"},
		AllowHeaders:     []string{"X-Custom", "Authorization"},
		ExposeHeaders:    []string{"X-Response-ID"},
		AllowCredentials: true,
		MaxAge:           3600,
	})))
	s.Router.GET("/middleware/security", core.Chain(handleSimple, core.SecurityHeaders(core.DefaultSecurityHeaders())))

	// ── WebSocket ──
	s.Router.GET("/ws/echo", handleWSEcho)

	// ── Static files ──
	s.Router.GET("/static/*filepath", handleStaticFile)

	// ── Streaming/SSE ──
	s.Router.GET("/stream/chunks", handleStreamChunks)
	s.Router.GET("/stream/sse", handleSSE)
	s.Router.GET("/stream/large", handleStreamLarge)

	// ── Cookies ──
	s.Router.GET("/cookie/set", handleCookieSet)
	s.Router.GET("/cookie/multi", handleCookieMulti)
	s.Router.GET("/cookie/get", handleCookieGet)

	// ── Redirects ──
	s.Router.GET("/redirect/:code", handleRedirect)

	// ── Upload ──
	s.Router.POST("/upload", handleUpload)
	s.Router.POST("/upload/large", handleUpload)

	// ── Slow/timeout ──
	s.Router.GET("/slow", handleSlow)

	// ── Concurrent ──
	s.Router.GET("/concurrent/:id", handleConcurrent)

	// ── JSON endpoints ──
	s.Router.POST("/json/validate", handleJSONValidate)
	s.Router.GET("/json/array", handleJSONArray)
	s.Router.GET("/json/nested", handleJSONNested)

	// ── Keep-alive ──
	s.Router.GET("/keepalive", handleSimple)

	// ── Ping (health) ──
	s.Router.GET("/ping", handlePing)
}

// ── Handlers ──

func handleGet(req *core.Request, resp *core.Response) {
	resp.Status(200).String("GET OK")
}
func handlePost(req *core.Request, resp *core.Response) {
	resp.Status(200).String("POST OK: " + string(req.Body))
}
func handlePut(req *core.Request, resp *core.Response) {
	resp.Status(200).String("PUT OK: " + string(req.Body))
}
func handleDelete(req *core.Request, resp *core.Response) {
	resp.Status(200).String("DELETE OK")
}
func handlePatch(req *core.Request, resp *core.Response) {
	resp.Status(200).String("PATCH OK: " + string(req.Body))
}
func handleHead(req *core.Request, resp *core.Response) {
	resp.Status(200).SetHeader("X-Head-Test", "yes")
}
func handleOptions(req *core.Request, resp *core.Response) {
	resp.Status(200).SetHeader("Allow", "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
}
func handleAny(req *core.Request, resp *core.Response) {
	resp.Status(200).String(req.Method + " ANY OK")
}

func handleRoot(req *core.Request, resp *core.Response) {
	resp.Status(200).String("root")
}
func handleParam(req *core.Request, resp *core.Response) {
	resp.Status(200).String("id=" + req.ParamValue("id"))
}
func handleMultiParam(req *core.Request, resp *core.Response) {
	resp.Status(200).String("team=" + req.ParamValue("team") + ",user=" + req.ParamValue("user"))
}
func handleCatchAll(req *core.Request, resp *core.Response) {
	resp.Status(200).String("path=" + req.ParamValue("path"))
}
func handleNested(req *core.Request, resp *core.Response) {
	resp.Status(200).String("nested")
}
func handlePriorityStatic(req *core.Request, resp *core.Response) {
	resp.Status(200).String("static")
}
func handlePriorityParam(req *core.Request, resp *core.Response) {
	resp.Status(200).String("param=" + req.ParamValue("param"))
}
func handleDeep(req *core.Request, resp *core.Response) {
	resp.Status(200).String("deep")
}
func handleSamePathGet(req *core.Request, resp *core.Response) {
	resp.Status(200).String("GET samepath")
}
func handleSamePathPost(req *core.Request, resp *core.Response) {
	resp.Status(200).String("POST samepath")
}
func handleLongPath(req *core.Request, resp *core.Response) {
	resp.Status(200).String("longpath")
}
func handleCustomNotFound(req *core.Request, resp *core.Response) {
	resp.Status(404).String("custom 404")
}
func handleCustomMethodNotAllowed(req *core.Request, resp *core.Response) {
	resp.Status(405).String("custom 405")
}

func handleEcho(req *core.Request, resp *core.Response) {
	ct := req.Header("content-type")
	resp.Status(200).Bytes(req.Body)
	if ct != "" {
		resp.ContentType = ct
	}
}
func handleEchoJSON(req *core.Request, resp *core.Response) {
	if !json.Valid(req.Body) {
		resp.Status(400).String("invalid json")
		return
	}
	resp.Status(200).JSON(req.Body)
}
func handleEchoBinary(req *core.Request, resp *core.Response) {
	resp.Status(200).SetHeader("Content-Type", "application/octet-stream")
	resp.Bytes(req.Body)
}

func handleStatus(req *core.Request, resp *core.Response) {
	codeStr := req.ParamValue("code")
	code, err := strconv.Atoi(codeStr)
	if err != nil || code < 100 || code > 599 {
		resp.Status(400).String("bad status code")
		return
	}
	resp.Status(code)
	if code >= 200 && code != 204 && code != 304 {
		resp.String("status " + codeStr)
	}
}

func handleHeadersEcho(req *core.Request, resp *core.Response) {
	hdrs := make(map[string]string)
	for _, h := range req.Headers {
		hdrs[strings.ToLower(h[0])] = h[1]
	}
	data, _ := json.Marshal(hdrs)
	resp.Status(200).JSON(data)
}
func handleHeadersSet(req *core.Request, resp *core.Response) {
	resp.Status(200).
		SetHeader("X-Custom-One", "value1").
		SetHeader("X-Custom-Two", "value2").
		SetHeader("Cache-Control", "no-cache").
		SetHeader("ETag", `"abc123"`).
		String("headers set")
}
func handleHeadersMulti(req *core.Request, resp *core.Response) {
	resp.Status(200).
		SetHeader("X-Multi", "first").
		SetHeader("X-Multi", "second").
		String("multi headers")
}
func handleHeadersSecurity(req *core.Request, resp *core.Response) {
	resp.Status(200).
		SetHeader("X-Frame-Options", "DENY").
		SetHeader("X-Content-Type-Options", "nosniff").
		SetHeader("X-XSS-Protection", "1; mode=block").
		SetHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload").
		SetHeader("Referrer-Policy", "strict-origin-when-cross-origin").
		String("security headers")
}

func handleRespString(req *core.Request, resp *core.Response) {
	resp.Status(200).String("plain text response")
}
func handleRespHTML(req *core.Request, resp *core.Response) {
	resp.Status(200).HTML("<html><body>Hello</body></html>")
}
func handleRespBytes(req *core.Request, resp *core.Response) {
	resp.Status(200).Bytes([]byte{0xDE, 0xAD, 0xBE, 0xEF})
}
func handleRespJSON(req *core.Request, resp *core.Response) {
	resp.Status(200).JSON([]byte(`{"key":"value"}`))
}
func handleRespJSONString(req *core.Request, resp *core.Response) {
	resp.Status(200).JSONString(`{"result":"ok"}`)
}
func handleRespJSONMarshal(req *core.Request, resp *core.Response) {
	type item struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	resp.Status(200)
	resp.JSONMarshal(item{ID: 42, Name: "test"})
}
func handleRespEmpty(req *core.Request, resp *core.Response) {
	resp.Status(204)
}
func handleRespLarge(req *core.Request, resp *core.Response) {
	data := strings.Repeat("X", 1024*1024)
	resp.Status(200).String(data)
}

func handleCompressLarge(req *core.Request, resp *core.Response) {
	resp.Status(200).String(strings.Repeat("Hello World! This is compressible text. ", 200))
}
func handleCompressJSON(req *core.Request, resp *core.Response) {
	items := make([]map[string]any, 100)
	for i := range items {
		items[i] = map[string]any{"id": i, "name": fmt.Sprintf("item-%d", i), "value": strings.Repeat("data", 10)}
	}
	data, _ := json.Marshal(items)
	resp.Status(200).JSON(data)
}
func handleCompressHTML(req *core.Request, resp *core.Response) {
	body := "<html><body>" + strings.Repeat("<p>Paragraph content here for compression testing.</p>\n", 100) + "</body></html>"
	resp.Status(200).HTML(body)
}
func handleCompressSmall(req *core.Request, resp *core.Response) {
	resp.Status(200).String("tiny")
}

func handlePanic(_ *core.Request, _ *core.Response) {
	panic("test panic")
}

func handleRequestID(req *core.Request, resp *core.Response) {
	resp.Status(200).String("ok")
}

func handleSimple(req *core.Request, resp *core.Response) {
	resp.Status(200).String("ok")
}

func handleWSEcho(req *core.Request, resp *core.Response) {
	ws := core.UpgradeWebSocket(req, resp)
	if ws == nil {
		return
	}
	defer ws.Close()
	for {
		opcode, payload, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if opcode == 0x1 || opcode == 0x2 {
			if err := ws.WriteMessage(opcode, payload); err != nil {
				return
			}
		}
	}
}

func handleStaticFile(req *core.Request, resp *core.Response) {
	name := req.ParamValue("filepath")
	if strings.Contains(name, "..") {
		resp.Status(403).String("forbidden")
		return
	}
	path := staticDir + "/" + name
	if err := resp.SendFile(path); err != nil {
		resp.Status(404).String("not found: " + name)
	}
}

func handleStreamChunks(req *core.Request, resp *core.Response) {
	sw := resp.EnsureStreamWriter()
	if sw == nil {
		// Fallback: build in memory (shouldn't happen)
		var sb strings.Builder
		for i := 0; i < 5; i++ {
			sb.WriteString(fmt.Sprintf("chunk-%d\n", i))
		}
		resp.Status(200).SetHeader("X-Stream", "yes").String(sb.String())
		return
	}
	sw.WriteHeader(200, [][2]string{{"X-Stream", "yes"}}, "text/plain")
	resp.SetStreamer(sw)
	for i := 0; i < 5; i++ {
		sw.WriteChunk([]byte(fmt.Sprintf("chunk-%d\n", i)))
		sw.Flush()
	}
	sw.Close()
}

func handleSSE(req *core.Request, resp *core.Response) {
	sw := resp.EnsureStreamWriter()
	if sw == nil {
		var sb strings.Builder
		for i := 0; i < 3; i++ {
			sb.WriteString(fmt.Sprintf("event: update\ndata: {\"seq\":%d}\n\n", i))
		}
		resp.Status(200).String(sb.String())
		resp.ContentType = "text/event-stream"
		return
	}
	sw.WriteHeader(200, nil, "text/event-stream")
	resp.SetStreamer(sw)
	for i := 0; i < 3; i++ {
		sw.WriteChunk([]byte(fmt.Sprintf("event: update\ndata: {\"seq\":%d}\n\n", i)))
		sw.Flush()
	}
	sw.Close()
}

func handleStreamLarge(req *core.Request, resp *core.Response) {
	sw := resp.EnsureStreamWriter()
	if sw == nil {
		data := strings.Repeat("A", 4096*100)
		resp.Status(200).Bytes([]byte(data))
		resp.ContentType = "application/octet-stream"
		return
	}
	sw.WriteHeader(200, nil, "application/octet-stream")
	resp.SetStreamer(sw)
	chunk := []byte(strings.Repeat("A", 4096))
	for i := 0; i < 100; i++ {
		sw.WriteChunk(chunk)
	}
	sw.Flush()
	sw.Close()
}

func handleCookieSet(req *core.Request, resp *core.Response) {
	resp.Status(200).
		SetHeader("Set-Cookie", "session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict").
		String("cookie set")
}
func handleCookieMulti(req *core.Request, resp *core.Response) {
	resp.Status(200).
		SetHeader("Set-Cookie", "a=1; Path=/").
		SetHeader("Set-Cookie", "b=2; Path=/").
		SetHeader("Set-Cookie", "c=3; Path=/; HttpOnly").
		String("cookies set")
}
func handleCookieGet(req *core.Request, resp *core.Response) {
	cookie := req.Header("cookie")
	resp.Status(200).String("cookie=" + cookie)
}

func handleRedirect(req *core.Request, resp *core.Response) {
	codeStr := req.ParamValue("code")
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		resp.Status(400).String("bad code")
		return
	}
	resp.Status(code).SetHeader("Location", "/get")
	if code >= 300 && code < 400 {
		resp.String("redirecting")
	}
}

func handleUpload(req *core.Request, resp *core.Response) {
	resp.Status(200).String(strconv.Itoa(len(req.Body)))
}

func handleSlow(req *core.Request, resp *core.Response) {
	time.Sleep(1 * time.Second)
	resp.Status(200).String("slow done")
}

func handleConcurrent(req *core.Request, resp *core.Response) {
	id := req.ParamValue("id")
	resp.Status(200).String("id=" + id)
}

func handleJSONValidate(req *core.Request, resp *core.Response) {
	if !json.Valid(req.Body) {
		resp.Status(400).String("invalid json")
		return
	}
	var m map[string]any
	if err := json.Unmarshal(req.Body, &m); err != nil {
		resp.Status(400).String(err.Error())
		return
	}
	resp.Status(200)
	resp.JSONMarshal(m)
}
func handleJSONArray(req *core.Request, resp *core.Response) {
	arr := []int{1, 2, 3, 4, 5}
	resp.Status(200)
	resp.JSONMarshal(arr)
}
func handleJSONNested(req *core.Request, resp *core.Response) {
	nested := map[string]any{
		"level1": map[string]any{
			"level2": map[string]any{
				"value": 42,
			},
		},
	}
	resp.Status(200)
	resp.JSONMarshal(nested)
}

func handlePing(req *core.Request, resp *core.Response) {
	resp.Status(200).String("pong")
}
