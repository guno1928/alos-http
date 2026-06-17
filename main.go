package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/guno1928/alos-http/core"
)

type User struct {
	ID     string `json:"user_id"`
	Method string `json:"method"`
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	plainHTTP := false
	autoFineTune := os.Getenv("ALOS_FINE_TUNE") == "1"
	defaultDomain := getenvDefault("ALOS_DOMAIN", "localhost")
	tlsCertFile := os.Getenv("ALOS_TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("ALOS_TLS_KEY_FILE")
	useACME := os.Getenv("ALOS_USE_ACME") == "1"

	var s *core.Server
	if plainHTTP {
		s = core.New(core.Config{
			Addr:        ":80",
			IdleTimeout: 120 * time.Second,
			Listeners:   4,
			Debug:       false,
			LogRequests: false,
			PlainHTTP:   true,

			MaxBodySize:       10 << 20,
			MaxReadSize:       16 << 20,
			MaxWriteSize:      64 << 20,
			MaxHeaderSize:     8192,
			MaxConcurrentReqs: 10000,
			ServerName:        "ALOS",
		})
	} else {
		cfg := core.Config{
			Addr:             ":443",
			IdleTimeout:      120 * time.Second,
			HandshakeTimeout: 30 * time.Second,
			Listeners:        10,
			WorkerCount:      30,
			Debug:            false,
			LogRequests:      false,
			DefaultDomain:    defaultDomain,
			TLSCertFile:      tlsCertFile,
			TLSKeyFile:       tlsKeyFile,

			MaxBodySize:       10 << 20,
			MaxReadSize:       16 << 20,
			MaxWriteSize:      64 << 20,
			MaxHeaderSize:     8192,
			MaxConcurrentReqs: 99999999,
			ServerName:        "ALOS",
		}
		if useACME {
			cfg.ACME = &core.ACMEConfig{
				Email:   getenvDefault("ALOS_ACME_EMAIL", "admin@crimy.pro"),
				Domains: []string{getenvDefault("ALOS_ACME_DOMAIN", defaultDomain)},
			}
			if cfg.DefaultDomain == "" {
				cfg.DefaultDomain = cfg.ACME.Domains[0]
			}
		}
		s = core.New(cfg)
	}

	s.SetProxyCache(core.ProxyCacheConfig{
		MaxEntrySize:   4 << 20,
		MaxTotalBytes:  256 << 20,
		CompressLevel:  2,
		CompressMinLen: 512,
	})

	s.OnProxyError(func(pe core.ProxyError) {
		log.Printf("[PROXY-ERR] domain=%s backend=%s client=%s attempt=%d err=%v",
			pe.Domain, pe.Backend, pe.ClientAddr, pe.Attempt, pe.Err)
	})

	s.OnProxyRequest(func(pr *core.ProxyRequest) bool {
		log.Printf("[PROXY-REQ] %s %s from real_ip=%s -> %s (%s)",
			pr.Method, pr.Path, pr.ClientAddr, pr.Backend, pr.Domain)
		return true
	})

	s.OnProxyResponse(func(pr *core.ProxyResponse) {
		log.Printf("[PROXY-RESP] %d from %s -> %s (%s)",
			pr.StatusCode, pr.ClientAddr, pr.Backend, pr.Domain)
		pr.Headers = append(pr.Headers, [2]string{"X-Proxy-By", "ALOS"})

		if pr.Backend == "cache" {
			log.Printf("[PROXY-RESP] cache hit for %s%s, skipping CacheThis()", pr.Domain, pr.Path)
			return
		}
	})

	s.SetHTTPRoutes([]core.HTTPRoute{})

	s.Router.Use(core.Recovery())
	s.Router.Use(core.RealIP())
	s.Router.Use(core.RequestID())
	s.Router.Use(core.SecurityHeaders(core.DefaultSecurityHeaders()))
	s.Router.Use(core.Compress(core.CompressConfig{Level: 6, MinSize: 512}))

	s.Router.ANY("/", func(req *core.Request, resp *core.Response) {
		resp.Status(200).JSONString(`{"server":"ALOS","status":"running"}`)
	})

	s.Router.GET("/whoami", func(req *core.Request, resp *core.Response) {
		j := core.AcquireJSON()
		resp.Status(200).JSON(j.Marshal(map[string]any{
			"ip":     req.RemoteAddr,
			"method": req.Method,
			"path":   req.Path,
			"host":   req.Host,
			"proto":  req.Proto,
		}))
		j.Release()
	})

	s.Router.GET("/json", func(req *core.Request, resp *core.Response) {
		j := core.AcquireJSON()
		resp.Status(200).JSON(j.Marshal(map[string]any{
			"server":     "ALOS",
			"protocol":   req.Proto,
			"method":     req.Method,
			"path":       req.Path,
			"h2_conns":   core.Stats.H2Conns.Load(),
			"h1_conns":   core.Stats.H1Conns.Load(),
			"total_reqs": core.Stats.TotalReqs.Load(),
		}))
		j.Release()
	})

	s.Router.GET("/stats", func(req *core.Request, resp *core.Response) {
		entries, totalBytes, hits, misses := s.ProxyCacheStats()

		j := core.AcquireJSON()
		resp.Status(200).JSON(j.Marshal(map[string]any{
			"active_conns":  core.Stats.ActiveConns.Load(),
			"total_conns":   core.Stats.TotalConns.Load(),
			"h2_conns":      core.Stats.H2Conns.Load(),
			"h1_conns":      core.Stats.H1Conns.Load(),
			"total_reqs":    core.Stats.TotalReqs.Load(),
			"bytes_in":      core.Stats.BytesIn.Load(),
			"bytes_out":     core.Stats.BytesOut.Load(),
			"cache_entries": entries,
			"cache_bytes":   totalBytes,
			"cache_hits":    hits,
			"cache_misses":  misses,
		}))
		j.Release()
	})

	s.Router.GET("/health", func(req *core.Request, resp *core.Response) {
		resp.Status(200).JSONString(`{"status":"ok"}`)
	})

	s.Router.POST("/echo", func(req *core.Request, resp *core.Response) {
		ct := req.Header("content-type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		resp.Status(200).SetHeader("Content-Type", ct)
		resp.SetBody(req.Body)
	})

	s.Router.GET("/users/:id", func(req *core.Request, resp *core.Response) {
		resp.Status(200).JSONMarshal(User{
			ID:     req.ParamValue("id"),
			Method: req.Method,
		})
	})

	api := s.Router.Group("/api", core.Logger())
	api.GET("/status", func(req *core.Request, resp *core.Response) {
		resp.Status(200).JSONString(`{"api":"v1","status":"running"}`)
	})

	s.Router.GET("/download", func(req *core.Request, resp *core.Response) {
		resp.SendFile("alos-tls.exe",
			core.WithAttachment("alos-tls.exe"),
			core.WithRateLimit(100),
		)
	})

	if autoFineTune {
		log.Printf("[FINETUNE] starting worker/listener auto-tune")
		if err := s.FineTune(); err != nil {
			log.Fatalf("[FINETUNE] failed: %v", err)
		}
	}

	if plainHTTP {
		go func() {
			if err := s.ListenAndServe(); err != nil {
				log.Fatal(err)
			}
		}()
	} else {
		go func() {
			if err := s.ListenAndServeTLS(); err != nil {
				log.Fatal(err)
			}
		}()
		go func() {
			if err := s.ListenAndServeQUIC(); err != nil {
				log.Printf("[QUIC] %v", err)
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received %v, shutting down...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
	log.Println("Server stopped")
}

func getenvDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
