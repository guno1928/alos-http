# ALOS HTTP - Go web framework on a custom epoll networking stack

> **Linux x86-64 only.** ALOS HTTP requires **Linux** on **amd64 (x86-64)** CPUs. It does not support Windows, macOS, ARM, or any other OS/architecture combination. If you are on Windows or macOS, use Docker or a Linux VM to run it.

> **Work in progress.** ALOS HTTP is still under active development and bugs may be present. If you find a bug or rough edge, please open a GitHub issue.
>
> **Join the Discord:** [https://alos.gg/discord](https://alos.gg/discord)

Based on the project's current published benchmark suite, ALOS HTTP is the fastest web framework currently available right now.

ALOS HTTP is a Linux-only Go web framework, Go HTTP server, and application server built around a custom networking stack running on a hand-built, edge-triggered `epoll` event loop. It only runs on **Linux amd64 (x86-64)** — the entire I/O layer, including HTTP/1.1, HTTP/2, HTTP/3 (QUIC), TLS, and reverse proxying, is built on a custom `epoll` backend and amd64-specific optimizations.

It includes first-class TLS handling, HTTP/1.1, HTTP/2, and HTTP/3 support, reverse proxying, load balancing, rate limiting, streaming, ACME automation, and a high-performance radix router.

It is designed for people who want more control than a thin net/http wrapper, while still getting an ergonomic handler API.

If you are looking for a high-performance Go web server or Go reverse proxy for Linux, ALOS HTTP is focused on the Linux fast path and its custom `epoll` networking stack rather than maintaining cross-platform behavior.

Official repository:
https://github.com/guno1928/alos-http

## Why ALOS HTTP

ALOS HTTP focuses on a different part of the stack than most Go web frameworks.

- Custom server core instead of delegating everything to net/http.
- Built-in HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) serving.
- Linux amd64 runtime on a custom `epoll` event-loop backend.
- Built-in TLS flow with ACME support for HTTPS and TLS automation.
- High-performance radix router with params, wildcards, groups, and middleware.
- Reverse proxy with load balancing, health checks, and cache support.
- Response streaming and file sending helpers.
- Middleware for recovery, logging, CORS, compression, auth, timeouts, security headers, and more.
- Rate limiting primitives and rule-driven limiting.

### Custom epoll networking stack

On Linux amd64, ALOS HTTP runs its entire I/O layer on a hand-built, edge-triggered `epoll` event loop instead of `net/http`:

- **TCP accept** — inbound connections are accepted on per-worker `SO_REUSEPORT` listeners, sharded across cores (listeners default to the machine's hardware thread count).
- **TLS record I/O** — a hand-rolled TLS 1.3 (and 1.2) record layer handles read, decrypt, encrypt, and write directly on the event loop, using AES-NI.
- **Plain HTTP I/O** — non-TLS HTTP/1.1 and HTTP/2 read/write paths run directly on the epoll loop, with per-connection response batching.
- **Reverse proxy egress** — outbound connections to backends (dial, send, receive) run over standard sockets.
- **Sendfile** — static file serving streams files to the client through the response path.
- **HTTP/2 framing** — HTTP/2 frame reads and writes on both the ingress and shared-bridge proxy paths run on the event loop.
- **HTTP/3 (QUIC)** — UDP socket I/O for QUIC uses `epoll` with `recvmmsg`/`sendmmsg` and UDP GSO batching, plus `SO_REUSEPORT` for multi-listener scaling.

The hot path is edge-triggered and allocation-free: requests are parsed, routed, and served without `net/http`, interface dispatch, or reflection. Slow handlers are offloaded to goroutines so they never block the event loop.

Search-friendly summary:

- Go web framework
- Go HTTP server
- Linux web server
- custom `epoll` networking stack
- reverse proxy and load balancer
- HTTP/1.1, HTTP/2, and HTTP/3 server
- QUIC server
- TLS 1.3 and ACME automation

## Platform Support

| | Supported |
|---|---|
| **OS** | Linux only |
| **Architecture** | amd64 (x86-64) only |
| **Go version** | Go 1.26+ |
| **Kernel** | Modern Linux; 4.18+ recommended for the HTTP/3 UDP GSO fast path |

- **Linux amd64 is the only supported platform.** ARM, RISC-V, 32-bit, Windows, macOS, and FreeBSD are not supported.
- The entire I/O stack (TCP accept, TLS, HTTP/1.1, HTTP/2, HTTP/3 QUIC, reverse proxy, sendfile) runs on a custom `epoll` event loop with `SO_REUSEPORT` sharding and amd64-specific optimizations.
- Hand-written amd64 assembly is used in hot paths (QUIC varint encoding, packet number processing).
- If you are developing on Windows or macOS, edit code locally and deploy/test on Linux via Docker or a Linux VM.
- For HTTP/3 (QUIC over UDP), the server uses `epoll`-driven UDP sockets with `recvmmsg`/`sendmmsg`, UDP GSO batching, and `SO_REUSEPORT`.

## How ALOS serves requests

ALOS HTTP does not use `net/http` for serving. It runs a custom, edge-triggered `epoll` event loop written for Linux amd64.

Very simple version:

- `net/http` gives every connection its own goroutine that blocks on read/write syscalls.
- ALOS runs a small pool of event-loop workers that watch many connections at once with `epoll` and only touch a connection when it is actually ready.

Why that matters for ALOS HTTP:

- less per-connection overhead and memory
- `SO_REUSEPORT` sharding scales the accept and serve path across all cores
- per-connection response batching and a short-read fast path cut syscalls
- lower latency on hot paths, and efficient handling of many active connections

Slow handlers are offloaded to goroutines so they never stall the event loop, and the fast path stays allocation-free for plain HTTP, TLS, and HTTP/2.

## Testing

in the testallnow directory, there are a variety of tests and benchmarks for ALOS HTTP.
=== SUMMARY ===
Test Results: 360 passed, 0 failed, 360 total

compression               15/15
concurrency               14/14
connections               10/10
cookies                   10/10
errors                    10/10
h2                        21/21
headers                   20/20
methods                   15/15
middleware                25/25
redirects                 10/10
request                   20/20
response                  25/25
routing                   25/25
static                    15/15
status-codes              15/15
streaming                 15/15
tls                       15/15
websocket                 20/20
xproto-static             15/15
xproto-stream             20/20
xproto-upload             10/10
xproto-ws                 15/15

Cleaning up container...

ALL 360 TESTS PASSED

## Benchmarks

If you want to see full benchmarks, go to:

https://alos.gg/aloshttpdocs/benchmarks

There are two benchmark views worth looking at:

- the published side-by-side framework comparison page

Published HTTPS HTTP/1.1 framework comparison:

| Framework | 500-conn throughput | 500-conn avg latency | 500-conn transfer/sec |
| --- | --- | --- | --- |
| ALOS HTTP | `222,353 req/s` | `1.86 ms` | `27.78 MB/s` |
| xitca-web (RUST framework) | `190,762 req/s` | `2.46 ms` | `23.65 MB/s` |
| ntex (RUST framework) | `176,532 req/s` | `2.44 ms` | `21.89 MB/s` |
| Fiber v3 | `174,555 req/s` | `2.76 ms` | `21.64 MB/s` |

Published throughput across connection levels:

| Framework | 200 conn | 500 conn | 1,200 conn | 5,000 conn |
| --- | --- | --- | --- | --- |
| ALOS HTTP | `222,916` | `222,353` | `192,575` | `120,998` |
| xitca-web (RUST framework) | `194,479` | `190,762` | `173,086` | `111,625` |
| ntex (RUST framework) | `172,456` | `176,532` | `159,512` | `105,211` |
| Fiber v3 | `180,861` | `174,555` | `156,505` | `100,916` |

Published comparison test environment:

- OS: Ubuntu 24
- CPU: Xeon E3-1270 v6 (8 threads)
- Tool: `wrk` (8 threads, 3-second runs)
- Protocol: TLS 1.3, HTTP/1.1, `Hello, World!` payload, local loopback

## Install

Linux only:

Add the module:

```bash
go get github.com/guno1928/alos-http@latest
```

Import the framework package:

```go
import "github.com/guno1928/alos-http/core"
```

If you want API documentation after publishing, the package docs will be available at:

https://alos.gg/aloshttpdocs/getting-started



## Quick Start

```go
package main

import (
    "log"
    "time"

    "github.com/guno1928/alos-http/core"
)

func main() {
    srv := core.New(core.Config{
        Addr:        ":8443",
        IdleTimeout: 120 * time.Second,
        ServerName:  "ALOS",
    })

    srv.Router.Use(core.Recovery())
    srv.Router.Use(core.RequestID())
    srv.Router.Use(core.SecurityHeaders(core.DefaultSecurityHeaders()))

    srv.Router.GET("/", func(req *core.Request, resp *core.Response) {
        resp.Status(200).String("ALOS HTTP is running")
    })

    srv.Router.GET("/users/:id", func(req *core.Request, resp *core.Response) {
        _ = resp.Status(200).JSONMarshal(map[string]any{
            "id":     req.ParamValue("id"),
            "method": req.Method,
            "path":   req.Path,
        })
    })

    log.Fatal(srv.ListenAndServeTLS())
}
```

## Auto Tune

ALOS HTTP has a built-in finetuner for Linux amd64. It benchmarks a set of worker and listener combinations on your machine, applies the best result automatically, and prints the full sweep at the end.

With the current default sweep it takes about 6 minutes to fully complete the raw benchmark runs, plus a little extra startup and shutdown time between runs.

this only has to be ran ONCE per machine to find the best tune.

```go
if err := srv.FineTune(); err != nil {
    log.Fatalf("[FINETUNE] failed: %v", err)
}
```

That will find the best tune for your machine from the built-in default candidates and apply the winning worker/listener configuration to the server.

## Plain HTTP Example

```go
srv := core.New(core.Config{
    Addr:      ":8080",
    PlainHTTP: true,
})

srv.Router.GET("/health", func(req *core.Request, resp *core.Response) {
    resp.Status(200).JSONString(`{"status":"ok"}`)
})

log.Fatal(srv.ListenAndServe())
```

## Middleware Example

```go
srv.Router.Use(core.Recovery())
srv.Router.Use(core.Logger())
srv.Router.Use(core.RealIP())
srv.Router.Use(core.RequestID())
srv.Router.Use(core.CORS(core.CORSConfig{
    AllowOrigins: []string{"*"},
    AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
}))
srv.Router.Use(core.Compress(core.CompressConfig{
    Level:   6,
    MinSize: 512,
}))
```

## Route Groups

```go
api := srv.Router.Group("/api", core.Logger())

api.GET("/status", func(req *core.Request, resp *core.Response) {
    resp.Status(200).JSONString(`{"status":"running"}`)
})

api.GET("/users/:id", func(req *core.Request, resp *core.Response) {
    resp.Status(200).String(req.ParamValue("id"))
})
```

## Reverse Proxy Example

```go
srv.SetProxy("api.example.com", core.DomainConfig{
    Backends: []core.BackendConfig{
        {Addr: "10.0.0.10:8080", Weight: 1},
        {Addr: "10.0.0.11:8080", Weight: 1},
    },
    LoadBalancer: core.LBRoundRobin,
    HealthCheck: core.HealthCheckConfig{
        Enabled:  true,
        Path:     "/health",
        Interval: 10 * time.Second,
        Timeout:  3 * time.Second,
    },
})
```

## Proxy Cache Example

```go
srv.SetProxyCache(core.ProxyCacheConfig{
    MaxEntrySize:   4 << 20,
    MaxTotalBytes:  256 << 20,
    DefaultMaxAge:  5 * time.Minute,
    CompressLevel:  6,
    CompressMinLen: 512,
    Rules: []core.CacheRule{
        {PathPrefix: "/static/", MaxAge: time.Hour},
        {PathPrefix: "/api/", MaxAge: 30 * time.Second, StatusOnly: []int{200}},
    },
})
```

## ACME Example

```go
srv := core.New(core.Config{
    Addr:          ":443",
    DefaultDomain: "example.com",
    ACME: &core.ACMEConfig{
        Email:   "admin@example.com",
        Domains: []string{"example.com", "www.example.com"},
    },
})

log.Fatal(srv.ListenAndServeTLS())
```

## Streaming and Files

```go
srv.Router.GET("/download", func(req *core.Request, resp *core.Response) {
    resp.SendFile(
        "./build/app.zip",
        core.WithAttachment("app.zip"),
        core.WithRateLimit(100),
    )
})
```

## Status

ALOS HTTP is an actively developed framework with a strong focus on performance-sensitive serving, proxying, and low-level protocol control. API surface may continue to evolve while the project is being expanded.

