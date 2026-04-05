# ALOS HTTP - go web framework with io_uring support

> **Work in progress.** ALOS HTTP is still under active development and bugs may be present. If you find a bug or rough edge, please open a GitHub issue.
>
> **Join the Discord:** [https://alos.gg/discord](https://alos.gg/discord)

Based on the project's current published benchmark suite, ALOS HTTP is the fastest web framework currently available right now.

ALOS HTTP is a Linux-first Go web framework, Go HTTP server, and application server built around a custom networking stack with full `io_uring` support on supported kernels.

It includes first-class TLS handling, HTTP/1.1 and HTTP/2 support, reverse proxying, load balancing, rate limiting, streaming, ACME automation, and a high-performance radix router.

It is designed for people who want more control than a thin net/http wrapper, while still getting an ergonomic handler API.

If you are looking for a high-performance Go web server or Go reverse proxy for Linux, ALOS HTTP is focused on the Linux fast path and full `io_uring` support rather than maintaining cross-platform behavior.

Official repository:
https://github.com/guno1928/alos-http

## Why ALOS HTTP

ALOS HTTP focuses on a different part of the stack than most Go web frameworks.

- Custom server core instead of delegating everything to net/http.
- Built-in HTTP/1.1 and HTTP/2 serving.
- Linux-first runtime with full `io_uring` support on supported kernels.
- Built-in TLS flow with ACME support for HTTPS and TLS automation.
- High-performance radix router with params, wildcards, groups, and middleware.
- Reverse proxy with load balancing, health checks, and cache support.
- Response streaming and file sending helpers.
- Middleware for recovery, logging, CORS, compression, auth, timeouts, security headers, and more.
- Rate limiting primitives and rule-driven limiting.

### Full io_uring Coverage

On Linux amd64 with a supported kernel, the following paths run entirely through `io_uring`:

- **TCP accept** — all inbound connections are accepted via `io_uring` submission queues.
- **TLS record I/O** — TLS read and write operations (both plaintext and encrypted record framing) are dispatched through `io_uring`.
- **Plain HTTP I/O** — non-TLS HTTP/1.1 and HTTP/2 read/write paths use `io_uring` directly.
- **Reverse proxy egress** — outbound connections to backends (dial, send, receive) go through dedicated proxy `io_uring` rings.
- **Sendfile** — static file serving uses `io_uring`-backed splice/sendfile operations where the kernel supports it.
- **HTTP/2 framing** — HTTP/2 frame reads and writes on both the ingress and shared-bridge proxy paths use `io_uring`.

In short, every network I/O syscall in the hot path (accept, read, write, connect, sendfile) is submitted through `io_uring` rather than the traditional `epoll` + blocking-syscall model.

Search-friendly summary:

- Go web framework
- Go HTTP server
- Linux web server
- `io_uring` framework
- reverse proxy and load balancer
- HTTP/1.1 and HTTP/2 server
- TLS 1.3 and ACME automation

## Platform Support

ALOS HTTP now targets Linux only.

- Linux is the supported production platform.
- The framework is optimized around `io_uring`, which is a Linux kernel feature.
- If you are developing on Windows or macOS, treat those environments as places to edit code, not as the target runtime.
- For the full fast path, use a recent Linux kernel with `io_uring` features enabled.

## What is io_uring?

`io_uring` is a newer Linux way for programs to ask the kernel to do network and file I/O work with less back-and-forth.

Very simple version:

- old way: app asks the kernel to do one thing, waits, then asks again
- `io_uring` way: app puts many I/O jobs into a shared ring, and the kernel finishes them and reports back with less overhead

Why that matters for ALOS HTTP:

- less syscall overhead
- better batching
- lower latency on hot paths
- more efficient handling for lots of active connections

In practice that means ALOS HTTP can lean harder into Linux-native networking paths for plain HTTP, TLS, and HTTP/2.

## Benchmarks

If you want to see full benchmarks, go to:

https://alos.gg/aloshttpdocs/benchmarks

There are two benchmark views worth looking at:

- the published side-by-side framework comparison page

Published HTTPS HTTP/1.1 framework comparison:

| Framework | 500-conn throughput | 30-conn avg latency | 500-conn transfer/sec |
| --- | --- | --- | --- |
| ALOS HTTP | `240,707 req/s` | `88.11us` | `31.91 MB/s` |
| Actix Web (RUST framework) | `165,165 req/s` | `272.33us` | `19.37 MB/s` |
| Fiber v3 | `144,342 req/s` | `265.23us` | `16.93 MB/s` |
| Gin | `113,220 req/s` | `440.28us` | `14.90 MB/s` |
| Iris | `111,138 req/s` | `480.58us` | `14.73 MB/s` |
| Echo | `108,755 req/s` | `448.37us` | `12.86 MB/s` |

Published throughput across connection levels:

| Framework | 30 conn | 500 conn | 5,000 conn | 8,000 conn |
| --- | --- | --- | --- | --- |
| ALOS HTTP | `165,573` | `240,707` | `220,624` | `194,726` |
| Actix Web (RUST framework) | `156,699` | `165,165` | `157,741` | `111,811` |
| Fiber v3 | `133,460` | `144,342` | `124,626` | `109,951` |
| Gin | `104,843` | `113,220` | `97,740` | `87,691` |
| Iris | `106,822` | `111,138` | `81,381` | `80,326` |
| Echo | `109,761` | `108,755` | `81,854` | `39,198` |

Published comparison test environment:

- OS: Ubuntu 24
- CPU: Xeon E3-1270
- Threads: 8

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

