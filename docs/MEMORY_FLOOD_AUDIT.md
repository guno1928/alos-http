# ALOS HTTP memory-flood audit

Date: 2026-08-01

## Executive finding

The 11+ GiB event is explained by multiplicative, pre-handler limits rather than a single leak. With the reported configuration, `MaxBodySize: 100 << 20` silently raised the effective connection read cap to roughly 100 MiB. `ProxyMode: true` meant `MaxConnsPerIP: 18` was enforced only after a request was parsed and was keyed from user-supplied forwarding headers. `MaxConcurrentReqs: 99000000` was effectively unlimited, `MinPrealloc: 50000` intentionally reserved a large floor, and no `MaxConns` limit existed. About 110 incomplete 100 MiB HTTP/1 uploads were therefore sufficient to account for 11 GiB before a handler or request limiter ran.

The implementation now keeps `MaxReadSize` independent from `MaxBodySize`, applies an 8192 default `MaxConns`, clamps preallocation to that ceiling, adds an aggregate body-memory budget, makes QUIC honor the same connection cap, bounds QUIC queues and default packet pools, and drops oversized backing arrays and stale string references when pooled objects are reset.

## Safe profile

This is the production profile used by `main.go`. Increase a limit only after calculating its aggregate memory effect.

```go
core.Config{
    ReadTimeout:             5 * time.Second,
    WriteTimeout:            5 * time.Second,
    IdleTimeout:             15 * time.Second,
    HandshakeTimeout:        5 * time.Second,
    MaxBodySize:             1 << 20,
    MaxReadSize:             2 << 20,
    MaxWriteSize:            4 << 20,
    MaxInFlightBodyBytes:    32 << 20,
    MaxHeaderSize:           8192,
    MaxHeaderCount:          64,
    MaxRequestsPerIP:        256,
    MaxConnsPerIP:           24,
    MaxConcurrentReqs:       2048,
    MaxConns:                8192,
    H2MaxConcurrentStreams:  64,
    QUICMaxData:             4 << 20,
    QUICMaxStreamData:       1 << 20,
    MinPrealloc:             1024,
}
```

Do not use `ProxyMode: true` on a directly Internet-facing socket. Use `TrustedProxies` with exact proxy CIDRs, or leave both settings off. A 100 MiB buffered-body allowance cannot simultaneously provide a low worst-case footprint unless the aggregate body budget is at least 100 MiB and admission is correspondingly strict; large uploads should ultimately use a streaming body API.

## 65-point audit

| # | Test or check | Finding / disposition |
|---:|---|---|
| 1 | Global TCP connection admission | The reported config had no `MaxConns`; zero now safely defaults to 8192 and `-1` is the explicit unlimited opt-out. |
| 2 | QUIC connection admission | QUIC formerly used only a separate 65,536 global constant; it now also reserves a server `MaxConns` slot. |
| 3 | Direct-client per-IP admission | Default socket-peer connection accounting works before request parsing. |
| 4 | Proxy-mode per-IP semantics | In proxy mode the limit is necessarily post-parse request accounting, so it cannot protect incomplete bodies. |
| 5 | Forwarded-IP trust | `ProxyMode` trusts every peer and permits rotating spoofed XFF identities; exact trusted proxy CIDRs are required. |
| 6 | Global handler concurrency | 99,000,000 was functionally disabled; the production profile uses 2048. |
| 7 | Pre-handler body concurrency | Handler concurrency was too late to protect parsers; aggregate `MaxInFlightBodyBytes` now gates H1/H2/H3 buffering. |
| 8 | Body limit versus read limit | A 100 MiB body limit silently raised every connection read cap; the two settings are now independent. |
| 9 | Default read-buffer ceiling | An omitted `MaxReadSize` remains the documented 2 MiB instead of inheriting `MaxBodySize`. |
| 10 | Unlimited read mode | `MaxReadSize: -1` remains explicit and documented as unsafe. |
| 11 | H1 declared body reservation | Content-Length bodies reserve aggregate capacity before their bytes are buffered. |
| 12 | H1 chunked body reservation | Chunked requests reserve the smaller of body and read ceilings before accumulation. |
| 13 | H2 aggregate body reservation | Every DATA append reserves from the shared server body budget. |
| 14 | H3 aggregate body reservation | QUIC request-stream receive growth uses the same shared body budget. |
| 15 | Body-budget release | H1 completion and H2/QUIC stream reset return reservations; unit tests verify reuse. |
| 16 | Plain HTTP incomplete upload | 256 declared 100 MiB uploads were rejected; RSS stayed about 8.9 MiB. |
| 17 | TLS HTTP incomplete upload | 256 declared 100 MiB uploads were rejected; RSS stayed about 14.3 MiB. |
| 18 | Content-Length integer overflow | Negative/overflowing lengths are rejected before allocation. |
| 19 | Chunk-framing overhead | Chunked framing is separately bounded and invalid framing closes the connection. |
| 20 | Header byte ceiling | HTTP/1 headers are capped at 8 KiB in the production profile. |
| 21 | Header count ceiling | The production profile adds a 64-header count cap. |
| 22 | HTTP/2 decoded header count | H2 rejects more than 128 decoded headers. |
| 23 | H2 continuation accumulation | Continuation blocks are capped and oversized blocks trigger GOAWAY. |
| 24 | HPACK table growth | Peer table size is clamped to 64 KiB and decoder state is reset on reuse. |
| 25 | QPACK decoded-block cache | Entry count and total bytes are bounded (1024 entries / 1 MiB). |
| 26 | QPACK response-prefix cache | The prefix cache is bounded to 512 entries. |
| 27 | Request pooled body retention | `Request.Reset` now discards bodies above 64 KiB instead of retaining peak arrays. |
| 28 | H2 stream body retention | `H2Stream.Reset` now discards oversized body and header buffers. |
| 29 | Response pooled body retention | Existing 64 KiB shrink policy was retained and header references are now cleared. |
| 30 | Header backing-array references | Request, response, and H2 stream reset now clears elements before truncating slices. |
| 31 | Route-param references | Reset clears used fixed-array params so large path strings cannot remain reachable. |
| 32 | Cookie references | Reset clears parsed cookie elements before reuse. |
| 33 | H2 shared header scratch | Oversized continuation/header slices are shrunk and string elements cleared. |
| 34 | Epoll read-buffer pool retention | The pool accepts at most 16 KiB buffers; larger read arrays are left for GC. |
| 35 | Epoll I/O pool retention | The generic epoll I/O pool is capped at 32 KiB entries. |
| 36 | Connection-local chunk decode buffer | Buffers above 32 KiB are dropped when an epoll connection is recycled. |
| 37 | Connection slab growth | Slabs grow in bounded batches and fully idle excess slabs are reclaimed. |
| 38 | Preallocation floor | The forced floor was reduced from 15,000 to 1,024; preallocation is now clamped to `MaxConns`, and the reported explicit 50,000 should not be used. |
| 39 | Prewarmed read buffers | Lowering the floor removes hundreds of MiB of avoidable page-faulted pool capacity. |
| 40 | Pending HTTP/1 writes | Epoll closes a slow client above the pending-write ceiling. |
| 41 | H2 stalled response bodies | Per-connection stalled response accounting closes above the pending-write ceiling. |
| 42 | H2 stream concurrency | The production profile advertises 64 rather than the previous 256 default. |
| 43 | H2 frame-size validation | Frames above the configured/spec limit are rejected before payload processing. |
| 44 | H2 reset flood | Reset rate is bounded per time window. |
| 45 | H2 control-frame flood | SETTINGS/PING/PRIORITY/WINDOW_UPDATE rates are bounded. |
| 46 | H2 oversized-body multiplex test | Before aggregate budgeting the test reached about 197 MiB; after budgeting it peaked about 75 MiB and recovered. |
| 47 | QUIC receive packet pool | Default pooled packet capacity dropped from 33,280 to 2,048 bytes. |
| 48 | QUIC send packet pool | Normal packets use 2 KiB pooled buffers; jumbo capacity is explicit and not retained in the default pool. |
| 49 | QUIC per-connection ingress queue | Queue depth dropped from 256 to 32, changing worst-case default queued storage from ~8.1 MiB to ~64 KiB per connection. |
| 50 | QUIC per-listener send queue | Queue depth dropped from 16,384 to 1,024; overload drops datagrams instead of retaining unbounded work. |
| 51 | QUIC handshake admission | The existing 8192 handshaking cap remains, now additionally constrained by server `MaxConns`. |
| 52 | QUIC tracked streams | Per-connection tracked streams remain capped. |
| 53 | QUIC concurrent request streams | Per-connection active request dispatch remains capped. |
| 54 | QUIC stream receive window | Internal receive allocation now matches the advertised default and honors `QUICMaxStreamData`. |
| 55 | QUIC connection-level flow control | Production config limits connection data to 4 MiB. |
| 56 | QUIC flood validation | 128 QUIC connections produced 100,732 successful requests in 6s with zero errors at ~34.7 MiB RSS. |
| 57 | H3 normal-load validation | 52,445 requests in 5s completed with zero errors at ~28 MiB RSS. |
| 58 | Plain HTTP/1 req/s validation | 512 offered connections produced ~9,931 req/s; per-IP admission refused excess sockets and RSS stayed below 18 MiB. |
| 59 | Plain h2c validation | 100,000/100,000 requests succeeded; RSS was about 21 MiB. |
| 60 | TLS HTTP/1 validation | 98,166 requests completed in 8s (~12,119 req/s); RSS was about 16.7 MiB. |
| 61 | TLS HTTP/2 validation | 30,000/30,000 requests succeeded at ~65-67k req/s after hardening. |
| 62 | Rate-limit identity map | Tracking is capped at 65,536 identities and fails closed when saturated. |
| 63 | Proxy/request logging allocations | Per-request proxy logging is off unless `ALOS_PROXY_LOG=1`; flood paths no longer format and serialize log lines by default. |
| 64 | Proxy cache memory | The configured proxy cache remains independently bounded (production main: 256 MiB); include it in the total RAM budget. |
| 65 | Post-flood health and OOM status | Docker tests used a 1 GiB cgroup; all protocol servers remained running and `OOMKilled=false`, and normal H2/H3 traffic succeeded after body floods. |

## Memory budget model

Treat limits as products, not independent knobs:

```text
baseline
+ active connections × connection state/base buffers
+ aggregate in-flight body budget (plus slice growth overhead)
+ pending writes and stalled responses
+ proxy/response cache ceilings
+ handler-owned memory
+ Go runtime and kernel socket buffers
```

`MaxBodySize` is a correctness limit for one request. `MaxInFlightBodyBytes` is the RAM-safety limit for all buffered requests. `MaxConns` bounds connection state. All three are required.

## Reproduction commands

The bounded incomplete-upload tool is available at `cmd/memflood`:

```bash
go run ./cmd/memflood -addr 127.0.0.1:8080 -conns 256 \
  -content-length 104857600 -send-bytes 4194304 -hold 8s

go run ./cmd/memflood -addr 127.0.0.1:8443 -tls -conns 256 \
  -content-length 104857600 -send-bytes 4194304 -hold 8s
```

Run it only against infrastructure you own or are explicitly authorized to test.
