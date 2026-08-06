# ALOS HTTP test suite

The `tests` tree is the categorized entry point for framework verification. It adds hundreds of distinct table-driven outcomes while also running every existing package test in the repository.

## Categories

| Folder | Coverage |
|---|---|
| `routing` | Static, parameter, catch-all, grouped, middleware, method, 404, and 405 routing |
| `correctness` | HTTP status text, JSON encoding, host validation, query decoding, object reset, response types, and header injection protection |
| `protocols` | HTTP/1 parsing and limits, HTTP/2 frame round trips and malformed input, TLS 1.3 ALPN, suites, key derivation, and certificates |
| `websocket` | RFC 6455 handshake validation, correction responses, connection tokens, keys, and versions |
| `proxy` | Reverse-proxy domain registration, replacement, normalized lookup, removal, and high-cardinality lifecycle |
| `concurrency` | Concurrent route lookup and independent request processing; the race stage covers the framework and categorized suites |
| `memory` | High-cardinality behavior, retained-buffer release, allocation budgets, heap recovery, and `-benchmem` benchmarks |
| `integration` | Live plain HTTP, HTTPS over H1 and H2, HTTP/3 over QUIC, and plain/TLS WebSocket traffic in Linux |

## Run everything

Windows:

```bat
tests\runall.bat
```

Linux and macOS:

```sh
./tests/runall.sh
```

The runner executes package correctness tests, focused static analysis, a Linux amd64 backend build, the race detector, five allocation benchmark samples, and the live all-protocol Docker suite. The Docker stage first executes all repository tests and the race detector natively on Linux so build-tagged epoll and io_uring coverage is not reduced to a cross-build. When Docker is not running, the live suite is reported as skipped so local unit work remains usable.

Set `ALOS_RUN_PROTOCOLS=1` to require the Docker protocol suite and fail if Docker is unavailable. Set it to `0` to skip that stage deliberately. `ALOS_RUN_RACE=0` and `ALOS_RUN_MEMORY=0` disable the slower race and benchmark stages.

The live integration stage reuses the maintained `testallnow` servers and clients. That stage provides real socket coverage for plain HTTP, TLS H1, H2, H3, and WebSockets; the portable proxy suite covers the proxy configuration lifecycle. The repository's extended Linux `fulltest.sh` remains the load, RSS, race, and live reverse-proxy stress harness for dedicated benchmark hosts.

## Memory results

The benchmark stage reports bytes and allocations per operation five times. Treat these numbers as measurements tied to the current machine and Go toolchain. The correctness checks ensure high-cardinality routing remains available and that oversized reusable request buffers are released at lifecycle boundaries; they do not substitute a global cardinality cap for memory optimization.
