# syntax=docker/dockerfile:1

# Build context must be the alos-http root directory:
#   docker build -f testallnow/Dockerfile -t alos-test-suite .

# ── Stage 1: Build server and runner ──
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

# Copy entire framework (needed for replace directive)
WORKDIR /src/alos-http
COPY go.mod go.sum ./
COPY core/ core/

# Copy test suite
COPY testallnow/go.mod testallnow/go.sum* testallnow/
COPY testallnow/server/ testallnow/server/
COPY testallnow/runner/ testallnow/runner/

WORKDIR /src/alos-http/testallnow

# Tidy and download deps
RUN go mod tidy && go mod download

# Build server and runner
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/server ./server/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/runner ./runner/

# ── Stage 2: Runtime (alpine for io_uring support) ──
FROM alpine:3.21

RUN apk add --no-cache bash

WORKDIR /app

# Copy binaries
COPY --from=builder /out/server /app/server
COPY --from=builder /out/runner /app/runner

# Copy static test files
COPY testallnow/static/ /app/static/

# Copy entrypoint
COPY testallnow/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080 8443

ENTRYPOINT ["/app/entrypoint.sh"]
