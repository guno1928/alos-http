#!/usr/bin/env sh
set -eu

TESTS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$TESTS_DIR/.." && pwd)
RUN_RACE=${ALOS_RUN_RACE:-1}
RUN_MEMORY=${ALOS_RUN_MEMORY:-1}
RUN_PROTOCOLS=${ALOS_RUN_PROTOCOLS:-auto}

cd "$REPO_DIR"

echo "[1/6] Correctness and package tests"
go test ./... -count=1 -shuffle=on

echo "[2/6] Static analysis"
go vet ./core ./tests/...

echo "[3/6] Linux amd64 backend build"
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/alos-http-tests.XXXXXX")
trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c ./core -o "$BUILD_DIR/core-linux-amd64.test"

echo "[4/6] Race detection"
if [ "$RUN_RACE" = "1" ]; then
    go test -race ./core ./tests/... -count=1
else
    echo "Race detection skipped by ALOS_RUN_RACE=$RUN_RACE"
fi

echo "[5/6] Allocation benchmarks"
if [ "$RUN_MEMORY" = "1" ]; then
    go test ./tests/memory -run '^$' -bench . -benchmem -count=5
else
    echo "Memory benchmarks skipped by ALOS_RUN_MEMORY=$RUN_MEMORY"
fi

echo "[6/6] Live plain HTTP, TLS H1, H2, H3, and WebSocket tests"
if [ "$RUN_PROTOCOLS" = "0" ]; then
    echo "Live protocol tests skipped by ALOS_RUN_PROTOCOLS=0"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    "$TESTS_DIR/integration/runall.sh"
elif [ "$RUN_PROTOCOLS" = "1" ]; then
    echo "Docker is required because ALOS_RUN_PROTOCOLS=1" >&2
    exit 1
else
    echo "Docker is unavailable; live protocol tests skipped"
fi

echo "All available ALOS HTTP test stages passed"
