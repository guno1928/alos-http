#!/usr/bin/env sh
set -eu

INTEGRATION_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$INTEGRATION_DIR/../.." && pwd)
IMAGE_NAME=${ALOS_TEST_IMAGE:-alos-http-all-protocol-tests}

cd "$REPO_DIR"
docker run --rm --security-opt seccomp=unconfined --ulimit memlock=-1:-1 -v "$REPO_DIR:/work" -w /work golang:1.26-trixie sh -c "go test ./... -count=1 && go test -race ./core ./tests/... -count=1"
docker build -f testallnow/Dockerfile.allproto -t "$IMAGE_NAME" .
docker run --rm --security-opt seccomp=unconfined --ulimit memlock=-1:-1 "$IMAGE_NAME"
