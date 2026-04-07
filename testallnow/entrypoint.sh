#!/bin/sh
set -e

echo "=== Starting ALOS test server ==="
/app/server &
SERVER_PID=$!

echo "Waiting for server to be ready..."
for i in $(seq 1 60); do
    if [ -f /tmp/server-ready ]; then
        echo "Server ready after ${i}s"
        break
    fi
    sleep 1
done

if [ ! -f /tmp/server-ready ]; then
    echo "FATAL: Server did not start within 60 seconds"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo ""
echo "=== Running 360 tests ==="
echo ""
/app/runner
TEST_EXIT=$?

echo ""
echo "=== Stopping server ==="
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

exit $TEST_EXIT
