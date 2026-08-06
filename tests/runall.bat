@echo off
setlocal
set "TESTS_DIR=%~dp0"
for %%I in ("%TESTS_DIR%..") do set "REPO_DIR=%%~fI"
if not defined ALOS_RUN_RACE set "ALOS_RUN_RACE=1"
if not defined ALOS_RUN_MEMORY set "ALOS_RUN_MEMORY=1"
if not defined ALOS_RUN_PROTOCOLS set "ALOS_RUN_PROTOCOLS=auto"
cd /d "%REPO_DIR%"

echo [1/6] Correctness and package tests
go test ./... -count=1 -shuffle=on
if errorlevel 1 exit /b 1

echo [2/6] Static analysis
go vet ./core ./tests/...
if errorlevel 1 exit /b 1

echo [3/6] Linux amd64 backend build
set "LINUX_TEST_BINARY=%TEMP%\alos-http-core-linux-amd64.test"
set "OLD_GOOS=%GOOS%"
set "OLD_GOARCH=%GOARCH%"
set "OLD_CGO_ENABLED=%CGO_ENABLED%"
set "GOOS=linux"
set "GOARCH=amd64"
set "CGO_ENABLED=0"
go test -c ./core -o "%LINUX_TEST_BINARY%"
set "GOOS=%OLD_GOOS%"
set "GOARCH=%OLD_GOARCH%"
set "CGO_ENABLED=%OLD_CGO_ENABLED%"
if errorlevel 1 exit /b 1

echo [4/6] Race detection
if "%ALOS_RUN_RACE%"=="1" (
    go test -race ./core ./tests/... -count=1
    if errorlevel 1 exit /b 1
) else (
    echo Race detection skipped by ALOS_RUN_RACE=%ALOS_RUN_RACE%
)

echo [5/6] Allocation benchmarks
if "%ALOS_RUN_MEMORY%"=="1" (
    go test ./tests/memory -run "^$" -bench . -benchmem -count=5
    if errorlevel 1 exit /b 1
) else (
    echo Memory benchmarks skipped by ALOS_RUN_MEMORY=%ALOS_RUN_MEMORY%
)

echo [6/6] Live plain HTTP, TLS H1, H2, H3, and WebSocket tests
if "%ALOS_RUN_PROTOCOLS%"=="0" (
    echo Live protocol tests skipped by ALOS_RUN_PROTOCOLS=0
    goto passed
)
docker info >nul 2>&1
if not errorlevel 1 (
    call "%TESTS_DIR%integration\runall.bat"
    if errorlevel 1 exit /b 1
    goto passed
)
if "%ALOS_RUN_PROTOCOLS%"=="1" (
    echo Docker is required because ALOS_RUN_PROTOCOLS=1
    exit /b 1
)
echo Docker is unavailable; live protocol tests skipped

:passed
echo All available ALOS HTTP test stages passed
exit /b 0
