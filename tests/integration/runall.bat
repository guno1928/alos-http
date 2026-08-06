@echo off
setlocal
set "INTEGRATION_DIR=%~dp0"
for %%I in ("%INTEGRATION_DIR%..\..") do set "REPO_DIR=%%~fI"
if not defined ALOS_TEST_IMAGE set "ALOS_TEST_IMAGE=alos-http-all-protocol-tests"
cd /d "%REPO_DIR%"
docker run --rm --security-opt seccomp=unconfined --ulimit memlock=-1:-1 -v "%REPO_DIR%:/work" -w /work golang:1.26-trixie sh -c "go test ./... -count=1 && go test -race ./core ./tests/... -count=1"
if errorlevel 1 exit /b 1
docker build -f testallnow/Dockerfile.allproto -t "%ALOS_TEST_IMAGE%" .
if errorlevel 1 exit /b 1
docker run --rm --security-opt seccomp=unconfined --ulimit memlock=-1:-1 "%ALOS_TEST_IMAGE%"
exit /b %errorlevel%
