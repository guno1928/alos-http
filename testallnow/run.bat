@echo off
setlocal enabledelayedexpansion

echo ============================================================
echo   ALOS HTTP Framework - Comprehensive Test Suite (360 tests)
echo ============================================================
echo.

set IMAGE_NAME=alos-test-suite
set CONTAINER_NAME=alos-test-run

echo [1/4] Building Docker image...
cd /d "%~dp0.."
docker build -f testallnow/Dockerfile -t %IMAGE_NAME% . 2>&1
if errorlevel 1 (
    echo.
    echo BUILD FAILED. Check errors above.
    exit /b 1
)
cd /d "%~dp0"
echo Build complete.
echo.

echo [2/4] Removing any previous test container...
docker rm -f %CONTAINER_NAME% >nul 2>&1

echo [3/4] Running 360 tests in container...
echo     (requires seccomp=unconfined for io_uring)
echo.
docker run ^
    --name %CONTAINER_NAME% ^
    --security-opt seccomp=unconfined ^
    --ulimit memlock=-1:-1 ^
    %IMAGE_NAME%

set TEST_EXIT=%errorlevel%

echo.
echo [4/4] Extracting results...
docker cp %CONTAINER_NAME%:/app/results.json results.json >nul 2>&1
docker cp %CONTAINER_NAME%:/app/summary.txt summary.txt >nul 2>&1

if exist results.json (
    echo   results.json written
) else (
    echo   results.json not found
)
if exist summary.txt (
    echo   summary.txt written
    echo.
    echo === SUMMARY ===
    type summary.txt
) else (
    echo   summary.txt not found
)

echo.
echo Cleaning up container...
docker rm -f %CONTAINER_NAME% >nul 2>&1

echo.
if %TEST_EXIT% equ 0 (
    echo ALL 360 TESTS PASSED
) else (
    echo SOME TESTS FAILED (exit code %TEST_EXIT%)
)

pause
exit /b %TEST_EXIT%
