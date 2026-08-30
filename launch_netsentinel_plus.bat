@echo off
setlocal
cd /d "%~dp0"
set "NETSENTINEL_BACKEND_URL=http://127.0.0.1:8100"
set "NETSENTINEL_PLUS_PORT=8200"
echo.
echo ============================================================
echo   NetSentinel Plus - additive analyst sidecar
echo   Existing app: 8100   Sidecar: 8200
echo   Metadata only - no payloads, downloads, execution, or blocking
echo ============================================================
echo.
python -m uvicorn addons.netsentinel_plus.app:app --host 127.0.0.1 --port %NETSENTINEL_PLUS_PORT%
endlocal
