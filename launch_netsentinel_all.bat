@echo off
setlocal
cd /d "%~dp0"

echo ============================================================
echo   NetSentinel complete local launch
echo   Original app: 8100 / 5174   Additive console: 8200
echo ============================================================
echo.

call "%~dp0launch_netsentinel.bat"
if errorlevel 1 (
  echo [NetSentinel] Original application launch failed.
  exit /b 1
)

echo [NetSentinel Plus] Checking additive console on http://127.0.0.1:8200 ...
curl.exe --silent --fail --max-time 2 http://127.0.0.1:8200/api/addon/status >nul 2>&1
if errorlevel 1 (
  echo [NetSentinel Plus] Starting additive console on http://127.0.0.1:8200 ...
  start "NetSentinel Plus" cmd /k "cd /d ""%~dp0"" && call launch_netsentinel_plus.bat"
  timeout /t 3 /nobreak >nul
) else (
  echo [NetSentinel Plus] Additive console already running; reusing it.
)

echo.
echo [NetSentinel] Original dashboard: http://127.0.0.1:5174
echo [NetSentinel Plus] Analyst console: http://127.0.0.1:8200
start "" http://127.0.0.1:8200
endlocal
