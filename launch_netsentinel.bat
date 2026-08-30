@echo off
setlocal
cd /d "%~dp0"
set "NETSENTINEL_PORT=8100"

echo [NetSentinel] Running measured launch audit first...
python tools\launch_demo.py
if errorlevel 1 (
  echo [NetSentinel] Launch audit failed. Servers were not started.
  pause
  exit /b 1
)

echo [NetSentinel] Checking backend on http://localhost:8100 ...
curl.exe --silent --fail --max-time 2 http://localhost:8100/api/health >nul 2>&1
if errorlevel 1 (
  echo [NetSentinel] Starting backend on http://localhost:8100 ...
  start "NetSentinel Backend" cmd /k "cd /d ""%~dp0"" && set NETSENTINEL_PORT=8100 && python run.py"
  timeout /t 4 /nobreak >nul
) else (
  echo [NetSentinel] Backend already running; reusing it.
)

echo [NetSentinel] Checking dashboard on http://localhost:5174 ...
curl.exe --silent --fail --max-time 2 http://localhost:5174 >nul 2>&1
if errorlevel 1 (
  echo [NetSentinel] Starting dashboard on http://localhost:5174 ...
  start "NetSentinel Dashboard" cmd /k "cd /d ""%~dp0frontend"" && npm run dev -- --host 0.0.0.0 --port 5174"
  timeout /t 3 /nobreak >nul
) else (
  echo [NetSentinel] Dashboard already running; reusing it.
)

echo.
echo [NetSentinel] Ready. Open http://localhost:5174
echo [NetSentinel] Audit report: reports\launch\launch_report.json
echo [NetSentinel] Stop either server with Ctrl+C in its terminal.
start "" http://localhost:5174
endlocal
