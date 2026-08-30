[CmdletBinding()]
param(
    [switch]$OpenBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

$python = (Get-Command python.exe -ErrorAction Stop).Path
$npm = (Get-Command npm.cmd -ErrorAction Stop).Path

function Get-Json([string]$url) {
    try {
        return Invoke-RestMethod -Uri $url -Method Get -TimeoutSec 5
    }
    catch {
        return $null
    }
}

function Wait-Http([string]$label, [string]$url, [int]$attempts = 30) {
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        if (Get-Json $url) {
            Write-Host ("[PASS] {0} ready: {1}" -f $label, $url) -ForegroundColor Green
            return
        }
        Start-Sleep -Seconds 1
    }
    throw ("{0} did not become ready: {1}" -f $label, $url)
}

function Start-IfMissing([string]$label, [string]$url, [string]$file, [string[]]$arguments, [string]$workingDirectory) {
    if (Get-Json $url) {
        Write-Host ("[PASS] {0} already running" -f $label) -ForegroundColor Green
        return
    }
    Write-Host ("[....] starting {0}" -f $label) -ForegroundColor Yellow
    Start-Process -FilePath $file -ArgumentList $arguments -WorkingDirectory $workingDirectory -WindowStyle Hidden
    Wait-Http $label $url
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " NetSentinel manual launch | measured evidence first" -ForegroundColor Cyan
Write-Host " Backend 8100 | Dashboard 5174 | Plus console 8200" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

Write-Host "[1/5] Running the measured audit..." -ForegroundColor Cyan
& $python "tools\launch_demo.py"
if ($LASTEXITCODE -ne 0) {
    throw "Measured audit failed; services were not started."
}

Write-Host "[2/5] Starting or reusing the three local services..." -ForegroundColor Cyan
$env:NETSENTINEL_PORT = "8100"
Start-IfMissing "NetSentinel backend" "http://127.0.0.1:8100/api/health" $python @("run.py") $root

Start-IfMissing "NetSentinel dashboard" "http://127.0.0.1:5174" $npm @("run", "dev", "--", "--host", "0.0.0.0", "--port", "5174") (Join-Path $root "frontend")

$env:NETSENTINEL_BACKEND_URL = "http://127.0.0.1:8100"
Start-IfMissing "NetSentinel Plus" "http://127.0.0.1:8200/api/addon/status" $python @("-m", "uvicorn", "addons.netsentinel_plus.app:app", "--host", "127.0.0.1", "--port", "8200") $root

Write-Host "[3/5] Printing the current measured scorecard..." -ForegroundColor Cyan
& $python "addons\netsentinel_plus\launch_summary.py"
if ($LASTEXITCODE -ne 0) {
    throw "Scorecard rendering failed."
}

$reportPath = Join-Path $root "reports\launch\launch_report.json"
$report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
Write-Host ("[INFO] calibration_error={0} (advisory metric; not a launch failure)" -f $report.safe_pipeline.calibration_error) -ForegroundColor DarkYellow

Write-Host "[4/5] Running strict backend and dashboard verification..." -ForegroundColor Cyan
& $python "tools\verify_final.py"
if ($LASTEXITCODE -ne 0) {
    throw "Strict verification failed. Review the PASS/FAIL table above."
}

Write-Host "[5/5] Checking the Plus API and final health snapshot..." -ForegroundColor Cyan
$plusHealth = Get-Json "http://127.0.0.1:8200/api/addon/health"
if (-not $plusHealth -or $plusHealth.status -ne "online" -or $plusHealth.backend.status -ne "online") {
    throw "Plus API health is not online."
}

$backendHealth = Get-Json "http://127.0.0.1:8100/api/health"
[PSCustomObject]@{
    backend = $backendHealth.status
    read_only = $backendHealth.read_only_mode
    payload_decrypted = $backendHealth.payload_decrypted
    plus = $plusHealth.status
    providers_configured = $plusHealth.providers.active_provider_count
} | Format-List

Write-Host "[PASS] All services and safety checks are ready." -ForegroundColor Green
Write-Host "Dashboard: http://127.0.0.1:5174"
Write-Host "API docs:  http://127.0.0.1:8100/docs"
Write-Host "Plus:      http://127.0.0.1:8200"
Write-Host "Report:    reports\launch\launch_report.json"

if ($OpenBrowser) {
    Start-Process "http://127.0.0.1:5174"
    Start-Process "http://127.0.0.1:8200"
}
