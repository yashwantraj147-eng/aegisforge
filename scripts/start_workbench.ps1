# ==============================================================================
# AegisForge Turnkey Local Deployment Launcher (PowerShell)
# Starts Backend API (:8000), React Dashboard (:5173), and MiniProto Target (:5000)
# ==============================================================================

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "    AegisForge Purple-Team Cyber Range & Vulnerability Workbench      " -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Start MiniProto Sandbox Target
Write-Host "[1/3] Starting MiniProto sandbox target on 127.0.0.1:5000..." -ForegroundColor Green
$miniProtoProc = Start-Process python -ArgumentList "sandbox/vulnerable_targets/mini_proto_server.py" -PassThru -WindowStyle Hidden

# 2. Start FastAPI Backend Hub
Write-Host "[2/3] Starting FastAPI backend on http://127.0.0.1:8000..." -ForegroundColor Green
$backendProc = Start-Process python -ArgumentList "-m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000" -PassThru -WindowStyle Hidden

# 3. Start React Frontend Dashboard
Write-Host "[3/3] Starting React frontend on http://localhost:5173..." -ForegroundColor Green
$frontendProc = Start-Process npm -ArgumentList "run dev" -WorkingDirectory "frontend" -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 3

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "AegisForge is running!" -ForegroundColor Yellow
Write-Host "  * Web Dashboard:       http://localhost:5173" -ForegroundColor Green
Write-Host "  * Swagger API Docs:    http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host "  * ReDoc Specification: http://127.0.0.1:8000/redoc" -ForegroundColor Green
Write-Host "  * Prometheus Metrics:  http://127.0.0.1:8000/metrics" -ForegroundColor Green
Write-Host "  * Process IDs:         MiniProto: $($miniProtoProc.Id) | Backend: $($backendProc.Id) | Frontend: $($frontendProc.Id)" -ForegroundColor DarkGray
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "Press Ctrl+C or close this window to exit."
