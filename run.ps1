Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "      Unified RAG Verifier - Starting System" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

Set-Location $PSScriptRoot

$pythonExe = "C:\Users\Admin\AppData\Local\Programs\Python\Python313\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "py"
    $pyArgs = @("-3.13", "main.py")
} else {
    $pyArgs = @("main.py")
}

Write-Host "Starting Web Application on http://127.0.0.1:8000 ..." -ForegroundColor Green
Start-Process "http://127.0.0.1:8000"

& $pythonExe $pyArgs
