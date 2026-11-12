@echo off
cd /d "%~dp0"
echo ========================================================
echo       Unified RAG Verifier - Starting System
echo ========================================================

set PYTHON_EXE=C:\Users\Admin\AppData\Local\Programs\Python\Python313\python.exe

if not exist "%PYTHON_EXE%" (
    set PYTHON_EXE=py -3.13
)

echo Starting Web Application on http://127.0.0.1:8000 ...
start http://127.0.0.1:8000
%PYTHON_EXE% main.py
pause
