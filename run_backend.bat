@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Aegis AI Firewall - Backend (Port 8000)
color 0A

set "SCRIPT_DIR=%~dp0"
if defined AEGIS_PYTHON_EXE (
    set "PYTHON_EXE=%AEGIS_PYTHON_EXE%"
) else (
    set "PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe"
    if not exist "%PYTHON_EXE%" set "PYTHON_EXE=%SCRIPT_DIR%.venv312\Scripts\python.exe"
)
if not exist "%PYTHON_EXE%" (
    echo [ERROR] Project Python environment is missing. Run start.bat first.
    pause
    exit /b 1
)

if not defined API_KEY (
    set "KEY_FILE=%TEMP%\aegis-dev-key-%RANDOM%-%RANDOM%.txt"
    "%PYTHON_EXE%" -c "import secrets; print(secrets.token_hex(32))" > "!KEY_FILE!"
    if errorlevel 1 (
        echo [ERROR] Could not generate the local API key.
        pause
        exit /b 1
    )
    set /p "GENERATED_KEY=" < "!KEY_FILE!"
    del /q "!KEY_FILE!" >nul 2>nul
    set "API_KEY=aegis_dev_!GENERATED_KEY!"
)

if not defined DASHBOARD_USERNAME set "DASHBOARD_USERNAME=admin"
if not defined DASHBOARD_PASSWORD set "DASHBOARD_PASSWORD=admin123"
if not defined DATABASE_URL set "DATABASE_URL=sqlite+aiosqlite:///./aegis_dev.db"
if not defined CORS_ORIGINS set "CORS_ORIGINS=["http://localhost:3000","http://127.0.0.1:3000"]"
set "ENVIRONMENT=development"
set "COOKIE_SECURE=false"
set "ENABLE_API_AUTH=true"
set "ENABLE_RATE_LIMITING=true"
set "OUTPUT_SECURITY_MODE=FULL_BUFFER"
set "PYTHONPATH=%SCRIPT_DIR%backend"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

cd /d "%SCRIPT_DIR%backend"
echo ========================================================================
echo                 AEGIS AI FIREWALL - BACKEND API
echo ========================================================================
echo API: http://127.0.0.1:8000
echo Docs: http://127.0.0.1:8000/docs
echo.
"%PYTHON_EXE%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
if errorlevel 1 (
    echo.
    echo [ERROR] Backend exited with an error. Review the messages above.
    pause
)
endlocal
