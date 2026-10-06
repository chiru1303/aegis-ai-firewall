@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Aegis AI Firewall - Local Launcher
color 0B

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo ========================================================================
echo                    AEGIS AI FIREWALL - LOCAL START
echo ========================================================================
echo.

rem Use the checked-in runtime lock with Python 3.11 or newer.
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "PYTHON_EXE=!VENV_DIR!\Scripts\python.exe"
if not exist "!PYTHON_EXE!" (
    where py >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python 3.11+ and the Windows Python launcher are required.
        echo Install Python 3.11 or newer, then run start.bat again.
        goto :fail
    )
    py -3.11 --version >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python 3.11 was not found. Install Python 3.11 or newer.
        goto :fail
    )
    echo [*] Creating the project Python environment...
    py -3.11 -m venv "!VENV_DIR!"
    if errorlevel 1 (
        echo [ERROR] Could not create .venv.
        goto :fail
    )
)

"!PYTHON_EXE!" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] The project environment requires Python 3.11 or newer.
    echo Install Python 3.11 and run start.bat again.
    goto :fail
)

where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js 22+ is required. Install Node.js and run start.bat again.
    goto :fail
)
node -e "const [major,minor]=process.versions.node.split('.').map(Number); process.exit((major===20&&minor>=19)||(major>=22&&(major>22||minor>=12))?0:1)" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Vite requires Node.js 20.19+ or 22.12+.
    goto :fail
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] npm was not found. Repair or reinstall Node.js 22+.
    goto :fail
)

if not exist "%SCRIPT_DIR%backend\requirements.lock" (
    echo [ERROR] backend\requirements.lock is missing. Run start.bat from the project folder.
    goto :fail
)
if not exist "%SCRIPT_DIR%frontend\package-lock.json" (
    echo [ERROR] frontend\package-lock.json is missing. Run start.bat from the project folder.
    goto :fail
)

"!PYTHON_EXE!" -c "import fastapi, uvicorn" >nul 2>nul
if errorlevel 1 (
    echo [*] Installing backend dependencies. This may take a few minutes...
    "!PYTHON_EXE!" -m pip install --use-feature=truststore -r "%SCRIPT_DIR%backend\requirements.lock"
    if errorlevel 1 (
        echo [ERROR] Backend dependency installation failed.
        goto :fail
    )
)

if not exist "%SCRIPT_DIR%frontend\node_modules\vite\bin\vite.js" (
    echo [*] Installing frontend dependencies. This may take a few minutes...
    pushd "%SCRIPT_DIR%frontend"
    call npm ci
    set "NPM_RESULT=!errorlevel!"
    popd
    if not "!NPM_RESULT!"=="0" (
        echo [ERROR] Frontend dependency installation failed.
        goto :fail
    )
)

rem Keep the local key stable so restarting the launcher does not invalidate login.
set "KEY_GENERATED=0"
if not defined API_KEY (
    set "KEY_GENERATED=1"
    set "KEY_STORE_FILE=%SCRIPT_DIR%.aegis-local-api-key"
    if exist "!KEY_STORE_FILE!" set /p "API_KEY=" < "!KEY_STORE_FILE!"
    if not defined API_KEY (
        set "KEY_TEMP_FILE=%TEMP%\aegis-dev-key-%RANDOM%-%RANDOM%.txt"
        "!PYTHON_EXE!" -c "import secrets; print(secrets.token_hex(32))" > "!KEY_TEMP_FILE!"
        if errorlevel 1 (
            echo [ERROR] Could not generate the local API key.
            goto :fail
        )
        set /p "GENERATED_KEY=" < "!KEY_TEMP_FILE!"
        del /q "!KEY_TEMP_FILE!" >nul 2>nul
        if not defined GENERATED_KEY (
            echo [ERROR] Could not read the generated local API key.
            goto :fail
        )
        set "API_KEY=aegis_dev_!GENERATED_KEY!"
        > "!KEY_STORE_FILE!" echo !API_KEY!
    )
)
if not defined API_KEY (
    echo [ERROR] Could not create the local API key.
    goto :fail
)
if not defined DASHBOARD_USERNAME set "DASHBOARD_USERNAME=admin"
if not defined DASHBOARD_PASSWORD set "DASHBOARD_PASSWORD=admin123"

set "ENVIRONMENT=development"
set "COOKIE_SECURE=false"
set "DEBUG=false"
set "ENABLE_API_AUTH=true"
set "ENABLE_RATE_LIMITING=true"
set "OUTPUT_SECURITY_MODE=FULL_BUFFER"
set "DATABASE_URL=sqlite+aiosqlite:///./aegis_dev.db"

rem Reuse this app if it is already running; otherwise choose a free Vite port.
set "FRONTEND_PORT="
set "FRONTEND_ALREADY_RUNNING=0"
for /L %%P in (3000,1,3010) do (
    if not defined FRONTEND_PORT (
        curl.exe -fsS --connect-timeout 1 http://127.0.0.1:%%P/ 2>nul | findstr /I /C:"Aegis AI Firewall Dashboard" >nul 2>nul
        if not errorlevel 1 (
            set "FRONTEND_PORT=%%P"
            set "FRONTEND_ALREADY_RUNNING=1"
        )
    )
)
if not defined FRONTEND_PORT (
    for /f %%P in ('powershell -NoProfile -Command "foreach ($port in 3000..3010) { if (-not (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue)) { $port; break } }"') do set "FRONTEND_PORT=%%P"
)
if not defined FRONTEND_PORT (
    echo [ERROR] No free frontend port was found between 3000 and 3010.
    goto :fail
)
set "CORS_ORIGINS=["http://localhost:!FRONTEND_PORT!","http://127.0.0.1:!FRONTEND_PORT!"]"
set "AEGIS_FRONTEND_PORT=!FRONTEND_PORT!"
set "AEGIS_PYTHON_EXE=!PYTHON_EXE!"
set "PYTHONPATH=%SCRIPT_DIR%backend"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

rem Reuse healthy services, but never kill an unrelated process occupying a port.
curl.exe -s --connect-timeout 1 http://127.0.0.1:8000/api/v1/health >nul 2>nul
if not errorlevel 1 (
    echo [OK] Backend is already responding on port 8000.
) else (
    powershell -NoProfile -Command "if (Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>nul
    if not errorlevel 1 (
        echo [ERROR] Port 8000 is occupied by another process.
        echo Close that process or configure Aegis to use another port.
        goto :fail
    )
    echo [*] Starting backend on http://127.0.0.1:8000 ...
    start "Aegis Backend - 8000" cmd /k ""%SCRIPT_DIR%run_backend.bat""
)

if "!FRONTEND_ALREADY_RUNNING!"=="1" (
    echo [OK] Aegis dashboard is already responding on port !FRONTEND_PORT!.
) else (
    echo [*] Starting frontend on http://localhost:!FRONTEND_PORT! ...
    start "Aegis Dashboard - !FRONTEND_PORT!" cmd /k ""%SCRIPT_DIR%run_frontend.bat""
)

echo.
echo [*] Waiting for the dashboard and API to become ready...
set "BACKEND_READY=0"
set "FRONTEND_READY=!FRONTEND_ALREADY_RUNNING!"
for /L %%I in (1,1,45) do (
    if "!BACKEND_READY!"=="0" (
        curl.exe -s --connect-timeout 1 http://127.0.0.1:8000/api/v1/health >nul 2>nul
        if not errorlevel 1 set "BACKEND_READY=1"
    )
    if "!FRONTEND_READY!"=="0" (
        curl.exe -fsS --connect-timeout 1 http://127.0.0.1:!FRONTEND_PORT!/ 2>nul | findstr /I /C:"Aegis AI Firewall Dashboard" >nul 2>nul
        if not errorlevel 1 set "FRONTEND_READY=1"
    )
    if "!BACKEND_READY!!FRONTEND_READY!"=="11" goto :services_ready
    ping 127.0.0.1 -n 2 >nul
)

:services_ready
echo.
if "!BACKEND_READY!"=="1" (echo [OK] Backend:  http://127.0.0.1:8000) else (echo [WARN] Backend has not responded yet; check its terminal window.)
if "!FRONTEND_READY!"=="1" (echo [OK] Dashboard: http://localhost:!FRONTEND_PORT!) else (echo [WARN] Frontend has not responded yet; check its terminal window.)
echo [INFO] API docs: http://127.0.0.1:8000/docs
echo.
echo Sign in with username: !DASHBOARD_USERNAME!
echo Password: !DASHBOARD_PASSWORD!
echo.
echo The Aegis API key is available after sign-in on the Connect an app page.
if "!FRONTEND_READY!"=="1" start "" http://localhost:!FRONTEND_PORT!
echo Close the backend and frontend terminal windows to stop the services.
echo.
pause
endlocal
exit /b 0

:fail
echo.
pause
endlocal
exit /b 1
