@echo off
setlocal EnableExtensions
title Aegis AI Firewall - Dashboard (Port 3000)
color 09
cd /d "%~dp0frontend"

if not exist "node_modules\vite\bin\vite.js" (
    echo [ERROR] Frontend dependencies are missing. Run start.bat first.
    pause
    exit /b 1
)

echo ========================================================================
echo                 AEGIS AI FIREWALL - DASHBOARD
echo ========================================================================
if not defined AEGIS_FRONTEND_PORT set "AEGIS_FRONTEND_PORT=3000"
echo Dashboard: http://localhost:%AEGIS_FRONTEND_PORT%
echo.
call npm run dev -- --host 127.0.0.1 --port %AEGIS_FRONTEND_PORT% --strictPort
if errorlevel 1 (
    echo.
    echo [ERROR] Frontend exited with an error. Review the messages above.
    pause
)
endlocal
