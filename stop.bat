@echo off
title Aegis AI Firewall - Service Stopper
color 0C

echo ========================================================================
echo                 AEGIS AI FIREWALL - SERVICE SHUTDOWN
echo ========================================================================
echo.
echo Stopping services on Port 8000 (Backend) and Port 3000 (Frontend)...

:: Kill processes on port 8000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo Terminating Backend process PID %%a...
    taskkill /F /PID %%a >nul 2>&1
)

:: Kill processes on port 3000
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING"') do (
    echo Terminating Frontend process PID %%a...
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo [OK] All Aegis AI Firewall services have been stopped.
echo.
pause
