@echo off
title Aegis AI Firewall - Demo Scenario Seeder
color 0B
cd /d "%~dp0"
set "PYTHONPATH=%~dp0backend"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo ========================================================================
echo         AEGIS AI FIREWALL - DEMO SCENARIO SEEDER
echo ========================================================================
echo [*] Seeding all 9 attack types, benign queries, and multi-step session...
echo.

python scripts\seed_demo.py
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Demo seeding failed.
) else (
    echo.
    echo [SUCCESS] Demo scenarios seeded into live database. Refresh dashboard to view.
)
pause
