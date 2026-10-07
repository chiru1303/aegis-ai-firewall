@echo off
setlocal
title Aegis AI Firewall - Install local ML models
set "SCRIPT_DIR=%~dp0"
set "PYTHON_EXE=%SCRIPT_DIR%.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" set "PYTHON_EXE=%SCRIPT_DIR%.venv312\Scripts\python.exe"
if not exist "%PYTHON_EXE%" (
  echo [ERROR] Run start.bat once to create the project Python environment.
  pause
  exit /b 1
)
echo Installing optional inference dependencies. This needs several GB of free disk space.
"%PYTHON_EXE%" -m pip install --use-feature=truststore -r "%SCRIPT_DIR%backend\requirements-ml.txt"
if errorlevel 1 goto :fail
"%PYTHON_EXE%" "%SCRIPT_DIR%scripts\install_ml_models.py"
if errorlevel 1 goto :fail
pushd "%SCRIPT_DIR%backend"
"%PYTHON_EXE%" -m app.classifiers.training
set "TRAIN_STATUS=%ERRORLEVEL%"
popd
if not "%TRAIN_STATUS%"=="0" goto :fail
echo.
echo [OK] DeBERTa, Wolf Defender, Laya, and Open-Jev model files are installed.
echo [INFO] LightGBM uses the included local model file when available.
echo [INFO] Open-Jev loads locally from backend\models\open_jev and runs for ambiguous escalations.
echo Restart the Aegis backend to load the models.
pause
exit /b 0
:fail
echo.
echo [ERROR] Optional model setup failed. See the error above.
pause
exit /b 1
