@echo off
setlocal
rem Rebuild backend\.venv in its current location and install all dependencies.
rem The old environment is renamed to .venv_old (not deleted) in case you need it.
cd /d "%~dp0"

set BASE=
if exist "D:\miniconda3\envs\code_review\python.exe" set BASE=D:\miniconda3\envs\code_review\python.exe
if not defined BASE (
  where py >nul 2>&1 && set BASE=py -3
)
if not defined BASE (
  where python >nul 2>&1 && set BASE=python
)
if not defined BASE (
  echo [ERROR] No Python found. Install Python 3.11+ first.
  pause
  exit /b 1
)
echo Using base Python: %BASE%
%BASE% --version

if exist .venv (
  if exist .venv_old rmdir /s /q .venv_old
  echo Renaming old .venv to .venv_old ...
  move .venv .venv_old >nul
)

echo Creating .venv ...
%BASE% -m venv .venv
if errorlevel 1 (
  echo [ERROR] Could not create the virtual environment.
  pause
  exit /b 1
)

echo Installing dependencies (requirements-dev.txt includes pytest) ...
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
if errorlevel 1 (
  echo [ERROR] pip install failed. Check your network / pip mirror settings.
  pause
  exit /b 1
)

echo Running tests ...
.venv\Scripts\python.exe -m pytest -q

echo.
echo Done. The new environment is backend\.venv
echo To use it in PowerShell:   .\.venv\Scripts\Activate.ps1
echo To use it in cmd:          .venv\Scripts\activate.bat
echo Once everything works you can delete backend\.venv_old
pause
