@echo off
rem Run DueMate backend tests from the tests folder.
rem Usage: double-click OR run from cmd/powershell. Any args are forwarded to pytest.

:: Move to project backend root (one level up from this tests folder)
cd /d "%~dp0.."

:: Prefer venv python if present to avoid requiring activation
if exist ".venv\Scripts\python.exe" (
  set "VENV_PY=.venv\Scripts\python.exe"
) else (
  set "VENV_PY=python"
)

:: Activate virtualenv if present (created as .venv in project root)
if exist ".venv\Scripts\activate.bat" (
  call ".venv\Scripts\activate.bat"
) else (
  echo WARNING: Virtualenv activate script not found at .venv\Scripts\activate.bat
  echo If you use PowerShell, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned ^& "^.%CD%\.venv\Scripts\Activate.ps1"
)

:: Optional: pass --install as first arg to install requirements before running tests
if "%1"=="--install" (
  echo Installing requirements...
  %VENV_PY% -m pip install -r requirements.txt
  shift
)

:: Fancy output: use --fancy to run verbose tests with extra summary (pytest -v -rA)
if "%1"=="--fancy" (
  shift
  echo Running pytest with fancy output in %CD% ...
  %VENV_PY% -m pytest -v -rA %*
  pause
  goto :EOF
)

echo Running pytest in %CD% ...
%VENV_PY% -m pytest -q %*
pause
