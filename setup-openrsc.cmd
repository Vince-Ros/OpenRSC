@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYEXE="
set "PYARGS="
where py.exe >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys;raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
    if not errorlevel 1 (
        set "PYEXE=py"
        set "PYARGS=-3"
    )
)
if not defined PYEXE (
    where python.exe >nul 2>nul
    if not errorlevel 1 (
        python -c "import sys;raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
        if not errorlevel 1 set "PYEXE=python"
    )
)
if not defined PYEXE (
    where winget.exe >nul 2>nul
    if errorlevel 1 (
        echo SETUP_ERROR: Python 3.11+ and winget were not found. 1>&2
        exit /b 2
    )
    echo [setup] Installing Python 3.14...
    winget install --id Python.Python.3.14 --exact --source winget --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 exit /b 2
    set "PYEXE=py"
    set "PYARGS=-3"
)

"%PYEXE%" %PYARGS% "%~dp0setup_openrsc.py" %*
exit /b %errorlevel%
