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

if not exist "%~dp0requirements.txt" (
    echo SETUP_ERROR: requirements.txt was not found. 1>&2
    exit /b 2
)

"%PYEXE%" %PYARGS% -m pip --version >nul 2>nul
if errorlevel 1 (
    echo [setup] Bootstrapping pip...
    "%PYEXE%" %PYARGS% -m ensurepip --upgrade
    if errorlevel 1 (
        echo SETUP_ERROR: pip could not be installed. 1>&2
        exit /b 2
    )
)

echo [setup] Installing Python requirements...
"%PYEXE%" %PYARGS% -m pip install --disable-pip-version-check --requirement "%~dp0requirements.txt"
if errorlevel 1 (
    echo SETUP_ERROR: Python requirements installation failed. 1>&2
    exit /b 2
)

"%PYEXE%" %PYARGS% "%~dp0setup_openrsc.py" %*
exit /b %errorlevel%
