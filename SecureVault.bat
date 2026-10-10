@echo off
setlocal
cd /d "%~dp0"

rem Already set up? Launch straight away (no console window stays open).
if exist ".venv\Scripts\pythonw.exe" goto run

echo First run: setting up SecureVault. This takes about a minute...
echo.

rem Prefer the Python launcher (py), fall back to python on PATH.
set "PY=python"
where py >nul 2>nul && set "PY=py -3"
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto nopython

%PY% -m venv .venv
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements.txt
if errorlevel 1 goto fail
echo Setup complete.

:run
start "" ".venv\Scripts\pythonw.exe" "%~dp0app.py" %*
exit /b 0

:nopython
echo Python 3.11 or newer is required but was not found.
echo.
echo  1. Install it from https://www.python.org/downloads/
echo     (tick "Add Python to PATH" during installation)
echo  2. Run SecureVault.bat again.
echo.
echo Or download SecureVault.exe from the project's Releases page - it needs no Python.
echo.
pause
exit /b 1

:fail
echo.
echo Setup failed - see the messages above. Check your internet connection and try again.
if exist ".venv" rmdir /s /q ".venv"
pause
exit /b 1
