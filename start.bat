@echo off
cd /d "%~dp0"
py -m pip install -r requirements.txt
if errorlevel 1 goto error
set APP_ENV=development
py app.py
if errorlevel 1 goto error
goto end
:error
echo.
echo There was an error. Check that Python and pip are installed.
pause
:end
