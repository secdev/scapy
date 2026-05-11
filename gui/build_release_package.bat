@echo off
setlocal

cd /d "%~dp0"

set "NO_PAUSE="
if /I "%~1"=="--no-pause" set "NO_PAUSE=1"

powershell -ExecutionPolicy Bypass -File ".\scripts\build_windows_release_package.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if not "%EXIT_CODE%"=="0" (
    echo Build failed with exit code %EXIT_CODE%.
) else (
    echo Release package completed successfully.
)

if not defined NO_PAUSE pause

exit /b %EXIT_CODE%