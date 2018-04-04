@echo off
set PYTHONPATH=%~dp0
set PYTHONDONTWRITEBYTECODE=True
if "%1"=="--nopause" (
  set nopause="True"
  python -m scapy
) else (
  set nopause="False"
  python -m scapy %*
)
if %errorlevel%==1 if NOT "%nopause%"=="True" (
   PAUSE
)
